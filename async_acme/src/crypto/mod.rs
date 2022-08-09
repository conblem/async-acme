use rcgen::DistinguishedName;
use ring::digest::{digest, Digest, SHA256};
use ring::error::{KeyRejected, Unspecified};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Signature, ECDSA_P384_SHA384_FIXED_SIGNING};
use rustls::PrivateKey;
use serde::ser;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::str;
use thiserror::Error;

pub trait Crypto: Sized {
    type Error: Error + 'static;
    type KeyPair: KeyPair<Error = Self::Error>;
    type Signature;
    type Thumbprint: AsRef<[u8]>;
    type Certificate: Certificate<KeyPair = Self::KeyPair>;

    fn sign<T: AsRef<[u8]>>(
        &self,
        key_pair: &Self::KeyPair,
        buf: T,
    ) -> Result<Self::Signature, Self::Error>;
    fn thumbprint<T: AsRef<[u8]>>(&self, buf: T) -> Result<Self::Thumbprint, Self::Error>;

    fn private_key(&self) -> Result<Self::KeyPair, Self::Error>;

    fn certificate(&self, domain: String) -> Result<Self::Certificate, Self::Error>;
}

pub trait KeyPair {
    type Error: Error + 'static;
    type PublicKey: Serialize;

    fn algorithm(&self) -> &'static str;

    fn public_key(&self) -> &Self::PublicKey;

    fn as_der(&self) -> &[u8];
}

pub trait Certificate: Sized {
    type Error: Error + 'static;
    type CSR: AsRef<[u8]>;
    type KeyPair: KeyPair<Error = Self::Error>;

    fn csr_der(&self) -> Result<Self::CSR, Self::Error>;
    fn key_pair(&self) -> &Self::KeyPair;
}

#[derive(Debug)]
pub enum XY {
    X,
    Y,
}

impl Display for XY {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            XY::X => write!(f, "X"),
            XY::Y => write!(f, "Y"),
        }
    }
}

#[derive(Debug, Error)]
pub enum RingCryptoError {
    #[error("Ring")]
    Ring(Unspecified),
    #[error("Invalid Key {0}")]
    InvalidKey(KeyRejected),
    #[error("Public key has invalid lenght of {0}")]
    InvalidPublicKeyLenght(usize),
    #[error("Public key uses invalid compression format {0}")]
    WrongCompressionFormat(u8),
    #[error("Invalid Base64 length {1} on public key part {0}")]
    InvalidBase64Len(XY, usize),
}

impl From<Unspecified> for RingCryptoError {
    fn from(error: Unspecified) -> Self {
        RingCryptoError::Ring(error)
    }
}

impl From<KeyRejected> for RingCryptoError {
    fn from(err: KeyRejected) -> Self {
        RingCryptoError::InvalidKey(err)
    }
}

#[derive(Debug, Clone)]
pub struct RingCrypto {
    random: SystemRandom,
}

impl RingCrypto {
    pub fn new() -> Self {
        Self {
            random: SystemRandom::new(),
        }
    }
}

impl<'a> Crypto for RingCrypto {
    type Error = RingCryptoError;
    type KeyPair = RingKeyPair;
    type Signature = Signature;
    type Thumbprint = Digest;
    type Certificate = RingCertificate;

    fn sign<T: AsRef<[u8]>>(
        &self,
        key_pair: &Self::KeyPair,
        buf: T,
    ) -> Result<Self::Signature, Self::Error> {
        let signature = key_pair.inner.sign(&self.random, buf.as_ref())?;
        Ok(signature)
    }

    fn thumbprint<T: AsRef<[u8]>>(&self, buf: T) -> Result<Self::Thumbprint, Self::Error> {
        let digest = digest(&SHA256, buf.as_ref());
        Ok(digest)
    }

    fn private_key(&self) -> Result<Self::KeyPair, Self::Error> {
        let private_der =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &self.random)?;
        let inner =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, private_der.as_ref())?;
        let public_key = RingKeyPair::export_public_key(&inner)?;

        Ok(RingKeyPair {
            private_der: PrivateKey(Vec::from(private_der.as_ref())),
            inner,
            public_key,
        })
    }

    fn certificate(&self, domain: String) -> Result<Self::Certificate, Self::Error> {
        let key_pair = self.private_key()?;
        // todo: remove unwrap
        let rcgen_key_pair = rcgen::KeyPair::from_der(key_pair.private_der.0.as_ref()).unwrap();

        let mut params = rcgen::CertificateParams::new([domain]);
        params.distinguished_name = DistinguishedName::new();
        params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
        params.key_pair = Some(rcgen_key_pair);

        // todo: remove unwrap
        let cert = rcgen::Certificate::from_params(params).unwrap();
        Ok(RingCertificate { key_pair, cert })
    }
}

pub struct RingKeyPair {
    private_der: PrivateKey,
    inner: EcdsaKeyPair,
    public_key: RingPublicKey,
}

impl Debug for RingKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl RingKeyPair {
    fn export_public_key(key_pair: &EcdsaKeyPair) -> Result<RingPublicKey, RingCryptoError> {
        let public = <EcdsaKeyPair as ring::signature::KeyPair>::public_key(&key_pair).as_ref();
        match public.len() {
            97 => {}
            len => return Err(RingCryptoError::InvalidPublicKeyLenght(len)),
        }

        // split public into [0..48][49..96]
        let (x, y) = public.split_at(49);

        let mut x_base64 = [0; 64];
        let mut y_base64 = [0; 64];

        match x[0] {
            4 => {}
            compression_format => {
                return Err(RingCryptoError::WrongCompressionFormat(compression_format))
            }
        }

        match base64::encode_config_slice(&x[1..], base64::URL_SAFE_NO_PAD, &mut x_base64) {
            64 => {}
            len => return Err(RingCryptoError::InvalidBase64Len(XY::X, len)),
        }
        match base64::encode_config_slice(y, base64::URL_SAFE_NO_PAD, &mut y_base64) {
            64 => {}
            len => return Err(RingCryptoError::InvalidBase64Len(XY::Y, len)),
        }

        Ok(RingPublicKey {
            x: x_base64,
            y: y_base64,
        })
    }
}

impl KeyPair for RingKeyPair {
    type Error = RingCryptoError;
    type PublicKey = RingPublicKey;

    fn algorithm(&self) -> &'static str {
        "ES384"
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn as_der(&self) -> &[u8] {
        self.private_der.0.as_ref()
    }
}

#[derive(Debug)]
pub struct RingPublicKey {
    x: [u8; 64],
    y: [u8; 64],
}

impl Serialize for RingPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct("RingKeyPair", 4)?;

        serializer.serialize_field("crv", "P-384")?;
        serializer.serialize_field("kty", "EC")?;

        match str::from_utf8(&self.x) {
            Ok(x) => serializer.serialize_field("x", x)?,
            Err(e) => return Err(ser::Error::custom(e)),
        };
        match str::from_utf8(&self.y) {
            Ok(y) => serializer.serialize_field("y", y)?,
            Err(e) => return Err(ser::Error::custom(e)),
        };

        serializer.end()
    }
}

pub struct RingCertificate {
    cert: rcgen::Certificate,
    key_pair: RingKeyPair,
}

impl Certificate for RingCertificate {
    type Error = RingCryptoError;
    type CSR = Vec<u8>;
    type KeyPair = RingKeyPair;

    fn csr_der(&self) -> Result<Self::CSR, Self::Error> {
        // todo: remove unwrap
        Ok(self.cert.serialize_request_der().unwrap())
    }

    fn key_pair(&self) -> &Self::KeyPair {
        &self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_private_key() -> Result<(), RingCryptoError> {
        let ring_crypto = RingCrypto::new();
        let _key_pair = ring_crypto.private_key()?;

        Ok(())
    }
}
