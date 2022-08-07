use ring::digest::{digest, Digest, SHA256};
use ring::error::{KeyRejected, Unspecified};
use ring::pkcs8::Document;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Signature, ECDSA_P384_SHA384_FIXED_SIGNING};
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
    type Signer: Signer<Error = Self::Error, KeyPair = Self::KeyPair>;
    type Thumbprint: AsRef<[u8]>;

    fn signer<T: Into<Option<usize>>>(self, size_hint: T) -> Self::Signer;
    fn thumbprint<T: AsRef<[u8]>>(self, buf: T) -> Result<Self::Thumbprint, Self::Error>;

    fn private_key(self) -> Result<Self::KeyPair, Self::Error>;
}

pub trait KeyPair {
    type Error: Error + 'static;
    type PublicKey: Serialize;

    fn algorithm(&self) -> &'static str;

    fn public_key(&self) -> &Self::PublicKey;
}

pub trait Signer {
    type Error: Error + 'static;
    type KeyPair: KeyPair;
    type Signature: AsRef<[u8]>;

    fn update<T: AsRef<[u8]>>(&mut self, buf: T);
    fn finish(self, key_pair: &Self::KeyPair) -> Result<Self::Signature, Self::Error>;
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

impl<'a> Crypto for &'a RingCrypto {
    type Error = RingCryptoError;
    type KeyPair = RingKeyPair;
    type Signer = RingSigner<'a>;
    type Thumbprint = Digest;

    fn signer<T: Into<Option<usize>>>(self, size_hint: T) -> Self::Signer {
        let size_hint = size_hint.into().unwrap_or_default();
        RingSigner {
            inner: Vec::with_capacity(size_hint),
            random: &self.random,
        }
    }

    fn thumbprint<T: AsRef<[u8]>>(self, buf: T) -> Result<Self::Thumbprint, Self::Error> {
        let digest = digest(&SHA256, buf.as_ref());
        Ok(digest)
    }

    fn private_key(self) -> Result<Self::KeyPair, Self::Error> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &self.random)?;
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, document.as_ref())?;
        let public_key = RingKeyPair::export_public_key(&inner)?;

        Ok(RingKeyPair {
            _document: document,
            inner,
            public_key,
        })
    }
}

pub struct RingKeyPair {
    _document: Document,
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
}

#[derive(Debug)]
pub struct RingPublicKey {
    x: [u8; 64],
    y: [u8; 64],
}

impl Serialize for RingPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct("RingKeyPair", 4)?;

        serializer.serialize_field("kty", "EC")?;
        serializer.serialize_field("crv", "P-384")?;

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

pub struct RingSigner<'a> {
    random: &'a SystemRandom,
    inner: Vec<u8>,
}

impl<'a> Signer for RingSigner<'a> {
    type Error = RingCryptoError;
    type KeyPair = RingKeyPair;
    type Signature = Signature;

    fn update<T: AsRef<[u8]>>(&mut self, buf: T) {
        self.inner.extend_from_slice(buf.as_ref());
    }

    fn finish(self, key_pair: &Self::KeyPair) -> Result<Self::Signature, Self::Error> {
        let signature = key_pair.inner.sign(self.random, &self.inner)?;
        Ok(signature)
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
