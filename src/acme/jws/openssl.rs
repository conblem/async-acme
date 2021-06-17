use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha::{sha384, Sha384};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use thiserror::Error;

use super::{Crypto, Sign};

pub struct OpenSSLCrypto {
    group: EcGroup,
}

impl Debug for OpenSSLCrypto {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "OpenSSLCrypto")
    }
}

#[derive(Error, Debug)]
pub enum OpenSSLError {
    #[error("OpenSSL error")]
    OpenSSL(#[from] ErrorStack),
    #[error("Public Key has invalid lenght: {0}")]
    InvalidPublicLen(usize),
}

impl Crypto for OpenSSLCrypto {
    type Signature = OpenSSLSignature;
    type KeyPair = OpenSSLKeyPair;
    type Signer = OpenSSLSigner<'_>;

    type Error = OpenSSLError;

    fn new() -> Result<Self, Self::Error> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;

        Ok(Self { group })
    }

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error> {
        let key = EcKey::generate(&self.group)?;
        let (x, y) = export_x_and_y(key.public_key(), &self.group)?;

        Ok(OpenSSLKeyPair {
            key,
            kid: None,
            x,
            y,
        })
    }

    fn sign<T: AsRef<[u8]>>(
        &self,
        keypair: &Self::KeyPair,
    ) -> Result<Self::Signer, Self::Error> {
        OpenSSLSigner()

    }

    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String) {
        keypair.kid = Some(kid);
    }

    fn algorithm(&self, _keypair: &Self::KeyPair) -> &'static str {
        "ES384"
    }
}

fn export_x_and_y(key: &EcPointRef, group: &EcGroupRef) -> Result<(String, String), OpenSSLError> {
    let mut context = BigNumContext::new()?;
    let public = key.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut context)?;

    match public.len() {
        97 => {}
        len => Err(OpenSSLError::InvalidPublicLen(len))?,
    }

    // todo: check first octet
    // splits public into [0..48][49..96]
    let (x, y) = public.split_at(49);

    // we have to skip the first octet as this is the compression format
    // 4 means no compression, we only support this format
    let x = base64::encode_config(&x[1..], base64::URL_SAFE_NO_PAD);
    let y = base64::encode_config(y, base64::URL_SAFE_NO_PAD);
    Ok((x, y))
}

pub struct OpenSSLKeyPair {
    key: EcKey<Private>,
    kid: Option<String>,
    // use constant width
    x: String,
    y: String,
}

impl AsRef<[u8]> for OpenSSLKeyPair {
    fn as_ref(&self) -> &[u8] {
        unimplemented!()
    }
}

impl Serialize for OpenSSLKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(kid) = &self.kid {
            return serializer.serialize_str(kid);
        }

        let mut serializer = serializer.serialize_struct("OpenSSLKeyPair", 4)?;

        serializer.serialize_field("kty", "EC")?;
        serializer.serialize_field("crv", "P-384")?;

        serializer.serialize_field("x", &self.x)?;
        serializer.serialize_field("y", &self.y)?;

        serializer.end()
    }
}

pub struct OpenSSLSignature(Vec<u8>);

impl Serialize for OpenSSLSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&data)
    }
}

pub struct OpenSSLSigner<'a>(&'a OpenSSLCrypto::KeyPair, Sha384);

impl Sign for OpenSSLSigner<'_> {
    type Signature = OpenSSLCrypto::Signature;

    type Error = OpenSSLCrypto::Error;

    fn update(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.0.update(buf);

        Ok(())
    }

    fn finish(self) -> Result<Self::Signature, Self::Error> {
        let digest = self.1.finish();
        let signature = EcdsaSig::sign(&digest, &self.0)?;

        let mut r = signature.r().to_vec();
        let s = signature.s().to_vec();
        r.extend_from_slice(&s);

        Ok(OpenSSLSignature(r))
    }
}