use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha::Sha384;
use serde::ser::{Error as SerError, SerializeStruct};
use serde::{Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::str;
use thiserror::Error;

use super::{Crypto, Header, Sign, Signer};

const X_LEN: usize = 64;
const Y_LEN: usize = 64;

#[derive(Debug)]
pub enum XY {
    X,
    Y,
}

// remove this duplication
impl Display for XY {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            XY::X => write!(f, "X"),
            XY::Y => write!(f, "X"),
        }
    }
}

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

    #[error("Base64 Conversion of Public Key Part {0} failed with lenght {1}")]
    InvalidBase64Len(XY, usize),
}

impl Crypto for OpenSSLCrypto {
    type Signer = OpenSSLSigner;
    type Signature = OpenSSLSignature;
    type KeyPair = OpenSSLKeyPair;

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

    fn sign<'a, 'b>(
        &'a self,
        keypair: &'b Self::KeyPair,
        size_hint: usize,
    ) -> Signer<'a, 'b, Self> {
        Signer::new(self, keypair, size_hint)
    }

    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: Header) {
        keypair.kid = Some(kid);
    }

    fn algorithm(&self, _keypair: &Self::KeyPair) -> &'static str {
        "ES384"
    }
}

fn export_x_and_y(
    key: &EcPointRef,
    group: &EcGroupRef,
) -> Result<([u8; X_LEN], [u8; Y_LEN]), OpenSSLError> {
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
    let mut x_base64 = [0; X_LEN];
    let mut y_base64 = [0; Y_LEN];
    // how can we make sure there is no panic
    match base64::encode_config_slice(&x[1..], base64::URL_SAFE_NO_PAD, &mut x_base64) {
        X_LEN => {}
        len => return Err(OpenSSLError::InvalidBase64Len(XY::X, len)),
    };
    match base64::encode_config_slice(y, base64::URL_SAFE_NO_PAD, &mut y_base64) {
        Y_LEN => {}
        len => return Err(OpenSSLError::InvalidBase64Len(XY::Y, len)),
    };

    Ok((x_base64, y_base64))
}

pub struct OpenSSLKeyPair {
    key: EcKey<Private>,
    x: [u8; X_LEN],
    y: [u8; Y_LEN],
    kid: Option<Header>,
}

impl TryInto<Vec<u8>> for OpenSSLKeyPair {
    type Error = <OpenSSLCrypto as Crypto>::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.key.private_key_to_der()?)
    }
}

impl TryFrom<Vec<u8>> for OpenSSLKeyPair {
    type Error = <OpenSSLCrypto as Crypto>::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // todo: use group from crypto
        // somehow export this to better traits
        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let key = EcKey::private_key_from_der(&*value)?;
        let (x, y) = export_x_and_y(key.public_key(), &group)?;

        Ok(OpenSSLKeyPair {
            key,
            x,
            y,
            kid: None,
        })
    }
}

impl Serialize for OpenSSLKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(kid) = &self.kid {
            return kid.serialize(serializer);
        }

        let mut serializer = serializer.serialize_struct("OpenSSLKeyPair", 4)?;

        serializer.serialize_field("kty", "EC")?;
        serializer.serialize_field("crv", "P-384")?;

        match str::from_utf8(&self.x) {
            Ok(x) => serializer.serialize_field("x", x)?,
            Err(e) => return Err(SerError::custom(e)),
        };
        match str::from_utf8(&self.y) {
            Ok(y) => serializer.serialize_field("y", y)?,
            Err(e) => return Err(SerError::custom(e)),
        };

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

pub struct OpenSSLSigner(Sha384);

impl Sign for OpenSSLSigner {
    type Crypto = OpenSSLCrypto;

    fn new(_size_hint: usize) -> Self {
        OpenSSLSigner(Sha384::new())
    }

    fn update(&mut self, buf: &[u8]) {
        self.0.update(buf);
    }

    fn finish(
        self,
        _crypto: &Self::Crypto,
        keypair: &<<Self as Sign>::Crypto as Crypto>::KeyPair,
    ) -> Result<
        <<Self as Sign>::Crypto as Crypto>::Signature,
        <<Self as Sign>::Crypto as Crypto>::Error,
    > {
        let digest = self.0.finish();

        let signature = EcdsaSig::sign(&digest, &keypair.key)?;

        let mut r = signature.r().to_vec();
        let s = signature.s().to_vec();
        r.extend_from_slice(&s);

        Ok(OpenSSLSignature(r))
    }
}
