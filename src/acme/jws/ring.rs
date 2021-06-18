use ring::error::{KeyRejected, Unspecified};
use ring::pkcs8::Document;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, Signature, ECDSA_P384_SHA384_FIXED_SIGNING};
use serde::ser::{Error as SerError, SerializeStruct};
use serde::{Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str;
use std::str::Utf8Error;
use thiserror::Error;

use super::{Crypto, Sign, Signer};

const X_LEN: usize = 64;
const Y_LEN: usize = 64;

#[derive(Debug)]
pub struct RingCrypto {
    random: SystemRandom,
}

impl Crypto for RingCrypto {
    type Signer = RingSigner;
    type Signature = RingSignature;
    type KeyPair = RingKeyPair;
    type Error = KeyPairError;

    fn new() -> Result<Self, Self::Error> {
        Ok(Self {
            random: SystemRandom::new(),
        })
    }

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &self.random)?;

        RingKeyPair::try_from(document)
    }

    fn sign<'a, 'b>(&'a self, keypair: &'b Self::KeyPair, size_hint: usize) -> Signer<'a, 'b, Self> {
        Signer::new(self, keypair, size_hint)
    }

    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String) {
        keypair.kid = Some(kid);
    }

    fn algorithm(&self, _keypair: &Self::KeyPair) -> &'static str {
        "ES384"
    }
}

pub struct RingKeyPair {
    //[pkcs len][pkcs][kid]
    // first octet is the pkcs len followed by the pkcs
    // the remaining bytes are the kid if any
    document: Document,
    pair: EcdsaKeyPair,
    x: [u8; X_LEN],
    y: [u8; Y_LEN],
    kid: Option<String>,
}

impl TryFrom<Document> for RingKeyPair {
    type Error = KeyPairError;

    fn try_from(document: Document) -> Result<Self, Self::Error> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, document.as_ref())?;
        let (x, y) = export_x_y(&pair)?;

        Ok(RingKeyPair {
            document,
            pair,
            kid: None,
            x,
            y,
        })
    }
}

fn export_x_y(pair: &EcdsaKeyPair) -> Result<([u8; X_LEN], [u8; Y_LEN]), KeyPairError> {
    let public = pair.public_key().as_ref();
    match public.len() {
        97 => {}
        len => Err(KeyPairError::InvalidPublicLen(len))?,
    }

    // todo: check first octet
    // splits public into [0..48][49..96]
    let (x, y) = public.split_at(49);
    println!("{}", x[0]);

    // we have to skip the first octet as this is the compression format
    // 4 means no compression, we only support this format
    let mut x_base64 = [0; X_LEN];
    let mut y_base64 = [0; Y_LEN];
    // how can we make sure there is no panic
    match base64::encode_config_slice(&x[1..], base64::URL_SAFE_NO_PAD, &mut x_base64) {
        X_LEN => {}
        len => return Err(KeyPairError::InvalidBase64Len(XY::X, len)),
    };
    match base64::encode_config_slice(y, base64::URL_SAFE_NO_PAD, &mut y_base64) {
        Y_LEN => {}
        len => return Err(KeyPairError::InvalidBase64Len(XY::Y, len)),
    };

    Ok((x_base64, y_base64))
}

impl Serialize for RingKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(kid) = &self.kid {
            return serializer.serialize_str(kid);
        }

        let mut serializer = serializer.serialize_struct("RingKeyPair", 4)?;

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

#[derive(Error, Debug)]
pub enum KeyPairError {
    #[error(transparent)]
    KeyRejected(#[from] KeyRejected),

    #[error(transparent)]
    Unspecified(#[from] Unspecified),

    #[error("Invalid Signature")]
    Signature(#[from] Utf8Error),

    #[error("First octet of Public Key has invalid value: {0:?}")]
    InvalidFirstOctetInPublic(Option<u8>),

    #[error("Public Key has invalid lenght of: {0}")]
    InvalidPublicLen(usize),

    #[error("Base64 Conversion of Public Key Part {0} failed with lenght {1}")]
    InvalidBase64Len(XY, usize),
}

#[derive(Debug)]
pub enum XY {
    X,
    Y,
}

impl Display for XY {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            XY::X => write!(f, "X"),
            XY::Y => write!(f, "X"),
        }
    }
}

pub struct RingSigner(Vec<u8>);

impl Sign for RingSigner {
    type Crypto = RingCrypto;
    fn new(size_hint: usize) -> Self {
        RingSigner(Vec::with_capacity(size_hint))
    }

    fn update(&mut self, buf: &[u8]) {
        self.0.extend_from_slice(buf);
    }

    fn finish(
        self,
        crypto: &Self::Crypto,
        keypair: &<<Self as Sign>::Crypto as Crypto>::KeyPair,
    ) -> Result<
        <<Self as Sign>::Crypto as Crypto>::Signature,
        <<Self as Sign>::Crypto as Crypto>::Error,
    > {
        let signature = keypair.pair.sign(&crypto.random, self.0.as_ref())?;
        Ok(RingSignature(signature))
    }
}

pub struct RingSignature(Signature);

impl Serialize for RingSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = base64::encode_config(self.0.as_ref(), base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&data)
    }
}
