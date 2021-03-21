use ring::error::{KeyRejected, Unspecified};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, Signature, ECDSA_P384_SHA384_FIXED_SIGNING};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::error::Error as StdError;
use std::fmt::Debug;
use std::str;
use std::str::Utf8Error;
use thiserror::Error;
use std::convert::TryFrom;

pub trait Crypto: Debug {
    type Signature: Serialize;
    type KeyPair: Serialize + AsRef<[u8]>;

    type Error: StdError;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error>;
    fn sign<T: AsRef<[u8]>>(
        &self,
        keypair: &Self::KeyPair,
        data: T,
    ) -> Result<Self::Signature, Self::Error>;
    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String);
    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str;
}

#[derive(Debug)]
pub struct TestCrypto {
    random: SystemRandom,
}

impl TestCrypto {
    pub(super) fn new() -> Self {
        TestCrypto {
            random: SystemRandom::new(),
        }
    }
}

impl Crypto for TestCrypto {
    type Signature = RingSignature;
    type KeyPair = RingKeyPair;
    type Error = KeyPairError;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error> {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &self.random)?;
        let document = document.as_ref();

        let mut data = Vec::with_capacity(1 + document.len());
        data.insert(0, document.len() as u8);
        data.extend_from_slice(document);

        RingKeyPair::try_from(data)
    }

    fn sign<T: AsRef<[u8]>>(
        &self,
        keypair: &Self::KeyPair,
        data: T,
    ) -> Result<Self::Signature, Self::Error> {
        let signature = keypair.pair.sign(&self.random, data.as_ref())?;
        Ok(RingSignature(signature))
    }

    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String) {
        let data = &mut keypair.data;

        // this includes the len octet at the begining
        let pkcs_len = data[0] as usize + 1;

        // if data is longer than len there is a kid at the end of data
        if pkcs_len != data.len() {
            // remove current kid
            data.truncate(pkcs_len)
        }
        data.extend_from_slice(kid.as_bytes());
    }

    fn algorithm(&self, _keypair: &Self::KeyPair) -> &'static str {
        "ES256"
    }
}

pub struct RingKeyPair {
    //[pkcs len][pkcs][kid]
    // first octet is the pkcs len followed by the pkcs
    // the remaining bytes are the kid if any
    data: Vec<u8>,
    pair: EcdsaKeyPair,
}

fn pkcs_len_inclusive(data: &Vec<u8>) -> Result<usize, KeyPairError> {
    let err = match data.iter().next() {
        Some(0) => Some(0),
        Some(len) => return Ok(*len as usize + 1),
        None => None
    };

    Err(KeyPairError::InvalidFirstOctetInPublic(err))
}

impl TryFrom<Vec<u8>> for RingKeyPair {
    type Error = KeyPairError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let len = pkcs_len_inclusive(&data)?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &data[1..len])?;

        Ok(RingKeyPair { data, pair })
    }
}

// todo: this work only once
impl Serialize for RingKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // this includes the len octet at the begining
        let pkcs_len = self.data[0] as usize + 1;
        // if data is longer than len there is a kid at the end of data
        if pkcs_len != self.data.len() {
            let kid = &self.data[pkcs_len..];
            // is safe because this part of the array always gets set as string bytes
            let kid = unsafe { str::from_utf8_unchecked(kid) };
            return serializer.serialize_str(kid);
        }

        let mut serializer = serializer.serialize_struct("RingKeyPair", 4)?;

        serializer.serialize_field("kty", "EC")?;
        serializer.serialize_field("crv", "P-256")?;

        let public = self.pair.public_key().as_ref();
        match public.len() {
            65 => {},
            len => Err(KeyPairError::InvalidPublicLen(len))?
        }
        // todo: check first octet
        let (x, y) = public.split_at(33);

        let x = base64::encode_config(&x[1..], base64::URL_SAFE_NO_PAD);
        serializer.serialize_field("x", &x)?;

        let y = base64::encode_config(y, base64::URL_SAFE_NO_PAD);
        serializer.serialize_field("y", &y)?;

        serializer.end()
    }
}

impl AsRef<[u8]> for RingKeyPair {
    fn as_ref(&self) -> &[u8] {
        &self.data
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
