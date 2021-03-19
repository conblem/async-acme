use reqwest::header::{HeaderValue, ToStrError, CONTENT_TYPE};
use reqwest::Client;
use ring::error::{KeyRejected, Unspecified};
use ring::pkcs8::Document;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, Signature, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::ser::{Error as SerError, SerializeStruct};
use serde::{Serialize, Serializer};
use std::error::Error as StdError;
use std::fmt::Debug;
use std::io;
use std::str;
use std::str::Utf8Error;
use thiserror::Error;

use dto::{ApiAccount, ApiAccountStatus, ApiDirectory};

mod dto;
mod persist;

#[derive(Error, Debug)]
pub(super) enum DirectoryError<C: Crypto> {
    #[error("Error while calling Api")]
    Reqwest(#[from] reqwest::Error),

    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error(transparent)]
    Nonce(#[from] NonceError),

    #[error("Crypto Error")]
    Crypto(C::Error),

    // todo: does this make sense
    #[error("JSON Error")]
    Json(#[from] serde_json::Error),
}

#[derive(Error, Debug)]
pub(super) enum NonceError {
    #[error("API did not return Nonce")]
    NoNonce,

    #[error("Nonce was not UTF 8 Compatible")]
    NonceFormatting(#[from] ToStrError),
}

const APPLICATION_JOSE_JSON: &str = "application/jose+json";

#[derive(Debug)]
pub(super) struct Directory<C> {
    directory: ApiDirectory,
    client: Client,
    crypto: C,
}

impl Directory<TestCrypto> {
    pub(super) async fn from_url(url: &str) -> Result<Self, DirectoryError<TestCrypto>> {
        let directory: ApiDirectory = reqwest::get(url).await?.json().await?;

        Ok(Directory {
            directory,
            client: Client::new(),
            crypto: TestCrypto::new(),
        })
    }

    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    const REPLACE_NONCE_HEADER: &'static str = "Replay-Nonce";
}

impl<C: Crypto> Directory<C> {
    async fn get_nonce(&self) -> Result<String, DirectoryError<C>> {
        let mut nonce_req = self.client.head(&self.directory.new_nonce).send().await?;

        let header = nonce_req
            .headers_mut()
            .remove(Directory::REPLACE_NONCE_HEADER)
            .ok_or_else(|| NonceError::NoNonce)?;

        match header.to_str() {
            Err(e) => Err(DirectoryError::Nonce(e.into())),
            Ok(nonce) => Ok(nonce.to_owned()),
        }
    }

    pub(super) async fn new_account(&self, tos: bool) -> Result<(), DirectoryError<C>> {
        let nonce = self.get_nonce().await?;

        let keypair = match self.crypto.generate_key() {
            Err(err) => Err(DirectoryError::Crypto(err))?,
            Ok(keypair) => keypair,
        };

        let protected = Protected {
            alg: self.crypto.algorithm(&keypair),
            nonce,
            url: self.directory.new_account.clone(),
            jwk: &keypair,
        };
        let protected = serde_json::to_string(&protected)?;
        let protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);

        let account = ApiAccount::new(vec![], tos);
        let account = serde_json::to_string(&account)?;
        let account = base64::encode_config(account, base64::URL_SAFE_NO_PAD);

        let mut signature_input = String::with_capacity(protected.len() + account.len() + 1);
        signature_input += &protected;
        signature_input += ".";
        signature_input += &account;
        let signature = match self.crypto.sign(&keypair, signature_input) {
            Err(err) => Err(DirectoryError::Crypto(err))?,
            Ok(signature) => signature,
        };

        let body = SignedRequest {
            protected,
            payload: account,
            signature,
        };

        let mut request = self
            .client
            .post(&self.directory.new_account)
            .json(&body)
            .build()?;

        request.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(APPLICATION_JOSE_JSON));
        let error = self.client.execute(request).await?.text().await?;
        println!("{}", error);

        Ok(())
    }
}

#[derive(Serialize)]
struct Protected<K: Serialize> {
    alg: &'static str,
    nonce: String,
    url: String,
    jwk: K,
}

#[derive(Serialize)]
struct SignedRequest<S: Serialize> {
    protected: String,
    payload: String,
    signature: S,
}

fn base64url<D: Serialize, S>(data: &D, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let data = match serde_json::to_string(data) {
        Err(err) => Err(SerError::custom(err))?,
        Ok(data) => data,
    };

    let data = base64::encode_config(data, base64::URL_SAFE_NO_PAD);

    serializer.serialize_str(&data)
}

enum Key<P: Serialize> {
    Private(P),
    Kid { private: P, kid: String },
}

pub(super) trait Crypto: Debug {
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
pub(super) struct TestCrypto {
    random: SystemRandom,
}

impl TestCrypto {
    fn new() -> Self {
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
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.random)?;
        let document = document.as_ref();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document)?;

        let mut data = Vec::with_capacity(1 + document.len());
        data.insert(0, document.len() as u8);
        data.extend_from_slice(document);

        // check if public key is has correct length and is uncompressed
        // https://tools.ietf.org/html/rfc5480#section-2.2
        let public = pair.public_key().as_ref();
        match public.len() {
            65 => {},
            len => Err(KeyPairError::InvalidPublicLen(len))?
        }
        match public[0] {
            4 => {},
            invalidOctet => Err(KeyPairError::InvalidFirstOctetInPublic(invalidOctet))?
        }

        Ok(RingKeyPair { data, pair })
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
        keypair.data.extend_from_slice(kid.as_bytes());
    }

    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str {
        "ES256"
    }
}

pub(super) struct RingKeyPair {
    // first octet is the length of the public key the remaining bytes are the kid if any
    data: Vec<u8>,
    pair: EcdsaKeyPair,
}

impl Serialize for RingKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = self.data[0] as usize + 1;
        if len != self.data.len() {
            let kid = &self.data[len..];
            let kid = unsafe { str::from_utf8_unchecked(kid) };
            return serializer.serialize_str(kid)
        }

        let mut serializer = serializer.serialize_struct("RingKeyPair", 4)?;

        serializer.serialize_field("kty", "EC")?;
        serializer.serialize_field("crv", "P-256")?;

        let public = self.pair.public_key().as_ref();
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

impl From<Vec<u8>> for RingKeyPair {
    fn from(_: Vec<u8>) -> Self {
        unimplemented!()
    }
}

#[derive(Error, Debug)]
pub(super) enum KeyPairError {
    #[error(transparent)]
    KeyRejected(#[from] KeyRejected),

    #[error(transparent)]
    Unspecified(#[from] Unspecified),

    #[error("Invalid Signature")]
    Signature(#[from] Utf8Error),

    #[error("First octet of Public Key has invalid value: {0}")]
    InvalidFirstOctetInPublic(u8),

    #[error("Public Key has invalid lenght of: {0}")]
    InvalidPublicLen(usize)
}

pub(super) struct RingSignature(Signature);

impl Serialize for RingSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = base64::encode_config(self.0.as_ref(), base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&data)
    }
}
