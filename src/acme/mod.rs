use reqwest::header::{HeaderValue, ToStrError, CONTENT_TYPE};
use reqwest::Client;
use serde::ser::{Error as SerError};
use serde::{Serialize, Serializer};
use std::fmt::Debug;
use std::io;
use std::str;
use thiserror::Error;

use dto::{ApiAccount, ApiDirectory};
use jws::{Crypto, TestCrypto};

mod dto;
mod jws;
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

        // replace Content-Type header with JOSE header
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(APPLICATION_JOSE_JSON),
        );

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
