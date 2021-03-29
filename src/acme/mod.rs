use hyper::body::to_bytes;
use hyper::{Body, Client, Request};
use serde::ser::Error as SerError;
use serde::{Serialize, Serializer};
use std::fmt::Debug;
use std::io;
use std::str;
use thiserror::Error;

use dto::{ApiAccount, ApiDirectory};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::http;
use jws::{Crypto, CryptoImpl};
use tls::{HTTPSConnector, HTTPSError};

mod dto;
mod jws;
mod persist;
mod tls;

#[derive(Error, Debug)]
pub(super) enum DirectoryError<C: Crypto> {
    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error("Crypto Error")]
    Crypto(C::Error),

    // todo: does this make sense
    #[error("JSON Error")]
    Json(#[from] serde_json::Error),

    #[error("Hyper Error")]
    Hyper(#[from] hyper::Error),

    #[error("HTTP Error")]
    HTTP(#[from] http::Error),

    #[error("API returned no noce")]
    NoNonce,

    #[error("HTTPS Connector Error")]
    HTTPSConnector(#[from] HTTPSError),
}

#[derive(Debug)]
pub(super) struct Directory<C> {
    directory: ApiDirectory,
    client: Client<HTTPSConnector>,
    crypto: C,
    application_jose_json: HeaderValue,
    replay_nonce_header: HeaderName,
}

const APPLICATION_JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE_HEADER: &str = "replay-nonce";

impl Directory<CryptoImpl> {
    pub(super) async fn from_url(url: &str) -> Result<Self, DirectoryError<CryptoImpl>> {
        let connector = HTTPSConnector::new()?;
        let client = Client::builder().build(connector);
        let req = Request::get(url).body(Body::empty())?;

        let mut res = client.request(req).await?;
        let body = to_bytes(res.body_mut()).await?;

        let directory = serde_json::from_slice(body.as_ref())?;

        let crypto = match CryptoImpl::new() {
            Ok(crypto) => crypto,
            Err(err) => Err(DirectoryError::Crypto(err))?
        };

        Ok(Directory {
            directory,
            client,
            crypto,
            application_jose_json: HeaderValue::from_static(APPLICATION_JOSE_JSON),
            replay_nonce_header: HeaderName::from_static(REPLAY_NONCE_HEADER),
        })
    }

    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
}

impl<C: Crypto> Directory<C> {
    async fn get_nonce(&self) -> Result<Nonce, DirectoryError<C>> {
        let req = Request::head(&self.directory.new_nonce).body(Body::empty())?;
        let mut res = self.client.request(req).await?;

        res.headers_mut()
            .remove(&self.replay_nonce_header)
            .map(Nonce)
            .ok_or_else(|| DirectoryError::NoNonce)
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

        let body = Body::from(serde_json::to_vec(&body)?);
        let mut req = Request::post(&self.directory.new_account).body(body)?;
        req.headers_mut().insert(CONTENT_TYPE, self.application_jose_json.clone());

        let mut res = self.client.request(req).await?;
        let bytes = to_bytes(res.body_mut()).await.unwrap();
        let body = str::from_utf8(&bytes).unwrap();
        println!("{}", body);

        Ok(())
    }
}

struct Nonce(HeaderValue);

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0.to_str() {
            Ok(str) => serializer.serialize_str(str),
            Err(e) => Err(SerError::custom(e)),
        }
    }
}

#[derive(Serialize)]
struct Protected<K: Serialize> {
    alg: &'static str,
    nonce: Nonce,
    url: String,
    jwk: K,
}

#[derive(Serialize)]
pub(crate) struct SignedRequest<S: Serialize> {
    protected: String,
    payload: String,
    signature: S,
}
