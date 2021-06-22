use hyper::body::to_bytes;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE, LOCATION};
use hyper::http;
use hyper::{Body, Client, Request};
use serde::ser::Error as SerError;
use serde::{Serialize, Serializer};
use std::fmt::Debug;
use std::io;
use std::str;
use thiserror::Error;

use dto::{ApiAccount, ApiDirectory};
use jws::{Crypto, CryptoImpl};
pub(super) use persist::MemoryPersist;
use persist::Persist;
use std::convert::TryFrom;
use tls::{HTTPSConnector, HTTPSError};

mod dto;
mod jws;
mod nonce;
mod persist;
mod tls;

#[derive(Error, Debug)]
pub(super) enum DirectoryError<C: Crypto, P: Persist> {
    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error("Crypto Error")]
    Crypto(C::Error),

    #[error("Persist Error")]
    Persist(P::Error),

    // todo: does this make sense
    #[error("JSON Error")]
    Json(#[from] serde_json::Error),

    #[error("Hyper Error")]
    Hyper(#[from] hyper::Error),

    #[error("HTTP Error")]
    HTTP(#[from] http::Error),

    #[error("API returned no noce")]
    NoNonce,

    #[error("API returned no kid")]
    NoKid,

    #[error("HTTPS Connector Error")]
    HTTPSConnector(#[from] HTTPSError),
}

#[derive(Debug)]
pub(super) struct Directory<C, P> {
    directory: ApiDirectory,
    client: Client<HTTPSConnector>,
    crypto: C,
    application_jose_json: HeaderValue,
    replay_nonce_header: HeaderName,
    persist: P,
}

const APPLICATION_JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE_HEADER: &str = "replay-nonce";

impl Directory<(), ()> {
    pub(super) async fn from_url<P: Persist>(
        url: &str,
        persist: P,
    ) -> Result<Directory<CryptoImpl, P>, DirectoryError<CryptoImpl, P>> {
        let connector = HTTPSConnector::new()?;
        let client = Client::builder().build(connector);
        let req = Request::get(url).body(Body::empty())?;

        let mut res = client.request(req).await?;
        let body = to_bytes(res.body_mut()).await?;

        let directory = serde_json::from_slice(body.as_ref())?;

        let crypto = match CryptoImpl::new() {
            Ok(crypto) => crypto,
            Err(err) => Err(DirectoryError::Crypto(err))?,
        };

        Ok(Directory {
            directory,
            client,
            crypto,
            application_jose_json: HeaderValue::from_static(APPLICATION_JOSE_JSON),
            replay_nonce_header: HeaderName::from_static(REPLAY_NONCE_HEADER),
            persist,
        })
    }

    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
}

impl<C: Crypto, P: Persist> Directory<C, P> {
    async fn get_nonce(&self) -> Result<Header, DirectoryError<C, P>> {
        let req = Request::head(&self.directory.new_nonce).body(Body::empty())?;
        let mut res = self.client.request(req).await?;

        res.headers_mut()
            .remove(&self.replay_nonce_header)
            .map(Header)
            .ok_or_else(|| DirectoryError::NoNonce)
    }

    pub(super) async fn new_account(&self, tos: bool) -> Result<ApiAccount, DirectoryError<C, P>> {
        let keypair = match self.persist.get("keypair").await {
            Err(e) => Err(DirectoryError::Persist(e))?,
            Ok(Some(keypair)) => C::KeyPair::try_from(keypair),
            Ok(None) => self.crypto.generate_key(),
        };

        let mut keypair = match keypair {
            Err(e) => Err(DirectoryError::Crypto(e))?,
            Ok(keypair) => keypair,
        };

        let nonce = self.get_nonce().await?;

        let protected = Protected {
            alg: self.crypto.algorithm(&keypair),
            nonce,
            url: &*self.directory.new_account,
            jwk: &keypair,
        };
        let protected = serde_json::to_string(&protected)?;
        let protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);

        let mut account = ApiAccount::new(vec![], tos);
        let account_str = serde_json::to_string(&account)?;
        let account_str = base64::encode_config(account_str, base64::URL_SAFE_NO_PAD);

        let mut signer = self
            .crypto
            .sign(&keypair, protected.len() + account_str.len() + 1);

        signer.update(&protected);
        signer.update(b".");
        signer.update(&account_str);
        let signature = match signer.finish() {
            Err(err) => return Err(DirectoryError::Crypto(err)),
            Ok(signature) => signature,
        };

        let body = SignedRequest {
            protected,
            payload: account_str,
            signature,
        };

        println!("{}", serde_json::to_string(&body)?);
        let body = Body::from(serde_json::to_vec(&body)?);
        let mut req = Request::post(&self.directory.new_account).body(body)?;
        req.headers_mut()
            .insert(CONTENT_TYPE, self.application_jose_json.clone());

        let mut res = self.client.request(req).await?;

        let kid = res
            .headers_mut()
            .remove(LOCATION)
            .map(Header)
            .ok_or_else(|| DirectoryError::NoKid)?;

        self.crypto.set_kid(&mut keypair, kid);

        let bytes = to_bytes(res.body_mut()).await.unwrap();
        let new_account: ApiAccount = serde_json::from_slice(bytes.as_ref())?;

        account.status = new_account.status;
        Ok(account)
    }
}

pub struct Header(HeaderValue);

impl Serialize for Header {
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
struct Protected<'a, K: Serialize> {
    alg: &'static str,
    nonce: Header,
    url: &'a str,
    jwk: K,
}

#[derive(Serialize)]
pub(crate) struct SignedRequest<S: Serialize> {
    protected: String,
    payload: String,
    signature: S,
}
