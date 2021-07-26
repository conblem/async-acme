use hyper::body::to_bytes;
use hyper::header::{HeaderValue, ToStrError, CONTENT_TYPE, LOCATION};
use hyper::http;
use hyper::{Body, Client, Request};
use serde::ser::Error as SerError;
use serde::{Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::io;
use std::str;
use std::sync::Arc;
use thiserror::Error;

use crate::acme::dto::ApiOrder;
use dto::{ApiAccount, ApiDirectory, ApiIndentifier};
use jws::{Crypto, CryptoImpl};
use nonce::{NoncePool, NoncePoolError};
pub(super) use persist::MemoryPersist;
use persist::{DataType, Persist};
use tls::{Connect, HTTPSError, HttpsConnector};

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

    #[error("Nonce Pool Error")]
    NoncePoolError(#[from] NoncePoolError),

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
pub(super) struct DirectoryInner<C, I, P> {
    directory: ApiDirectory,
    client: Client<I>,
    crypto: C,
    application_jose_json: HeaderValue,
    nonce_pool: NoncePool,
    persist: P,
}

#[derive(Debug, Clone)]
pub(super) struct Directory<C, I, P> {
    inner: Arc<DirectoryInner<C, I, P>>,
}

const APPLICATION_JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE_HEADER: &str = "replay-nonce";

impl Directory<(), (), ()> {
    pub(super) async fn from_url<P: Persist>(
        url: &str,
        persist: P,
    ) -> Result<Directory<CryptoImpl, impl Connect, P>, DirectoryError<CryptoImpl, P>> {
        let connector = HttpsConnector::new()?;
        let client = Client::builder().build(connector);
        let req = Request::get(url).body(Body::empty())?;

        let mut res = client.request(req).await?;
        let body = to_bytes(res.body_mut()).await?;

        let directory: ApiDirectory = serde_json::from_slice(body.as_ref())?;

        let nonce_pool = NoncePool::new(client.clone(), directory.new_nonce.clone());

        let crypto = match CryptoImpl::new() {
            Ok(crypto) => crypto,
            Err(err) => Err(DirectoryError::Crypto(err))?,
        };

        let inner = DirectoryInner {
            directory,
            client,
            crypto,
            nonce_pool,
            application_jose_json: HeaderValue::from_static(APPLICATION_JOSE_JSON),
            persist,
        };

        Ok(Directory {
            inner: Arc::new(inner),
        })
    }

    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
}

impl<C: Crypto, I: Connect, P: Persist> Directory<C, I, P> {
    async fn protect(
        &self,
        keypair: &C::KeyPair,
        url: &str,
    ) -> Result<String, DirectoryError<C, P>> {
        let inner = &self.inner;

        let nonce = inner.nonce_pool.get_nonce().await?;

        let protected = Protected {
            alg: inner.crypto.algorithm(&keypair),
            nonce,
            url,
            jwk: &keypair,
        };

        let protected = serde_json::to_string(&protected)?;
        Ok(base64::encode_config(protected, base64::URL_SAFE_NO_PAD))
    }

    fn sign<S: Serialize>(
        &self,
        keypair: &C::KeyPair,
        protected: String,
        payload: &S,
    ) -> Result<SignedRequest<C::Signature>, DirectoryError<C, P>> {
        let payload = serde_json::to_string(payload)?;
        let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        let mut signer = self
            .inner
            .crypto
            .sign(&keypair, protected.len() + payload.len() + 1);

        signer.update(&protected);
        signer.update(b".");
        signer.update(&payload);
        let signature = match signer.finish() {
            Err(err) => return Err(DirectoryError::Crypto(err)),
            Ok(signature) => signature,
        };

        Ok(SignedRequest {
            protected,
            payload,
            signature,
        })
    }

    pub(super) async fn account(
        &self,
        tos: bool,
        mail: &str,
    ) -> Result<Account<C, I, P>, DirectoryError<C, P>> {
        let inner = &self.inner;
        let url = &*inner.directory.new_account;

        let keypair = match inner.persist.get(DataType::PrivateKey, &*mail).await {
            Err(e) => Err(DirectoryError::Persist(e))?,
            Ok(Some(keypair)) => C::KeyPair::try_from(keypair),
            Ok(None) => inner.crypto.generate_key(),
        };

        let mut keypair = match keypair {
            Err(e) => Err(DirectoryError::Crypto(e))?,
            Ok(keypair) => keypair,
        };

        let protected = self.protect(&keypair, url).await?;
        let mail = format!("mailto:{}", mail);
        let mut account = ApiAccount::new(vec![mail], tos);
        let signed = self.sign(&keypair, protected, &account)?;

        let body = serde_json::to_vec(&signed)?.into();
        let mut req = Request::post(url).body(body)?;
        req.headers_mut()
            .insert(CONTENT_TYPE, inner.application_jose_json.clone());

        let mut res = inner.client.request(req).await?;
        let bytes = to_bytes(res.body_mut()).await?;

        let new_account: ApiAccount = serde_json::from_slice(bytes.as_ref())?;
        account.status = new_account.status;

        let kid = res
            .headers_mut()
            .remove(LOCATION)
            .map(Header)
            .ok_or_else(|| DirectoryError::NoKid)?;

        inner.crypto.set_kid(&mut keypair, kid);

        Ok(Account {
            api_account: account,
            directory: Directory::clone(&self),
            keypair,
        })
    }
}

#[derive(Debug)]
pub(super) struct Account<C: Crypto, I, P> {
    directory: Directory<C, I, P>,
    api_account: ApiAccount,
    keypair: C::KeyPair,
}

impl<C: Crypto, I: Connect, P: Persist> Account<C, I, P> {
    async fn new_order(
        &self,
        primary_name: &str,
        alt_names: &[&str],
    ) -> Result<(), DirectoryError<C, P>> {
        let directory = &self.directory;
        let url = &directory.inner.directory.new_order;

        let primary_arr = [primary_name];
        let identifiers = primary_arr
            .iter()
            .chain(alt_names)
            .map(|value| value.to_string())
            .into_iter();

        let protected = directory.protect(&self.keypair, url).await?;
        let order = ApiOrder::new(identifiers);
        let signed = directory.sign(&self.keypair, protected, &order)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Header(HeaderValue);

impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.to_str() {
            Ok(str) => serializer.serialize_str(str),
            Err(e) => Err(SerError::custom(e)),
        }
    }
}

impl Header {
    fn to_str(&self) -> Result<&str, ToStrError> {
        self.0.to_str()
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
