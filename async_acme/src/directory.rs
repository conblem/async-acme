use acme_core::{AcmeServer, AcmeServerBuilder, AmceServerExt, Uri, ApiAccount, SignedRequest, Payload};
use hyper::client::HttpConnector;
use thiserror::Error;
use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;

use crate::crypto::{Crypto, RingCrypto, RingCryptoError, RingKeyPair, KeyPair, RingPublicKey, Signer};
use crate::{HyperAcmeServer, HyperAcmeServerBuilder, HyperAcmeServerError};

type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error(transparent)]
    HyperAcmeServerError(#[from] HyperAcmeServerError),
    #[error(transparent)]
    RingCryptoError(#[from] RingCryptoError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

pub struct Directory {
    server: HyperAcmeServer<HttpsConnector>,
    crypto: RingCrypto,
}

// Factory Helpers
impl Directory {
    fn base_builder() -> HyperAcmeServerBuilder<HttpsConnector> {
        let connector = HttpsConnector::with_webpki_roots();
        let mut builder = HyperAcmeServer::builder();
        builder.connector(connector);

        builder
    }

    async fn finish(
        mut builder: HyperAcmeServerBuilder<HttpsConnector>,
    ) -> Result<Self, DirectoryError> {
        let server = builder.build().await?;
        let crypto = RingCrypto::new();

        Ok(Self { server, crypto })
    }
}

impl Directory {
    pub async fn from_le_staging() -> Result<Self, DirectoryError> {
        let mut builder = Self::base_builder();
        builder.le_staging();
        Self::finish(builder).await
    }

    pub async fn from_le() -> Result<Self, DirectoryError> {
        let builder = Self::base_builder();
        Self::finish(builder).await
    }

    pub async fn from_url(url: String) -> Result<Self, DirectoryError> {
        let mut builder = Self::base_builder();
        builder.url(url);
        Self::finish(builder).await
    }

    pub async fn new_account<T: AsRef<str>>(&self, mail: T) -> Result<Account, DirectoryError> {
        let key_pair = self.crypto.private_key()?;
        let uri = &self.server.directory().new_account;
        let protected = self.protect(uri, &key_pair).await?;

        let mail = format!("mailto:{}", mail.as_ref());
        let account = ApiAccount::new(mail, true);
        let signed = self.sign(&key_pair, protected, &account)?;

        let account = self.server.new_account(signed).await?;

        let server = self.server.clone();

        Ok(Account { server, inner: account })
    }
}

impl Directory {
    async fn protect(&self, url: &Uri, key_pair: &RingKeyPair) -> Result<String, DirectoryError> {
        let alg = key_pair.algorithm();
        let nonce = self.server.new_nonce().await?;
        let public_key = key_pair.public_key();

        let protected = Protected {
            nonce,
            alg,
            url,
            jwk: AccountKey::JWK(public_key)
        };

        let protected = serde_json::to_vec(&protected)?;
        Ok(base64::encode_config(protected, base64::URL_SAFE_NO_PAD))
    }

    fn sign<T: Serialize>(&self, key_pair: &RingKeyPair, protected: String, payload: &T) -> Result<SignedRequest<T>, DirectoryError> {
        let payload = serde_json::to_vec(payload)?;
        let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        let mut signer = self.crypto.signer(protected.len() + payload.len() + 1);

        signer.update(&protected);
        signer.update(b".");
        signer.update(&payload);

        let signature = signer.finish(key_pair)?;
        let signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);

        Ok(SignedRequest {
            payload: Payload::from(payload),
            signature,
            protected,
        })
    }
}

#[derive(Debug)]
pub struct Account {
    server: HyperAcmeServer<HttpsConnector>,
    inner: ApiAccount<()>
}

struct Protected<'a> {
    alg: &'static str,
    nonce: String,
    url: &'a Uri,
    jwk: AccountKey<'a>,
}

impl Serialize for Protected<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct("Protected", 4)?;
        serializer.serialize_field("alg", &self.alg)?;
        serializer.serialize_field("nonce", &self.nonce)?;
        serializer.serialize_field("url", &self.url)?;

        match &self.jwk {
            AccountKey::JWK(public_key) => serializer.serialize_field("jwk", public_key)?,
            AccountKey::KID(kid) => serializer.serialize_field("kid", kid)?,
        };

        serializer.end()
    }
}

enum AccountKey<'a> {
    JWK(&'a RingPublicKey),
    KID(String),
}

impl Serialize for AccountKey<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            AccountKey::KID(kid) => kid.serialize(serializer),
            AccountKey::JWK(public_key) => public_key.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test() -> Result<(), DirectoryError> {
        let directory = Directory::from_le_staging().await?;
        let account = directory.new_account("test@test.com").await?;
        panic!("{:?}", account);

        Ok(())
    }
}
