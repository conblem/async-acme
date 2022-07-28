use acme_core::{
    AcmeServer, AcmeServerBuilder, AmceServerExt, ApiAccount, ApiIdentifier, ApiIdentifierType,
    ApiNewOrder, ApiOrder, Payload, SignedRequest, Uri,
};
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnectorBuilder;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::borrow::Cow;
use thiserror::Error;

use crate::crypto::{
    Crypto, KeyPair, RingCrypto, RingCryptoError, RingKeyPair, RingPublicKey, Signer,
};
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

#[derive(Debug, Clone)]
pub struct Directory {
    server: HyperAcmeServer<HttpsConnector>,
    crypto: RingCrypto,
}

// Factory Helpers
impl Directory {
    fn base_builder() -> HyperAcmeServerBuilder<HttpsConnector> {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .build();

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
    async fn protect<'a, T>(
        &self,
        url: &Uri,
        key_pair: &RingKeyPair,
        kid: T,
    ) -> Result<String, DirectoryError>
    where
        T: Into<Option<&'a Uri>>,
    {
        let alg = key_pair.algorithm();
        let nonce = self.server.new_nonce().await?;
        let jwk = match kid.into() {
            Some(kid) => AccountKey::KID(kid),
            None => AccountKey::JWK(key_pair.public_key()),
        };

        let protected = Protected {
            nonce,
            alg,
            url,
            jwk,
        };

        self.serialize_and_base64_encode(&protected)
    }

    fn serialize_and_base64_encode<T: Serialize>(
        &self,
        payload: &T,
    ) -> Result<String, DirectoryError> {
        let payload = serde_json::to_vec(payload)?;
        Ok(base64::encode_config(payload, base64::URL_SAFE_NO_PAD))
    }

    fn sign<T, P>(
        &self,
        key_pair: &RingKeyPair,
        protected: String,
        payload: P,
    ) -> Result<SignedRequest<T>, DirectoryError>
    where
        T: Serialize,
        P: Into<Option<String>>,
    {
        let payload = payload.into().map(Payload::from).unwrap_or_default();
        let mut signer = self.crypto.signer(protected.len() + 1 + payload.len());

        signer.update(&protected);
        signer.update(b".");
        match &payload {
            Payload::Post { inner, .. } => signer.update(inner),
            Payload::Get => {}
        }

        let signature = signer.finish(key_pair)?;
        let signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);

        Ok(SignedRequest {
            payload,
            signature,
            protected,
        })
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

    pub async fn new_account<T: AsRef<str>>(&self, mail: T) -> Result<Account<'_>, DirectoryError> {
        let key_pair = self.crypto.private_key()?;
        let uri = &self.server.directory().new_account;
        let protected = self.protect(uri, &key_pair, None).await?;

        let mail = format!("mailto:{}", mail.as_ref());
        let account = ApiAccount::new(mail, true);
        let account = self.serialize_and_base64_encode(&account)?;
        let signed = self.sign(&key_pair, protected, account)?;

        let (account, kid) = self.server.new_account(signed).await?;

        Ok(Account {
            directory: Cow::Borrowed(self),
            inner: account,
            kid,
            key_pair,
        })
    }
}

#[derive(Debug)]
pub struct Account<'a> {
    directory: Cow<'a, Directory>,
    inner: ApiAccount<()>,
    kid: Uri,
    key_pair: RingKeyPair,
}

impl<'a> Account<'a> {
    pub fn into_owned(self) -> Account<'static> {
        let server = self.directory.into_owned();
        Account {
            directory: Cow::Owned(server),
            inner: self.inner,
            kid: self.kid,
            key_pair: self.key_pair,
        }
    }

    pub async fn update(&mut self) -> Result<&mut Account<'a>, DirectoryError> {
        let protected = self
            .directory
            .protect(&self.kid, &self.key_pair, &self.kid)
            .await?;
        let signed: SignedRequest<()> = self.directory.sign(&self.key_pair, protected, None)?;

        let account = self.directory.server.get_account(&self.kid, signed).await?;
        self.inner = account;
        Ok(self)
    }

    pub async fn new_order<T: AsRef<str>>(&self, domain: T) -> Result<Order<'_>, DirectoryError> {
        let identifier = ApiIdentifier {
            type_field: ApiIdentifierType::DNS,
            value: domain.as_ref().to_string(),
        };
        let new_order = ApiNewOrder {
            identifiers: vec![identifier],
            not_after: None,
            not_before: None,
        };

        let directory = &self.directory;
        let server = &directory.server;

        let uri = &server.directory().new_order;
        let protected = directory.protect(uri, &self.key_pair, &self.kid).await?;

        let new_order = directory.serialize_and_base64_encode(&new_order)?;
        let signed = directory.sign(&self.key_pair, protected, new_order)?;

        let (order, location) = server.new_order(signed).await?;
        Ok(Order {
            account: self,
            inner: order,
            location,
        })
    }
}

#[derive(Debug)]
pub struct Order<'a> {
    account: &'a Account<'a>,
    inner: ApiOrder<()>,
    location: Uri,
}

impl<'a> Order<'a> {
    pub async fn update(&mut self) -> Result<&mut Order<'a>, DirectoryError> {
        let account = self.account;
        let directory = &account.directory;

        let protected = directory
            .protect(&self.location, &account.key_pair, &account.kid)
            .await?;
        let signed: SignedRequest<()> = directory.sign(&account.key_pair, protected, None)?;

        let order = directory.server.get_order(&self.location, signed).await?;
        self.inner = order;
        Ok(self)
    }
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
    KID(&'a Uri),
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
    use testcontainers::clients::Cli;

    use mysql::MySQL;
    use stepca::Stepca;

    #[tokio::test]
    async fn test() -> Result<(), DirectoryError> {
        let docker = Cli::default();
        // todo: rename docker network because its the same as the other;
        let _mysql = MySQL::run(&docker, "directory");
        let stepca = Stepca::run(&docker, "directory");

        let directory = Directory::from_url(stepca.endpoint("/directory")).await?;
        let account = directory.new_account("test@test.com").await?;
        let mut order = account.new_order("example.com").await?;
        order.update().await?;

        //panic!("{:?}", order)
        Ok(())
    }
}
