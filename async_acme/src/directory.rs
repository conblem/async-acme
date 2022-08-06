use acme_core::{
    AcmeServer, AcmeServerBuilder, AmceServerExt, ApiAccount, ApiAuthorization, ApiIdentifier,
    ApiIdentifierType, ApiNewOrder, ApiOrder, DynAcmeServer, ErrorWrapper, Payload, SignedRequest,
    Uri,
};
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnectorBuilder;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use thiserror::Error;

use crate::crypto::{
    Crypto, KeyPair, RingCrypto, RingCryptoError, RingKeyPair, RingPublicKey, Signer,
};
use crate::{HyperAcmeServer, HyperAcmeServerBuilder};

type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;

mod private {
    use super::*;

    pub trait Sealed {}
    impl Sealed for NeedsServer {}
    impl Sealed for NeedsEndpoint {}
    impl Sealed for Finished {}
}

pub trait DirectoryBuilderConfigState: private::Sealed {}

pub struct Finished;
impl DirectoryBuilderConfigState for Finished {}

pub struct NeedsServer;
impl DirectoryBuilderConfigState for NeedsServer {}

pub struct NeedsEndpoint;
impl DirectoryBuilderConfigState for NeedsEndpoint {}

#[derive(Default)]
pub struct DirectoryBuilder<T: DirectoryBuilderConfigState, S = ()> {
    state: PhantomData<T>,
    builder: Option<S>,
}

impl DirectoryBuilder<NeedsServer, ()> {
    pub fn server<S: AcmeServerBuilder>(self, builder: S) -> DirectoryBuilder<NeedsEndpoint, S> {
        DirectoryBuilder {
            state: PhantomData,
            builder: Some(builder),
        }
    }

    pub fn default(
        self,
    ) -> DirectoryBuilder<NeedsEndpoint, HyperAcmeServerBuilder<HttpsConnector>> {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .build();

        let mut builder = HyperAcmeServer::builder();
        builder.connector(connector);

        DirectoryBuilder {
            state: PhantomData,
            builder: Some(builder),
        }
    }
}

impl<C> DirectoryBuilder<NeedsEndpoint, HyperAcmeServerBuilder<C>> {
    pub fn url<T: Into<Cow<'static, str>>>(
        mut self,
        url: T,
    ) -> DirectoryBuilder<Finished, HyperAcmeServerBuilder<C>> {
        if let Some(builder) = &mut self.builder {
            builder.url(url);
        }
        DirectoryBuilder {
            state: PhantomData,
            builder: self.builder,
        }
    }

    pub fn le_staging(mut self) -> DirectoryBuilder<Finished, HyperAcmeServerBuilder<C>> {
        if let Some(builder) = &mut self.builder {
            builder.le_staging();
        }
        DirectoryBuilder {
            state: PhantomData,
            builder: self.builder,
        }
    }
}

impl<S: AcmeServerBuilder> DirectoryBuilder<NeedsEndpoint, S> {
    pub fn default(self) -> DirectoryBuilder<Finished, S> {
        DirectoryBuilder {
            state: PhantomData,
            builder: self.builder,
        }
    }
}

impl<S: AcmeServerBuilder> DirectoryBuilder<Finished, S>
where
    S::Server: Clone + Debug,
{
    async fn build(self) -> Result<Directory, <S::Server as AcmeServer>::Error> {
        let server = self.builder.unwrap().build().await?;
        Ok(Directory {
            crypto: RingCrypto::new(),
            server: Box::new(server),
        })
    }
}

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error(transparent)]
    ServerError(#[from] ErrorWrapper),
    #[error(transparent)]
    RingCryptoError(#[from] RingCryptoError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct Directory {
    server: Box<dyn DynAcmeServer>,
    crypto: RingCrypto,
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
    pub fn builder() -> DirectoryBuilder<NeedsServer> {
        DirectoryBuilder {
            state: PhantomData,
            builder: None,
        }
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
            key_pair: Arc::new(key_pair),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Account<'a> {
    directory: Cow<'a, Directory>,
    inner: ApiAccount<()>,
    kid: Uri,
    key_pair: Arc<RingKeyPair>,
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

    pub async fn authorizations(&self) -> Result<Vec<Authorization<'_>>, DirectoryError> {
        let inner = &self.inner;

        let mut authorizations = Vec::with_capacity(inner.authorizations.len());

        for authorization in &self.inner.authorizations {
            let authorization = self.authorization(authorization).await?;
            authorizations.push(authorization);
        }

        Ok(authorizations)
    }

    async fn authorization(&self, location: &str) -> Result<Authorization<'_>, DirectoryError> {
        let account = self.account;
        let directory = &account.directory;
        // todo: fix this unwrap
        let uri = Uri::try_from(location).unwrap();

        let protected = directory
            .protect(&uri, &account.key_pair, &account.kid)
            .await?;

        let signed: SignedRequest<()> = directory.sign(&account.key_pair, protected, None)?;

        let authorization = directory.server.get_authorization(&uri, signed).await?;
        Ok(Authorization {
            inner: authorization,
            order: self,
        })
    }
}

pub struct Authorization<'a> {
    order: &'a Order<'a>,
    inner: ApiAuthorization,
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
    use std::error::Error;
    use testcontainers::clients::Cli;

    use mysql::MySQL;
    use stepca::Stepca;

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = Cli::default();
        // todo: rename docker network because its the same as the other;
        let _mysql = MySQL::run(&docker, "directory");
        let stepca = Stepca::run(&docker, "directory");

        let mut server_builder = HyperAcmeServer::builder();
        server_builder
            .url(stepca.endpoint("/directory"))
            .connector(stepca.connector()?);

        let directory = Directory::builder()
            .server(server_builder)
            .default()
            .build()
            .await?;
        let account = directory.new_account("test@test.com").await?;
        let mut order = account.new_order("example.com").await?;
        order.update().await?;
        panic!("{:?}", order.inner);
        Ok(())
    }
}
