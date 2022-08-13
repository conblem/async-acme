use acme_core::{
    AcmeServer, AcmeServerBuilder, AmceServerExt, ApiAccount, ApiAuthorization, ApiChallenge,
    ApiChallengeType, ApiIdentifier, ApiIdentifierType, ApiNewOrder, ApiOrder,
    ApiOrderFinalization, DynAcmeServer, ErrorWrapper, Payload, SignedRequest, Uri,
};
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnectorBuilder;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;
use thiserror::Error;

use crate::crypto::{
    Certificate, Crypto, KeyPair, RingCrypto, RingCryptoError, RingKeyPair, RingPublicKey,
};
use crate::{HyperAcmeServer, HyperAcmeServerBuilder};

type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;

mod private {
    use super::*;

    pub trait Sealed {}
    impl Sealed for NeedsServer {}
    impl Sealed for NeedsEndpoint {}
    impl Sealed for Finished {}
    impl Sealed for Http {}
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

        let mut buf = Vec::with_capacity(protected.len() + 1 + payload.len());
        buf.extend_from_slice(protected.as_ref());
        buf.push(b'.');

        match &payload {
            Payload::Post { inner, .. } => buf.extend_from_slice(inner.as_ref()),
            Payload::Get => {}
        }

        let signature = self.crypto.sign(key_pair, buf)?;
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

    pub async fn new_order<T: Into<String>>(&self, domain: T) -> Result<Order<'_>, DirectoryError> {
        let domain = domain.into();
        let identifier = ApiIdentifier {
            type_field: ApiIdentifierType::DNS,
            value: domain.clone(),
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
            domain,
        })
    }
}

#[derive(Debug)]
pub struct Order<'a> {
    account: &'a Account<'a>,
    inner: ApiOrder<()>,
    location: Uri,
    domain: String,
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

    pub async fn finalize(&mut self) -> Result<Vec<u8>, DirectoryError> {
        // todo: remove unwrap
        let inner = &mut self.inner;
        let finalize = &inner.finalize;

        let account = self.account;
        let directory = &account.directory;

        let cert = directory.crypto.certificate(self.domain.clone())?;
        let csr = cert.csr_der()?;
        let csr = base64::encode_config(csr, base64::URL_SAFE_NO_PAD);
        let order_finalization = ApiOrderFinalization { csr };

        let protected = directory
            .protect(finalize, &account.key_pair, &account.kid)
            .await?;

        let order_finalization = directory.serialize_and_base64_encode(&order_finalization)?;
        let signed = directory.sign(&account.key_pair, protected, order_finalization)?;

        let order = directory.server.finalize(finalize, signed).await?;
        let _ = mem::replace(inner, order);

        // todo: remove unwrap
        let certificate = inner.certificate.as_ref().unwrap();

        let protected = directory
            .protect(certificate, &account.key_pair, &account.kid)
            .await?;
        let signed: SignedRequest<()> = directory.sign(&account.key_pair, protected, None)?;

        let certificate = directory
            .server
            .download_certificate(certificate, signed)
            .await?;
        Ok(certificate)
    }

    pub async fn authorizations(&self) -> Result<Vec<Authorization<'_>>, DirectoryError> {
        let inner = &self.inner;

        let mut authorizations = Vec::with_capacity(inner.authorizations.len());

        for authorization in &self.inner.authorizations {
            // todo: fix this unwrap
            let authorization = self.authorization(authorization).await?;
            authorizations.push(authorization);
        }

        Ok(authorizations)
    }

    async fn authorization(&self, location: &Uri) -> Result<Authorization<'_>, DirectoryError> {
        let account = self.account;
        let directory = &account.directory;

        let protected = directory
            .protect(location, &account.key_pair, &account.kid)
            .await?;

        let signed: SignedRequest<()> = directory.sign(&account.key_pair, protected, None)?;

        let authorization = directory.server.get_authorization(location, signed).await?;
        Ok(Authorization {
            inner: authorization,
            order: self,
            location: location.clone(),
        })
    }
}

#[derive(Debug)]
pub struct Authorization<'a> {
    order: &'a Order<'a>,
    inner: ApiAuthorization,
    location: Uri,
}

impl<'a> Authorization<'a> {
    pub fn http_challenge(&self) -> Option<Challenge<'_, Http>> {
        self.inner
            .challenges
            .iter()
            .find(|c| c.type_field == ApiChallengeType::HTTP)
            .map(|c| Challenge {
                inner: c,
                authorization: self,
                phantom: PhantomData,
            })
    }

    pub async fn update(&mut self) -> Result<(), DirectoryError> {
        let mut this = self.order.authorization(&self.location).await?;
        mem::swap(self, &mut this);

        Ok(())
    }
}

pub trait ChallengeType: private::Sealed {}
impl ChallengeType for Http {}

pub struct Http;

#[derive(Debug)]
pub struct Challenge<'a, T: ChallengeType> {
    authorization: &'a Authorization<'a>,
    inner: &'a ApiChallenge,
    phantom: PhantomData<T>,
}

impl<'a, T: ChallengeType> Challenge<'a, T> {
    pub fn token(&self) -> &str {
        &self.inner.token
    }

    pub async fn validate(&self) -> Result<(), DirectoryError> {
        let account = self.authorization.order.account;
        let directory = &account.directory;
        // todo: remove unwrap
        let uri = Uri::try_from(&*self.inner.url).unwrap();

        let protected = directory
            .protect(&uri, &account.key_pair, &account.kid)
            .await?;

        let empty_object = HashMap::<(), ()>::new();
        let empty_object = directory.serialize_and_base64_encode(&empty_object)?;

        let signed = directory.sign(&account.key_pair, protected, empty_object)?;

        // todo: maybe use return type
        directory.server.validate_challenge(&uri, signed).await?;
        Ok(())
    }
}

impl<'a> Challenge<'a, Http> {
    pub fn proof(&self) -> Result<String, DirectoryError> {
        let mut token = self.inner.token.clone();
        token.push('.');

        let account = self.authorization.order.account;

        let public_key = account.key_pair.public_key();
        let public_key = serde_json::to_vec(&public_key)?;

        let thumbprint = account.directory.crypto.thumbprint(public_key)?;
        base64::encode_config_buf(thumbprint, base64::URL_SAFE_NO_PAD, &mut token);

        Ok(token)
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
    use std::error::Error;
    use testcontainers::clients::Cli;

    use mysql::MySQL;
    use nginx_minio::WebserverWithApi;
    use stepca::Stepca;

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = Cli::default();

        // todo: rename docker network because its the same as the other;
        let _mysql = MySQL::run(&docker, "directory");
        let stepca = Stepca::run(&docker, "directory");

        let endpoint = stepca.endpoint("/directory");
        println!("{}", endpoint);
        let mut server_builder = HyperAcmeServer::builder();
        server_builder.url(endpoint).connector(stepca.connector()?);

        let directory = Directory::builder()
            .server(server_builder)
            .default()
            .build()
            .await?;
        let account = directory.new_account("test@test.com").await?;
        let mut order = account.new_order("nginx").await?;
        let mut authorizations = order.authorizations().await?;
        let authorization = &mut authorizations[0];
        let challenge = authorization.http_challenge().unwrap();

        let webserver = WebserverWithApi::new(&docker, "directory")?;
        webserver
            .put_text(challenge.token(), challenge.proof()?)
            .await?;

        challenge.validate().await?;
        authorization.update().await?;

        let res = order.finalize().await?;
        let res = String::from_utf8(res)?;
        println!("{}", res);

        panic!("{:?}", order.inner);
    }
}
