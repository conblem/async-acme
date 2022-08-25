use acme_core::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiAuthorization, ApiChallenge, ApiDirectory,
    ApiError, ApiNewOrder, ApiOrder, ApiOrderFinalization, SignedRequest, Uri,
};
use async_trait::async_trait;
use hyper::body::Bytes;
use hyper::client::connect::Connect as HyperConnect;
use hyper::http::header::{HeaderName, CONTENT_TYPE};
use hyper::http::uri::InvalidUri;
use hyper::http::HeaderValue;
use hyper::{body, HeaderMap, Response};
use hyper::{Body, Client, Request};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt::Debug;
use std::str;
use thiserror::Error;

const REPLAY_NONCE_HEADER: &str = "replay-nonce";
const LOCATION_HEADER: &str = "location";

pub trait Connect: HyperConnect + Clone + Debug + Send + Sync + 'static {}
impl<C: HyperConnect + Clone + Debug + Send + Sync + 'static> Connect for C {}

enum Endpoint {
    LetsEncryptStaging,
    LetsEncrypt,
    Url(Cow<'static, str>),
}

impl<T> From<T> for Endpoint
where
    T: Into<Cow<'static, str>>,
{
    fn from(url: T) -> Self {
        Endpoint::Url(url.into())
    }
}

impl Endpoint {
    fn to_str(&self) -> &str {
        match self {
            Endpoint::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
            Endpoint::LetsEncryptStaging => {
                "https://acme-staging-v02.api.letsencrypt.org/directory"
            }
            Endpoint::Url(endpoint) => endpoint.as_ref(),
        }
    }
}

// todo: retain this error somehow for dyn AcmeServer
#[derive(Debug, Error)]
pub enum HyperAcmeServerError {
    #[error("No connector configured")]
    NoConnector,
    #[error("API returned nonce {0:?}")]
    Nonce(Option<HeaderValue>),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Http(#[from] hyper::http::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("API returned error {0:?}")]
    ApiError(ApiError),
    #[error("Invalid header {0} is {1:?}")]
    InvalidHeader(&'static str, Option<HeaderValue>),
    #[error(transparent)]
    InvalidUri(#[from] InvalidUri),
}

pub struct HyperAcmeServerBuilder<C> {
    connector: Option<C>,
    endpoint: Endpoint,
}

impl<C> Default for HyperAcmeServerBuilder<C> {
    fn default() -> Self {
        Self {
            connector: None,
            endpoint: Endpoint::LetsEncrypt,
        }
    }
}

#[async_trait]
impl<C: Connect> AcmeServerBuilder for HyperAcmeServerBuilder<C> {
    type Server = HyperAcmeServer<C>;

    async fn build(&mut self) -> Result<Self::Server, <Self::Server as AcmeServer>::Error> {
        let replay_nonce_header = HeaderName::from_static(REPLAY_NONCE_HEADER);
        let location_header = HeaderName::from_static(LOCATION_HEADER);

        let connector = self
            .connector
            .take()
            .ok_or(HyperAcmeServerError::NoConnector)?;
        let client = Client::builder().build(connector);

        let req = Request::get(self.endpoint.to_str()).body(Body::empty())?;
        let mut res = client.request(req).await?;
        // todo: add error handling
        // todo: does no length check if in the future we allow custom acme endpoints we should keep this in mind
        let body = body::to_bytes(res.body_mut()).await?;

        let directory = serde_json::from_slice(body.as_ref())?;

        let acme_server = HyperAcmeServer {
            replay_nonce_header,
            location_header,
            client,
            directory,
        };

        Ok(acme_server)
    }
}

#[derive(Debug, Clone)]
pub struct HyperAcmeServer<C> {
    replay_nonce_header: HeaderName,
    location_header: HeaderName,
    client: Client<C, Body>,
    directory: ApiDirectory,
}

impl<C> HyperAcmeServerBuilder<C> {
    pub fn connector(&mut self, connector: C) -> &mut Self {
        self.connector = Some(connector);
        self
    }

    pub fn le_staging(&mut self) -> &mut Self {
        self.endpoint = Endpoint::LetsEncryptStaging;
        self
    }

    pub fn url<T: Into<Cow<'static, str>>>(&mut self, url: T) -> &mut Self {
        self.endpoint = Endpoint::from(url);
        self
    }
}

static APPLICATION_JOSE_JSON: HeaderValue = HeaderValue::from_static("application/jose+json");

impl<C: Connect> HyperAcmeServer<C> {
    fn handle_if_error(
        &self,
        res: &Response<Body>,
        body: &Bytes,
    ) -> Result<(), HyperAcmeServerError> {
        if res.status().is_success() {
            return Ok(());
        }
        let error: ApiError = serde_json::from_slice(body.as_ref())?;
        Err(HyperAcmeServerError::ApiError(error))
    }

    fn extract_location(
        &self,
        headers: &mut HeaderMap<HeaderValue>,
    ) -> Result<Option<Uri>, HyperAcmeServerError> {
        let location_header = match headers.remove(&self.location_header) {
            Some(location) => location,
            None => return Ok(None),
        };

        fn invalid_error(location: HeaderValue) -> Result<Option<Uri>, HyperAcmeServerError> {
            Err(HyperAcmeServerError::InvalidHeader(
                LOCATION_HEADER,
                Some(location),
            ))
        }
        let location = match location_header.to_str() {
            Ok(location) => location.try_into(),
            Err(_) => return invalid_error(location_header),
        };
        let location = match location {
            Ok(location) => location,
            Err(_) => return invalid_error(location_header),
        };

        Ok(Some(location))
    }

    async fn post_and_deserialize<T: Serialize, R>(
        &self,
        body: T,
        uri: &Uri,
    ) -> Result<(R, Option<Uri>), HyperAcmeServerError>
    where
        R: for<'a> Deserialize<'a>,
    {
        let (res, location) = self.post(body, uri).await?;
        let res = serde_json::from_slice(res.as_ref())?;
        Ok((res, location))
    }

    async fn post<T: Serialize>(
        &self,
        body: T,
        uri: &Uri,
    ) -> Result<(Bytes, Option<Uri>), HyperAcmeServerError> {
        let body = serde_json::to_vec(&body)?;

        let mut req = Request::post(uri).body(Body::from(body))?;
        req.headers_mut()
            .append(CONTENT_TYPE, APPLICATION_JOSE_JSON.clone());

        let mut res = self.client.request(req).await?;
        // todo: also no length check here
        let body = body::to_bytes(res.body_mut()).await?;
        self.handle_if_error(&res, &body)?;

        let location = self.extract_location(res.headers_mut())?;

        Ok((body, location))
    }
}

#[async_trait]
impl<C: Connect> AcmeServer for HyperAcmeServer<C> {
    type Error = HyperAcmeServerError;
    type Builder = HyperAcmeServerBuilder<C>;

    async fn new_nonce(&self) -> Result<String, Self::Error> {
        let req = Request::head(&self.directory.new_nonce).body(Body::empty())?;
        let mut res = self.client.request(req).await?;
        let body = body::to_bytes(res.body_mut()).await?;
        self.handle_if_error(&res, &body)?;

        let nonce = res
            .headers_mut()
            .remove(&self.replay_nonce_header)
            .ok_or(HyperAcmeServerError::Nonce(None))?;

        match nonce.to_str() {
            Ok(nonce) => Ok(nonce.to_owned()),
            Err(_) => Err(HyperAcmeServerError::Nonce(Some(nonce))),
        }
    }

    fn directory(&self) -> &ApiDirectory {
        &self.directory
    }

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error> {
        let (account, kid) = self
            .post_and_deserialize(req, &self.directory.new_account)
            .await?;

        let kid = match kid {
            Some(kid) => kid,
            None => return Err(HyperAcmeServerError::InvalidHeader(LOCATION_HEADER, None)),
        };

        Ok((account, kid))
    }

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, Self::Error> {
        let (account, _) = self.post_and_deserialize(req, uri).await?;
        Ok(account)
    }

    async fn update_account(
        &self,
        uri: &Uri,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<ApiAccount<()>, Self::Error> {
        let (account, _) = self.post_and_deserialize(req, uri).await?;
        Ok(account)
    }

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error> {
        let (order, location) = self
            .post_and_deserialize(req, &self.directory.new_order)
            .await?;

        let location = match location {
            Some(location) => location,
            None => return Err(HyperAcmeServerError::InvalidHeader(LOCATION_HEADER, None)),
        };

        Ok((order, location))
    }

    async fn get_order(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiOrder<()>, Self::Error> {
        let (order, _) = self.post_and_deserialize(req, uri).await?;
        Ok(order)
    }

    // todo: use retry Retry-After header
    async fn get_authorization(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAuthorization, Self::Error> {
        let (authorization, _) = self.post_and_deserialize(req, uri).await?;
        Ok(authorization)
    }

    async fn validate_challenge(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiChallenge, Self::Error> {
        let (challenge, _) = self.post_and_deserialize(req, uri).await?;
        Ok(challenge)
    }

    async fn finalize(
        &self,
        uri: &Uri,
        req: SignedRequest<ApiOrderFinalization>,
    ) -> Result<ApiOrder<()>, Self::Error> {
        let (order, _) = self.post_and_deserialize(req, uri).await?;
        Ok(order)
    }

    async fn download_certificate(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<Vec<u8>, Self::Error> {
        let (res, _) = self.post(req, uri).await?;
        Ok(res.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use acme_core::AcmeServerExt;
    use std::convert::TryFrom;
    use std::error::Error;
    use testcontainers::clients::Cli;

    use mysql::MySQL;
    use stepca::Stepca;

    use super::*;

    #[tokio::test]
    async fn containers() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = Cli::default();

        let _mysql = MySQL::run(&docker, "directory-tests");
        let stepca = Stepca::run(&docker, "directory-tests");

        let server = HyperAcmeServer::builder()
            .url(stepca.endpoint("/directory"))
            .connector(stepca.connector()?)
            .build()
            .await?;

        // check if directory getter works as expected
        assert_eq!(&server.directory, server.directory());

        // test if we get a nonce and if two nonces are different
        let nonce_one = server.new_nonce().await?;
        let nonce_two = server.new_nonce().await?;
        assert_eq!(nonce_one.len(), 43);
        assert_eq!(nonce_one.len(), 43);
        assert_ne!(nonce_one, nonce_two);

        let ApiDirectory {
            new_nonce,
            new_account,
            new_order,
            new_authz,
            revoke_cert,
            key_change,
            meta,
        } = server.directory;

        // test if directory returns correct url
        assert_eq!(new_nonce, Uri::try_from(stepca.endpoint("/new-nonce"))?);
        assert_eq!(new_account, Uri::try_from(stepca.endpoint("/new-account"))?);
        assert_eq!(new_order, Uri::try_from(stepca.endpoint("/new-order"))?);
        assert_eq!(new_authz, None);
        assert_eq!(revoke_cert, Uri::try_from(stepca.endpoint("/revoke-cert"))?);
        assert_eq!(key_change, Uri::try_from(stepca.endpoint("/key-change"))?);
        assert_eq!(meta, None);

        Ok(())
    }

    #[test]
    fn endpoint_should_return_correct_url() {
        assert_eq!(
            "https://acme-v02.api.letsencrypt.org/directory",
            Endpoint::LetsEncrypt.to_str()
        );
        assert_eq!(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            Endpoint::LetsEncryptStaging.to_str()
        );

        let endpoint = Endpoint::from("https://test.com");
        assert_eq!("https://test.com", endpoint.to_str())
    }
}
