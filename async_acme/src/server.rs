use acme_core::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiDirectory, ApiNewOrder, ApiOrder, SignedRequest,
};
use async_trait::async_trait;
use hyper::body;
use hyper::client::connect::Connect as HyperConnect;
use hyper::http::header::{HeaderName, CONTENT_TYPE};
use hyper::http::HeaderValue;
use hyper::{Body, Client, Request};
use std::fmt::Debug;
use thiserror::Error;

const REPLAY_NONCE_HEADER: &str = "replay-nonce";

pub trait Connect: HyperConnect + Clone + Debug + Send + Sync + 'static {}
impl<C: HyperConnect + Clone + Debug + Send + Sync + 'static> Connect for C {}

enum Endpoint {
    LetsEncryptStaging,
    LetsEncrypt,
    Url(String),
}

impl Endpoint {
    fn to_str(&self) -> &str {
        match self {
            Endpoint::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
            Endpoint::LetsEncryptStaging => {
                "https://acme-staging-v02.api.letsencrypt.org/directory"
            }
            Endpoint::Url(endpoint) => endpoint.as_str(),
        }
    }
}

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

        let connector = self
            .connector
            .take()
            .ok_or_else(|| HyperAcmeServerError::NoConnector)?;
        let client = Client::builder().build(connector);

        let req = Request::get(self.endpoint.to_str()).body(Body::empty())?;
        let mut res = client.request(req).await?;
        let body = body::to_bytes(res.body_mut()).await?;

        let directory = serde_json::from_slice(body.as_ref())?;

        let acme_server = HyperAcmeServer {
            replay_nonce_header,
            client,
            directory,
        };

        Ok(acme_server)
    }
}

#[derive(Debug, Clone)]
pub struct HyperAcmeServer<C> {
    replay_nonce_header: HeaderName,
    client: Client<C, Body>,
    directory: ApiDirectory,
}

impl<C> HyperAcmeServerBuilder<C> {
    pub(crate) fn connector(&mut self, connector: C) -> &mut Self {
        self.connector = Some(connector);
        self
    }

    pub(crate) fn le_staging(&mut self) -> &mut Self {
        self.endpoint = Endpoint::LetsEncryptStaging;
        self
    }

    pub(crate) fn url(&mut self, url: String) -> &mut Self {
        self.endpoint = Endpoint::Url(url);
        self
    }
}

const APPLICATION_JOSE_JSON: HeaderValue = HeaderValue::from_static("application/jose+json");

#[async_trait]
impl<C: Connect> AcmeServer for HyperAcmeServer<C> {
    type Error = HyperAcmeServerError;
    type Builder = HyperAcmeServerBuilder<C>;

    async fn new_nonce(&self) -> Result<String, Self::Error> {
        let req = Request::head(&self.directory.new_nonce).body(Body::empty())?;
        let mut res = self.client.request(req).await?;

        let nonce = res
            .headers_mut()
            .remove(&self.replay_nonce_header)
            .ok_or_else(|| HyperAcmeServerError::Nonce(None))?;

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
    ) -> Result<ApiAccount<()>, Self::Error> {
        let body = serde_json::to_vec(&req)?;

        let mut req = Request::post(&self.directory.new_account).body(Body::from(body))?;
        req.headers_mut()
            .append(CONTENT_TYPE, APPLICATION_JOSE_JSON);

        let mut res = self.client.request(req).await?;
        let body = body::to_bytes(res.body_mut()).await?;
        let account = serde_json::from_slice(body.as_ref())?;

        Ok(account)
    }

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<ApiOrder<()>, Self::Error> {
        let body = serde_json::to_vec(&req)?;

        let mut req = Request::post(&self.directory.new_order).body(Body::from(body))?;
        req.headers_mut()
            .append(CONTENT_TYPE, APPLICATION_JOSE_JSON);

        let mut res = self.client.request(req).await?;
        let body = body::to_bytes(res.body_mut()).await?;
        let order = serde_json::from_slice(body.as_ref())?;

        Ok(order)
    }

    async fn finalize(&self) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let endpoint = Endpoint::Url("https://test.com".to_string());
        assert_eq!("https://test.com", endpoint.to_str())
    }
}