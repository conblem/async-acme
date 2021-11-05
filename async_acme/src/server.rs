use acme_core::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiDirectory, ApiError, ApiNewOrder, ApiOrder,
    SignedRequest, Uri,
};
use async_trait::async_trait;
use hyper::body::Bytes;
use hyper::client::connect::Connect as HyperConnect;
use hyper::http::header::{HeaderName, CONTENT_TYPE};
use hyper::http::uri::InvalidUri;
use hyper::http::HeaderValue;
use hyper::{body, Response, HeaderMap};
use hyper::{Body, Client, Request};
use serde::{Deserialize, Serialize};
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
            .ok_or_else(|| HyperAcmeServerError::NoConnector)?;
        let client = Client::builder().build(connector);

        let req = Request::get(self.endpoint.to_str()).body(Body::empty())?;
        let mut res = client.request(req).await?;
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

    fn extract_location(&self, headers: &mut HeaderMap<HeaderValue>) -> Result<Option<Uri>, HyperAcmeServerError> {
        let location_header = match headers.remove(&self.location_header) {
            Some(location) => location,
            None => return Ok(None),
        };

        let invalid_error = |location: HeaderValue| {
            Err(HyperAcmeServerError::InvalidHeader(LOCATION_HEADER, Some(location)))
        };
        let location = match location_header.to_str() {
            Ok(location) => location.try_into(),
            Err(_) => return invalid_error(location_header)
        };
        let location = match location {
            Ok(location) => location,
            Err(_) => return invalid_error(location_header)
        };

        Ok(Some(location))
    }

    async fn post<T: Serialize, R>(
        &self,
        body: T,
        uri: &Uri,
    ) -> Result<(R, Option<Uri>), HyperAcmeServerError>
    where
        R: for<'a> Deserialize<'a>,
    {
        let body = serde_json::to_vec(&body)?;

        let mut req = Request::post(uri).body(Body::from(body))?;
        req.headers_mut()
            .append(CONTENT_TYPE, APPLICATION_JOSE_JSON);

        let mut res = self.client.request(req).await?;
        let body = body::to_bytes(res.body_mut()).await?;
        self.handle_if_error(&res, &body)?;

        let location = self.extract_location(res.headers_mut())?;
        let res = serde_json::from_slice(body.as_ref())?;
        Ok((res, location))
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
    ) -> Result<(ApiAccount<()>, Uri), Self::Error> {
        let (account, kid) = self.post(req, &self.directory.new_account).await?;

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
        let (account, _) = self.post(req, uri).await?;
        Ok(account)
    }

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error> {
        let (order, location) = self.post(req, &self.directory.new_order).await?;

        let location = match location {
            Some(location) => location,
            None => return Err(HyperAcmeServerError::InvalidHeader(LOCATION_HEADER, None)),
        };

        Ok((order, location))
    }

    async fn get_order(&self, uri: &Uri, req: SignedRequest<()>) -> Result<ApiOrder<()>, Self::Error> {
        let (order, _) = self.post(req, uri).await?;
        Ok(order)
    }

    async fn finalize(&self) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use testcontainers::{clients, Image, Docker, Container};
    use std::convert::Infallible;
    use std::collections::HashMap;
    use std::array::IntoIter;
    use std::thread::{sleep, spawn};
    use std::time::Duration;
    use std::io;

    use super::*;

    #[derive(Default)]
    struct SmallStepVolumes;

    impl IntoIterator for SmallStepVolumes {
        type Item = (String, String);
        type IntoIter = IntoIter<(String, String), 2>;

        fn into_iter(self) -> Self::IntoIter {
            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            let from = format!("{}/smallstep/config", manifest_dir);
            let to = "/home/step/config/".to_string();
            let config = (from, to);

            let from = format!("{}/smallstep/secrets", manifest_dir);
            let to = "/home/step/secrets/".to_string();
            let secrets = (from, to);

            IntoIter::new([config, secrets])
        }
    }


    #[derive(Default)]
    struct SmallStepArgs;

    impl IntoIterator for SmallStepArgs {
        type Item = String;
        type IntoIter = IntoIter<String, 0>;

        fn into_iter(self) -> Self::IntoIter {
            IntoIter::new([])
        }
    }

    #[derive(Default)]
    struct SmallStep;

    impl Image for SmallStep {
        type Args = SmallStepArgs;
        type EnvVars = HashMap<String, String>;
        type Volumes = SmallStepVolumes;
        type EntryPoint = Infallible;

        fn descriptor(&self) -> String {
            "smallstep/step-ca:0.17.6".to_string()
        }

        // todo: implement
        fn wait_until_ready<D: Docker>(&self, container: &Container<'_, D, Self>) {
            container.
            let mut logs = container.logs();
            let mut stdout = io::stdout();
            io::copy(logs.stderr.as_mut(), &mut stdout);
        }

        fn args(&self) -> Self::Args {
            SmallStepArgs::default()
        }

        fn env_vars(&self) -> Self::EnvVars {
            HashMap::new()
        }

        fn volumes(&self) -> Self::Volumes {
            SmallStepVolumes::default()
        }

        fn with_args(self, _arguments: Self::Args) -> Self {
            self
        }
    }

    #[test]
    fn containers() {
        let docker = clients::Cli::default();
        MySql
        let smallstep = SmallStep::default();
        docker.run(smallstep);
        sleep(Duration::from_secs(20));
        panic!()
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

        let endpoint = Endpoint::Url("https://test.com".to_string());
        assert_eq!("https://test.com", endpoint.to_str())
    }
}
