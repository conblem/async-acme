use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use hyper::{Client, Uri};
use serde::Serialize;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::client::TlsStream;

use super::{Nonce, RepoError};
use crate::acme::dto::ApiDirectory;
use crate::acme::SignedRequest;

#[derive(Debug)]
pub(crate) struct HyperRepo {
    client: Client<HTTPSConnector>,
}

impl HyperRepo {
    pub(crate) fn new() -> Self {
        HyperRepo {
            client: Client::builder().build(HTTPSConnector),
        }
    }

    pub(crate) async fn get_nonce(&self, url: &str) -> Result<Nonce, RepoError> {
        unimplemented!()
    }

    pub(crate) async fn get_directory(&self, url: &str) -> Result<ApiDirectory, RepoError> {
        unimplemented!()
    }

    pub(crate) async fn crate_account<S: Serialize>(
        &self,
        url: &str,
        body: &SignedRequest<S>,
    ) -> Result<(), RepoError> {
        unimplemented!()
    }
}

#[derive(Error, Debug)]
enum HTTPSError {
    #[error("No Host")]
    NoHost,

    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error("DNS returned no records")]
    EmptyLookup
}

#[derive(Clone, Debug)]
struct HTTPSConnector;

struct TlsConnection(TlsStream<TcpStream>);

impl Deref for TlsConnection {
    type Target = TlsStream<TcpStream>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TlsConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Connection for Pin<TlsConnection> {
    fn connected(&self) -> Connected {
        unimplemented!()
    }
}

impl Service<Uri> for HTTPSConnector {
    type Response = Pin<TlsConnection>;
    type Error = HTTPSError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        unimplemented!()
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        Box::pin(connect(req))
    }
}

async fn connect(req: Uri) -> Result<Pin<TlsConnection>, HTTPSError> {
    let host = match req.host() {
        Some(host) => host,
        None => Err(HTTPSError::NoHost)?,
    };

    let ip = match SocketAddr::from_str(host) {
        Ok(ip) => ip,
        Err(_) => {
            let mut ips = lookup_host(host).await?;
            ips.next().ok_or(HTTPSError::EmptyLookup)?
        },
    };

    unimplemented!()
}
