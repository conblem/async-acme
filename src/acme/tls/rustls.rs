use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use hyper::Uri;
use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::webpki::{DNSNameRef, InvalidDNSNameError};
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

#[derive(Error, Debug)]
pub(crate) enum HTTPSError {
    #[error("No Host")]
    NoHost,

    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error("DNS returned no records")]
    EmptyLookup,

    #[error("Invalid DNS Name")]
    InvalidDNSName(#[from] InvalidDNSNameError),
}

#[derive(Clone)]
pub(crate) struct HTTPSConnector {
    config: Arc<ClientConfig>,
}

impl HTTPSConnector {
    pub(crate) fn new() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&TLS_SERVER_ROOTS);

        HTTPSConnector {
            config: Arc::new(config),
        }
    }
}

pub(crate) struct TlsConnection(TlsStream<TcpStream>);

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
        Connected::new()
    }
}

impl From<TlsStream<TcpStream>> for Pin<TlsConnection> {
    fn from(stream: TlsStream<TcpStream>) -> Self {
        Pin::new(TlsConnection(stream))
    }
}

impl Service<Uri> for HTTPSConnector {
    type Response = Pin<TlsConnection>;
    type Error = HTTPSError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    // todo: maybe do something
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let config = self.config.clone();
        Box::pin(connect(req, config))
    }
}

async fn connect(req: Uri, config: Arc<ClientConfig>) -> Result<Pin<TlsConnection>, HTTPSError> {
    let port = req.port_u16().unwrap_or(443);
    let host = match req.host() {
        Some(host) => host,
        None => Err(HTTPSError::NoHost)?,
    };
    let host_with_port = format!("{}:{}", host, port);

    let mut ips = lookup_host(host_with_port).await?;
    let ip = ips.next().ok_or(HTTPSError::EmptyLookup)?;

    let dns = DNSNameRef::try_from_ascii_str(host)?;

    let stream = TcpStream::connect(ip).await?;
    let tls_connector = TlsConnector::from(config);
    let tls_stream = tls_connector.connect(dns, stream).await?;

    Ok(tls_stream.into())
}
