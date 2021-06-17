use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use hyper::Uri;
use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};

#[cfg(feature = "rustls")]
use tokio_rustls::webpki::InvalidDNSNameError;
#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
use rustls::{HTTPSConnectorInner, TlsStream};

#[cfg(feature = "open-ssl")]
mod openssl;
#[cfg(feature = "open-ssl")]
use self::openssl::{HTTPSConnectorInner, TlsStream};
#[cfg(feature = "open-ssl")]
use ::openssl::error::ErrorStack;
#[cfg(feature = "open-ssl")]
use ::openssl::ssl::Error as SSLError;

#[derive(Error, Debug)]
pub(crate) enum HTTPSError {
    #[error("No Host")]
    NoHost,

    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error("DNS returned no records")]
    EmptyLookup,

    #[cfg(feature = "rustls")]
    #[error("Invalid DNS Name")]
    InvalidDNSName(#[from] InvalidDNSNameError),

    #[cfg(feature = "open-ssl")]
    #[error("OpenSSL Error Stack")]
    OpenSSLErrorStack(#[from] ErrorStack),

    #[cfg(feature = "open-ssl")]
    #[error("OpenSSL SSL Error")]
    OpenSSLErrorSSL(#[from] SSLError),
}

#[derive(Clone)]
pub(crate) struct HTTPSConnector(HTTPSConnectorInner);

impl HTTPSConnector {
    pub(crate) fn new() -> Result<Self, HTTPSError> {
        let inner = HTTPSConnectorInner::new()?;
        Ok(HTTPSConnector(inner))
    }
}

impl Service<Uri> for HTTPSConnector {
    type Response = Pin<TlsConnection<TlsStream>>;
    type Error = HTTPSError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let inner = self.0.clone();
        Box::pin(async move {
            let tls_connection = inner.connect(uri).await?;
            Ok(tls_connection.into())
        })
    }
}

pub(crate) struct TlsConnection<T>(T);

impl<T> Deref for TlsConnection<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for TlsConnection<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Connection for Pin<TlsConnection<T>> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl<T: Unpin> From<T> for Pin<TlsConnection<T>> {
    fn from(stream: T) -> Self {
        Pin::new(TlsConnection(stream))
    }
}

fn extract_host(req: &Uri) -> Result<&str, HTTPSError> {
    match req.host() {
        Some(host) => Ok(host),
        None => Err(HTTPSError::NoHost),
    }
}

async fn connect_tcp(host: &str, port: Option<u16>) -> Result<TcpStream, HTTPSError> {
    let port = port.unwrap_or(443);
    let host_with_port = format!("{}:{}", host, port);

    let mut ips = lookup_host(host_with_port).await?;
    let ip = ips.next().ok_or(HTTPSError::EmptyLookup)?;

    let stream = TcpStream::connect(ip).await?;
    Ok(stream)
}
