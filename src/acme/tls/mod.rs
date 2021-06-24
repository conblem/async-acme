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

#[cfg(any(feature = "rustls", test))]
mod rustls;

#[cfg(any(feature = "open-ssl", test))]
mod openssl;

use tokio::io::{AsyncRead, AsyncWrite};

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
    InvalidDNSName(#[from] tokio_rustls::webpki::InvalidDNSNameError),

    #[cfg(feature = "open-ssl")]
    #[error("OpenSSL Error Stack")]
    OpenSSLErrorStack(#[from] ::openssl::error::ErrorStack),

    #[cfg(feature = "open-ssl")]
    #[error("OpenSSL SSL Error")]
    OpenSSLErrorSSL(#[from] ::openssl::ssl::Error),
}

// if both all features are selected use ring
#[cfg(feature = "rustls")]
pub(crate) type HttpsConnectorInner = rustls::HTTPSConnectorInner;
#[cfg(all(not(feature = "rustls"), feature = "open-ssl"))]
pub(crate) type HttpsConnectorInner = openssl::HTTPSConnectorInner;

pub(crate) type HttpsConnector = HTTPSConnectorGeneric<HttpsConnectorInner>;

#[derive(Clone)]
pub(crate) struct HTTPSConnectorGeneric<I>(I);

impl<I> HTTPSConnectorGeneric<I> {
    #[cfg(feature = "rustls")]
    pub(crate) fn new() -> Result<HttpsConnector, HTTPSError> {
        let inner = rustls::HTTPSConnectorInner::new(None)?;
        return Ok(HTTPSConnectorGeneric(inner));
    }

    #[cfg(all(not(feature = "rustls"), feature = "open-ssl"))]
    pub(crate) fn new() -> Result<HttpsConnector, HTTPSError> {
        let inner = rustls::HTTPSConnectorInner::new(None)?;
        return Ok(HTTPSConnectorGeneric(inner));
    }
}

impl Service<Uri> for HTTPSConnectorGeneric<HttpsConnectorInner> {
    type Response = <HttpsConnectorInner as HttpsConnectorInnerTest>::TlsStream;
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

// todo: rename
pub(crate) trait HttpsConnectorInnerTest: Clone {
    type TlsStream: AsyncRead + AsyncWrite + Connection;
}

#[cfg(test)]
mod tests {
    use hyper::body::to_bytes;
    use hyper::{Body, Client};
    use std::convert::TryInto;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::str;
    use warp::Filter;

    use super::*;

    fn server() -> SocketAddr {
        let routes = warp::any().map(|| "Hello, World!");

        let localhost = include_bytes!("localhost.crt");
        let localhost_key = include_bytes!("localhost.key");

        let (addr, fut) = warp::serve(routes)
            .tls()
            .cert(localhost)
            .key(localhost_key)
            .bind_ephemeral(([127, 0, 0, 1], 0));

        tokio::spawn(fut);

        addr
    }

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let addr = server();

        let ca = include_bytes!("ca.der");
        let rustls_connector = rustls::HTTPSConnectorInner::new(&ca[..])?;
        let rustls_connector = HTTPSConnectorGeneric(rustls_connector);
        let rustls_client = Client::builder()
            .build::<HTTPSConnectorGeneric<rustls::HTTPSConnectorInner>, Body>(rustls_connector);

        let mut res = rustls_client
            .get(format!("http://localhost:{}", addr.port()).try_into()?)
            .await?;
        let body = to_bytes(res.body_mut()).await.unwrap();
        let actual = str::from_utf8(body.as_ref())?;

        assert_eq!("Hello, World!", actual);
        Ok(())
    }
}
