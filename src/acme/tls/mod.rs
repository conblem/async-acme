use hyper::client::connect::{Connect, Connection};
use hyper::service::Service;
use hyper::Uri;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{lookup_host, TcpStream};

#[cfg(feature = "rustls")]
mod rustls;

#[cfg(feature = "open-ssl")]
mod openssl;

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

pub(crate) trait Inner: Clone + FnOnce(Uri) -> <Self as Inner>::Output {
    type Output;
}

impl<O, F> Inner for F
where
    F: Clone + FnOnce(Uri) -> O,
{
    type Output = O;
}

#[derive(Clone)]
pub(crate) struct HttpsConnector<I>(I);

impl HttpsConnector<()> {
    #[cfg(feature = "rustls")]
    pub(crate) fn new() -> Result<impl Connect + Clone + Send + Sync + 'static, HTTPSError> {
        let inner = openssl::connector(None)?;
        Ok(HttpsConnector(inner))
    }

    #[cfg(all(feature = "openssl", not(feature = "rustls")))]
    pub(crate) fn new() -> Result<impl Connect + Clone + Send + Sync + 'static, HTTPSError> {
        let inner = rustls::connector(None)?;
        Ok(HttpsConnector(inner))
    }
}

impl<S, F, I> Service<Uri> for HttpsConnector<I>
where
    S: AsyncRead + AsyncWrite + Connection + 'static,
    F: Future<Output = Result<S, HTTPSError>> + Send + Sync + 'static,
    I: Inner<Output = F>,
{
    type Response = S;
    type Error = HTTPSError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let inner = self.0.clone();

        Box::pin(inner(req))
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
    async fn run() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let addr = server();
        let ca = include_bytes!("ca.der");

        let rustls_inner = rustls::connector(&ca[..])?;
        test(rustls_inner, &addr).await?;

        let openssl_inner = openssl::connector(&ca[..])?;
        test(openssl_inner, &addr).await?;

        Ok(())
    }

    async fn test<I>(inner: I, addr: &SocketAddr) -> Result<(), Box<dyn Error + Send + Sync + 'static>> where HttpsConnector<I>: Connect + Clone + Send + Sync + 'static {
        let connector = HttpsConnector(inner);
        let client = Client::builder().build::<_, Body>(connector);

        let mut res = client
            .get(format!("https://localhost:{}", addr.port()).try_into()?)
            .await?;
        let body = to_bytes(res.body_mut()).await.unwrap();
        let actual = str::from_utf8(body.as_ref())?;

        assert_eq!("Hello, World!", actual);
        Ok(())
    }
}
