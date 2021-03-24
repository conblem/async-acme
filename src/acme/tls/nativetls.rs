use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use hyper::Uri;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Protocol;
use tokio_native_tls::{TlsConnector, TlsStream};

use super::{connect_tcp, extract_host, HTTPSError};

#[derive(Clone)]
pub(crate) struct HTTPSConnector {
    connector: native_tls::TlsConnector,
}

impl HTTPSConnector {
    pub(crate) fn new() -> Result<Self, HTTPSError> {
        let mut builder = native_tls::TlsConnector::builder();
        builder.min_protocol_version(Some(Protocol::Tlsv12));

        Ok(HTTPSConnector {
            connector: builder.build()?,
        })
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
        let connector = self.connector.clone();
        Box::pin(connect(req, connector))
    }
}

async fn connect(
    req: Uri,
    connector: native_tls::TlsConnector,
) -> Result<Pin<TlsConnection>, HTTPSError> {
    let port = req.port_u16();
    let host = extract_host(&req)?;
    let stream = connect_tcp(host, port).await?;

    let connector = TlsConnector::from(connector);
    let tls_stream = connector.connect(host, stream).await?;

    Ok(tls_stream.into())
}
