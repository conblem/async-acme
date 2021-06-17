use hyper::Uri;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use std::pin::Pin;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{connect_tcp, extract_host, HTTPSError};

pub(super) type TlsStream = SslStream<TcpStream>;

#[derive(Clone)]
pub(super) struct HTTPSConnectorInner(SslConnector);

impl HTTPSConnectorInner {
    pub(crate) fn new() -> Result<Self, HTTPSError> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        Ok(HTTPSConnectorInner(builder.build()))
    }

    pub(super) async fn connect(self, req: Uri) -> Result<SslStream<TcpStream>, HTTPSError> {
        let port = req.port_u16();
        let host = extract_host(&req)?;
        let stream = connect_tcp(host, port).await?;

        let ssl = self.0.configure()?.into_ssl(host)?;

        let mut tls_stream = SslStream::new(ssl, stream)?;
        Pin::new(&mut tls_stream).connect().await?;

        Ok(tls_stream)
    }
}
