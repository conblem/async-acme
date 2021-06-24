use hyper::client::connect::{Connected, Connection};
use hyper::Uri;
use openssl::ssl::{SslConnector, SslMethod, SslVersion};
use openssl::x509::X509;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use super::{connect_tcp, extract_host, HTTPSError};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) struct TlsStream(SslStream<TcpStream>);

impl Deref for TlsStream {
    type Target = SslStream<TcpStream>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TlsStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Connection for Pin<TlsStream> {
    fn connected(&self) -> Connected {
        self.get_ref().connected()
    }
}

#[derive(Clone)]
pub(super) struct HTTPSConnectorInner(SslConnector);

impl HTTPSConnectorInner {
    pub(crate) fn new<'a, T: Into<Option<&'a [u8]>>>(der: T) -> Result<Self, HTTPSError> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        if let Some(der) = der {
            let cert = X509::from_der(der)?;
            builder.add_extra_chain_cert(cert)?;
        }
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        Ok(HTTPSConnectorInner(builder.build()))
    }

    pub(super) async fn connect(self, req: Uri) -> Result<TlsStream, HTTPSError> {
        let port = req.port_u16();
        let host = extract_host(&req)?;
        let stream = connect_tcp(host, port).await?;

        let ssl = self.0.configure()?.into_ssl(host)?;

        let mut tls_stream = SslStream::new(ssl, stream)?;
        Pin::new(&mut tls_stream).connect().await?;

        Ok(TlsStream(tls_stream))
    }
}

impl super::HttpsConnectorInnerTest for HTTPSConnectorInner {
    type TlsStream = Pin<TlsStream>;
}