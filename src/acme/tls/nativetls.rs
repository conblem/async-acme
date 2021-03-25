use hyper::Uri;
use tokio::net::TcpStream;
use tokio_native_tls::native_tls;
use tokio_native_tls::native_tls::Protocol;
use tokio_native_tls::{TlsConnector, TlsStream as NativeTlsStream};

use super::{connect_tcp, extract_host, HTTPSError};

pub(super) type TlsStream = NativeTlsStream<TcpStream>;

#[derive(Clone)]
pub(super) struct HTTPSConnectorInner(native_tls::TlsConnector);

impl HTTPSConnectorInner {
    pub(crate) fn new() -> Result<Self, HTTPSError> {
        let mut builder = native_tls::TlsConnector::builder();
        builder.min_protocol_version(Some(Protocol::Tlsv12));
        Ok(HTTPSConnectorInner(builder.build()?))
    }

    pub(super) async fn connect(self, req: Uri) -> Result<TlsStream, HTTPSError> {
        let port = req.port_u16();
        let host = extract_host(&req)?;
        let stream = connect_tcp(host, port).await?;

        let connector = TlsConnector::from(self.0);
        let tls_stream = connector.connect(host, stream).await?;

        Ok(tls_stream)
    }
}
