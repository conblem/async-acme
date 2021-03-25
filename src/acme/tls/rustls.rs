use hyper::Uri;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as RustTlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use super::{connect_tcp, extract_host, HTTPSError};

pub(super) type TlsStream = RustTlsStream<TcpStream>;

#[derive(Clone)]
pub(super) struct HTTPSConnectorInner(Arc<ClientConfig>);

impl HTTPSConnectorInner {
    pub(crate) fn new() -> Result<Self, HTTPSError> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&TLS_SERVER_ROOTS);

        Ok(HTTPSConnectorInner(Arc::new(config)))
    }

    pub(super) async fn connect(self, uri: Uri) -> Result<TlsStream, HTTPSError> {
        let port = uri.port_u16();
        let host = extract_host(&uri)?;
        let dns = DNSNameRef::try_from_ascii_str(&host)?;

        let stream = connect_tcp(host, port).await?;

        let tls_connector = TlsConnector::from(self.0);
        let tls_stream = tls_connector.connect(dns, stream).await?;

        Ok(tls_stream)
    }
}
