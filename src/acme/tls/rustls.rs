use hyper::client::connect::{Connected, Connection};
use hyper::Uri;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as RustTlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;
use webpki::TLSServerTrustAnchors;
use webpki_roots::TLS_SERVER_ROOTS;

use super::{connect_tcp, extract_host, HTTPSError};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) struct TlsStream(RustTlsStream<TcpStream>);

impl Deref for TlsStream {
    type Target = RustTlsStream<TcpStream>;

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
        let (tcp, _) = self.get_ref();
        tcp.connected()
    }
}

#[derive(Clone)]
pub(super) struct HTTPSConnectorInner(Arc<ClientConfig>);

impl HTTPSConnectorInner {
    pub(crate) fn new<'a, T: Into<Option<&'a [u8]>>>(der: T) -> Result<Self, HTTPSError> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&TLS_SERVER_ROOTS);

        if let Some(der) = der {
            let anchor = [webpki::trust_anchor_util::cert_der_as_trust_anchor(der).unwrap()];
            let anchor = TLSServerTrustAnchors(&anchor);
            config.root_store.add_server_trust_anchors(&anchor);
        }

        Ok(HTTPSConnectorInner(Arc::new(config)))
    }

    pub(super) async fn connect(self, uri: Uri) -> Result<TlsStream, HTTPSError> {
        let port = uri.port_u16();
        let host = extract_host(&uri)?;
        let dns = DNSNameRef::try_from_ascii_str(&host)?;

        let stream = connect_tcp(host, port).await?;

        let tls_connector = TlsConnector::from(self.0);
        let tls_stream = tls_connector.connect(dns, stream).await?;

        Ok(TlsStream(tls_stream))
    }
}

impl super::HttpsConnectorInnerTest for HTTPSConnectorInner {
    type TlsStream = Pin<TlsStream>;
}

