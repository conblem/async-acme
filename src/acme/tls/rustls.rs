use hyper::client::connect::{Connected, Connection};
use hyper::Uri;
use std::future::Future;
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

use super::{connect_tcp, extract_host, HTTPSError, Inner};

pub(crate) struct TlsStream(RustTlsStream<TcpStream>);

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

pub(super) fn connector<'a, T: Into<Option<&'a [u8]>>>(
    der: T,
) -> Result<impl Inner<Output = impl Future<Output = Result<Pin<TlsStream>, HTTPSError>>>, HTTPSError>
{
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&TLS_SERVER_ROOTS);

    if let Some(der) = der.into() {
        // todo handle this error
        let anchor = [webpki::trust_anchor_util::cert_der_as_trust_anchor(der).unwrap()];
        let anchor = TLSServerTrustAnchors(&anchor);
        config.root_store.add_server_trust_anchors(&anchor);
    }

    let config = Arc::new(config);

    Ok(|req: Uri| async move {
        let port = req.port_u16();
        let host = extract_host(&req)?;
        let dns = DNSNameRef::try_from_ascii_str(&host)?;

        let stream = connect_tcp(host, port).await?;

        let tls_connector = TlsConnector::from(config);
        let tls_stream = tls_connector.connect(dns, stream).await?;

        Ok(Pin::new(TlsStream(tls_stream)))
    })
}
