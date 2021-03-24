use hyper::Uri;
use std::io;
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};

#[cfg(feature = "rustls")]
use tokio_rustls::webpki::InvalidDNSNameError;
#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub(crate) use rustls::HTTPSConnector;

#[cfg(feature = "native-tls")]
use tokio_native_tls::native_tls;
#[cfg(feature = "native-tls")]
mod nativetls;
#[cfg(feature = "native-tls")]
pub(crate) use nativetls::HTTPSConnector;

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

    #[cfg(feature = "native-tls")]
    #[error("Native TLS Error")]
    NativeTLS(#[from] native_tls::Error),
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

// use this to increase code reuse
trait Func: FnOnce(Uri) -> <Self as Func>::Output {
    type Output;
}

impl <O, F> Func for F where F: FnOnce(Uri) -> O {
    type Output = O;
}