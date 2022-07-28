use hyper::client::connect::Connect as HyperConnect;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use rustls::{Certificate, ClientConfig, RootCertStore};
use std::error::Error;
use std::fmt::Debug;
use testcontainers::clients::Cli;
use testcontainers::core::WaitFor;
use testcontainers::images::generic::GenericImage;
use testcontainers::{Container, RunnableImage};

pub trait Connect: HyperConnect + Clone + Debug + Send + Sync + 'static {}
impl<C: HyperConnect + Clone + Debug + Send + Sync + 'static> Connect for C {}

pub struct Stepca<'a>(Container<'a, GenericImage>, String);

impl<'a> Stepca<'a> {
    pub fn run(docker: &'a Cli, network: &str) -> Self {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let from = format!("{}/smallstep", manifest_dir);
        let to = "/home/step/".to_string();

        let args = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exec /usr/local/bin/step-ca /home/step/config/ca.json".to_string(),
        ];

        // should be stdout container does weird stuff
        let wait_for = WaitFor::message_on_stderr("Serving HTTPS");

        let smallstep = GenericImage::new("smallstep/step-ca", "0.17.6")
            .with_volume(from, to)
            .with_exposed_port(9000)
            .with_wait_for(wait_for);

        let smallstep = RunnableImage::from((smallstep, args)).with_network(network);
        let smallstep = docker.run(smallstep);
        let port = smallstep.get_host_port_ipv4(9000);

        Stepca(smallstep, format!("https://localhost:{}/acme/acme", port))
    }

    pub fn endpoint(&self, path: &str) -> String {
        let mut endpoint = self.1.clone();
        endpoint.push_str(path);

        endpoint
    }

    pub fn connector(&self) -> Result<impl Connect, Box<dyn Error + Send + Sync + 'static>> {
        let mut root_certs = RootCertStore::empty();

        let mut root_cert = include_bytes!("../smallstep/certs/root_ca.crt").as_ref();
        let mut root_cert = rustls_pemfile::certs(&mut root_cert)?;
        root_certs.add(&Certificate(root_cert.remove(0)))?;

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();

        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Ok(HttpsConnector::from((http, config)))
    }
}
