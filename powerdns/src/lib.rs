use serde::{Deserialize, Serialize};
use testcontainers::clients::Cli;
use testcontainers::core::WaitFor;
use testcontainers::images::generic::GenericImage;
use testcontainers::{Container, RunnableImage};

#[derive(Deserialize, Debug, Clone)]
pub struct ApiServer {
    #[serde(rename = "type")]
    pub type_val: String,
    pub id: String,
    pub daemon_type: DaemonType,
    pub version: String,
    pub url: String,
    pub config_url: String,
    pub zones_url: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum DaemonType {
    Recursor,
    Authoritative,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ApiZone {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_val: String,
    pub url: String,
    pub kind: ZoneKind,
    pub rrsets: Vec<()>,
    #[serde(skip_serializing)]
    pub serial: u32,
    #[serde(skip_serializing)]
    pub notified_serial: u32,
    pub edited_serial: u32,
    pub masters: Vec<String>,
    pub dnssec: bool,
    pub nsec3param: String,
    pub nsec3narrow: bool,
    pub presigned: bool,
    pub soa_edit: String,
    pub soa_edit_api: String,
    pub api_rectify: bool,
    pub zone: Option<String>,
    pub account: Option<String>,
    #[serde(default)]
    pub nameservers: Vec<String>,
    pub master_tsgi_key_ids: Vec<String>,
    pub slave_tsig_key_ids: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum ZoneType {
    Zone,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum ZoneKind {
    Native,
    Master,
    Slave,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum RRSetType {
    A,
    PTR,
    MX,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum RRSetChangeType {
    REPLACE,
    DELETE,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RRSet {
    pub name: String,
    #[serde(rename = "type")]
    pub type_val: RRSetType,
    pub ttl: u32,
    pub changetype: String,
    pub records: Vec<ApiRecord>,
    pub comments: Vec<ApiComment>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ApiRecord {
    pub content: String,
    pub disabled: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ApiComment {
    pub content: String,
    pub account: String,
    // figure out the correct datatype for this
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub modified_at: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
struct ApiError {
    error: String,
    errors: Vec<String>,
}

pub fn powerdns_container<T: Into<String>>(docker: &Cli, name: T) -> Container<'_, GenericImage> {
    let wait_for = WaitFor::message_on_stderr("Creating backend connection for TCP");

    let powerdns = GenericImage::new("powerdns", "latest")
        .with_wait_for(wait_for)
        .with_env_var("MYSQL_DB", "asyncacme");

    let powerdns = RunnableImage::from(powerdns)
        .with_network("powerdns")
        .with_container_name(name);

    docker.run(powerdns)
}

#[derive(Clone)]
struct Client {
    client: reqwest::Client,
    base_url: String,
}

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

impl Client {
    fn format_url<T: AsRef<str>>(&self, path: T) -> String {
        format!("{}{}", self.base_url, path.as_ref())
    }

    async fn get<T, R>(&self, path: T) -> Result<R, Error>
    where
        T: AsRef<str>,
        R: for<'a> Deserialize<'a>,
    {
        let res = self
            .client
            .get(self.format_url(path))
            .header("X-API-Key", "root")
            .send()
            .await?;
        let status = res.status();

        if status.is_success() {
            return Ok(res.json().await?);
        }

        let error: ApiError = res.json().await?;
        let error = format!("{}: {}", status, error.error);

        Err(error.into())
    }

    pub fn new<T: Into<String>>(base_url: T) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    pub async fn get_servers(&self) -> Result<Vec<Server<'_>>, Error> {
        let servers: Vec<ApiServer> = self.get("/servers").await?;
        let servers = servers
            .into_iter()
            .map(|inner| Server {
                client: self,
                inner,
            })
            .collect();

        Ok(servers)
    }

    pub async fn get_server<T: AsRef<str>>(&self, server_id: T) -> Result<Server<'_>, Error> {
        let path = format!("/servers/{}", server_id.as_ref());
        let inner = self.get(path).await?;

        Ok(Server {
            client: self,
            inner,
        })
    }
}

struct Server<'a> {
    client: &'a Client,
    inner: ApiServer,
}

impl<'a> Server<'a> {}

#[cfg(test)]
mod tests {
    use mysql::MySQL;

    use super::*;

    #[tokio::test]
    async fn works() -> Result<(), Error> {
        let docker = Cli::default();

        let _mysql = MySQL::run(&docker, "powerdns");

        let powerdns = powerdns_container(&docker, "powerdns");
        let powerdns_port = powerdns.get_host_port_ipv4(8081);

        let client = Client::new(format!("http://localhost:{}/api/v1", powerdns_port));
        let servers = client.get_servers().await?;
        assert_eq!(servers.len(), 1);

        let server = client.get_server("localhost").await;

        Ok(())
    }
}
