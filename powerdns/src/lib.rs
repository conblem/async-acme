use reqwest::StatusCode;
use serde::Deserialize;
use testcontainers::images::generic::{GenericImage, WaitFor};
use testcontainers::{clients, Container, Docker, RunArgs};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum DaemonType {
    Recursor,
    Authoritative,
}

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
struct ApiError {
    error: String,
    errors: Vec<String>,
}

pub fn powerdns_container<T: ToString, M: Into<String>>(
    docker: &clients::Cli,
    name: T,
    mysql: M,
) -> Container<'_, clients::Cli, GenericImage> {
    let wait_for = WaitFor::message_on_stderr("Creating backend connection for TCP");

    let powerdns = GenericImage::new("powerdns:latest")
        .with_wait_for(wait_for)
        .with_env_var("MYSQL_HOST", mysql)
        .with_env_var("MYSQL_DB", "asyncacme");

    let run_args = RunArgs::default().with_network("asyncacme").with_name(name);

    docker.run_with_args(powerdns, run_args)
}

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
        let res = self.client.get(self.format_url(path)).send().await?;
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

    pub async fn get_servers(&self) -> Result<Vec<Server>, Error> {
        let servers: Vec<ApiServer> = self.get("/servers").await?;
        let servers = servers
            .into_iter()
            .map(|inner| Server { inner })
            .collect();

        Ok(servers)
    }

    pub async fn get_server<T: AsRef<str>>(&self, server_id: T) -> Result<Server, Error> {
        let path = format!("/servers/{}", server_id.as_ref());
        let inner = self.get(path).await?;

        Ok(Server { inner })
    }
}

struct Server {
    inner: ApiServer,
}

#[cfg(test)]
mod tests {
    use mysql::mysql_container;

    use super::*;

    #[tokio::test]
    async fn works() -> Result<(), Error> {
        let docker = clients::Cli::default();
        let _mysql = mysql_container(&docker, "mysql-powerdns");
        let powerdns = powerdns_container(&docker, "powerdns", "mysql-powerdns");
        let powerdns_port = powerdns.get_host_port(8081).ok_or("Port not found")?;

        let client = Client::new(format!("http://localhost:{}", powerdns_port));
        let servers = client.get_servers().await?;
        assert_eq!(servers.len(), 1);

        Ok(())
    }
}
