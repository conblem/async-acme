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
pub struct Server {
    #[serde(rename = "type")]
    pub type_val: String,
    pub id: String,
    pub daemon_type: DaemonType,
    pub version: String,
    pub url: String,
    pub config_url: String,
    pub zones_url: String,
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

    let run_args = RunArgs::default()
        .with_network("asyncacme")
        .with_name(name);

    docker.run_with_args(powerdns, run_args)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use mysql::mysql_container;

    use super::*;

    #[test]
    fn works() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = clients::Cli::default();
        let _mysql = mysql_container(&docker, "mysql-powerdns");
        let powerdns = powerdns_container(&docker, "powerdns", "mysql-powerdns");
        let powerdns_port = powerdns.get_host_port(8081).ok_or("Port not found")?;
        std::thread::sleep(std::time::Duration::from_secs(20));

        Ok(())
    }
}
