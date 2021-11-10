use std::array::IntoIter;
use std::collections::HashMap;
use testcontainers::{clients, Container, Docker, Image, RunArgs, WaitForMessage};
use testcontainers::images::generic::GenericImage;

#[derive(Default)]
pub struct MySqlEnv;

impl IntoIterator for MySqlEnv {
    type Item = (String, String);
    type IntoIter = IntoIter<(String, String), 2>;

    fn into_iter(self) -> Self::IntoIter {
        let password = ("MYSQL_ROOT_PASSWORD".to_string(), "root".to_string());
        let database = ("MYSQL_DATABASE".to_string(), "asyncacme".to_string());

        IntoIter::new([password, database])
    }
}

#[derive(Default)]
pub struct MySqlImage;

impl Image for MySqlImage {
    type Args = Vec<String>;
    type EnvVars = MySqlEnv;
    type Volumes = HashMap<String, String>;
    type EntryPoint = String;

    fn descriptor(&self) -> String {
        "mysql:latest".to_string()
    }

    fn wait_until_ready<D: Docker>(&self, container: &Container<'_, D, Self>) {
        std::thread::sleep(std::time::Duration::from_secs(20));
        let stdout = container.logs().stdout;
        stdout.wait_for_message("MySQL init process done. Ready for start up.").unwrap();
    }

    fn args(&self) -> Self::Args {
        Self::Args::default()
    }

    fn env_vars(&self) -> Self::EnvVars {
        Self::EnvVars::default()
    }

    fn volumes(&self) -> Self::Volumes {
        Self::Volumes::default()
    }

    fn with_args(self, _arguments: Self::Args) -> Self {
        unimplemented!()
    }
}

pub fn mysql_container<T: ToString>(
    docker: &clients::Cli,
    name: T,
) -> Container<'_, clients::Cli, MySqlImage> {
    GenericImage::new("test;");
    let mysql_args = RunArgs::default().with_network("asyncacme").with_name(name);

    docker.run_with_args(MySqlImage::default(), mysql_args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::MySqlPool;
    use std::error::Error;

    #[tokio::test]
    async fn it_works() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = clients::Cli::default();
        let mysql = mysql_container(&docker, "mysql");
        let mysql_port = mysql.get_host_port(3306).ok_or("Port not found")?;

        // sleep a little extra
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let uri = format!("mysql://root:password@localhost:{}/asyncacme", mysql_port);
        let pool = MySqlPool::connect(&uri).await?;

        let (res,): (i64,) = sqlx::query_as("SELECT 1 + 1").fetch_one(&pool).await?;
        assert_eq!(res, 2);

        Ok(())
    }
}
