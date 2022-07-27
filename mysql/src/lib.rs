use std::time::Duration;
use testcontainers::clients::Cli;
use testcontainers::core::WaitFor;
use testcontainers::images::generic::GenericImage;
use testcontainers::{Container, RunnableImage};

pub struct MySQL<'a>(Container<'a, GenericImage>, String);

impl<'a> MySQL<'a> {
    pub fn run(docker: &'a Cli, network: &str) -> Self {
        let wait_for = WaitFor::message_on_stdout("MySQL init process done. Ready for start up.");
        let mysql = GenericImage::new("mysql", "8.0.29")
            .with_env_var("MYSQL_ROOT_PASSWORD", "root")
            .with_env_var("MYSQL_DATABASE", "asyncacme")
            .with_wait_for(wait_for);

        let mysql = RunnableImage::from(mysql)
            .with_container_name("mysql")
            .with_network(network);

        let mysql = docker.run(mysql);

        std::thread::sleep(Duration::from_secs(5));

        let port = mysql.get_host_port_ipv4(3306);

        MySQL(
            mysql,
            format!("mysql://root:root@localhost:{}/asyncacme", port),
        )
    }

    pub fn connection_string(&self) -> &str {
        &self.1
    }
}

#[cfg(test)]
mod tests {
    use sqlx::MySqlPool;
    use std::error::Error;

    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = Cli::default();
        let mysql = MySQL::run(&docker, "mysql");

        let pool = MySqlPool::connect(mysql.connection_string()).await?;

        let (res,): (i64,) = sqlx::query_as("SELECT 1 + 1").fetch_one(&pool).await?;
        assert_eq!(res, 2);

        Ok(())
    }
}
