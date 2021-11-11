use std::time::Duration;
use testcontainers::images::generic::{GenericImage, WaitFor};
use testcontainers::{clients, Container, Docker, RunArgs};

pub fn mysql_container<T: ToString>(
    docker: &clients::Cli,
    name: T,
) -> Container<'_, clients::Cli, GenericImage> {
    let wait_for = WaitFor::message_on_stdout("MySQL init process done. Ready for start up.");
    let mysql = GenericImage::new("mysql:8")
        .with_env_var("MYSQL_ROOT_PASSWORD", "root")
        .with_env_var("MYSQL_DATABASE", "asyncacme")
        .with_wait_for(wait_for);

    let mysql_args = RunArgs::default().with_network("asyncacme").with_name(name);

    let mysql = docker.run_with_args(mysql, mysql_args);

    std::thread::sleep(Duration::from_secs(5));

    mysql
}

#[cfg(test)]
mod tests {
    use sqlx::MySqlPool;
    use std::error::Error;

    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = clients::Cli::default();
        let mysql = mysql_container(&docker, "mysql");
        let mysql_port = mysql.get_host_port(3306).ok_or("Port not found")?;

        let uri = format!("mysql://root:root@localhost:{}/asyncacme", mysql_port);
        let pool = MySqlPool::connect(&uri).await?;

        let (res,): (i64,) = sqlx::query_as("SELECT 1 + 1").fetch_one(&pool).await?;
        assert_eq!(res, 2);

        Ok(())
    }
}
