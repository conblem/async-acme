use std::time::Duration;
use testcontainers::clients::Cli;
use testcontainers::core::WaitFor;
use testcontainers::images::generic::GenericImage;
use testcontainers::{Container, RunnableImage};

pub fn mysql_container<T: Into<String>>(docker: &Cli, name: T) -> Container<'_, GenericImage> {
    let wait_for = WaitFor::message_on_stdout("MySQL init process done. Ready for start up.");
    let mysql = GenericImage::new("mysql", "8.0.29")
        .with_env_var("MYSQL_ROOT_PASSWORD", "root")
        .with_env_var("MYSQL_DATABASE", "asyncacme")
        .with_wait_for(wait_for);

    let mysql = RunnableImage::from(mysql)
        .with_network("asyncacme")
        .with_container_name(name);

    let mysql = docker.run(mysql);

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
        let docker = Cli::default();
        let mysql = mysql_container(&docker, "mysql");
        let mysql_port = mysql.get_host_port_ipv4(3306);

        let uri = format!("mysql://root:root@localhost:{}/asyncacme", mysql_port);
        let pool = MySqlPool::connect(&uri).await?;

        let (res,): (i64,) = sqlx::query_as("SELECT 1 + 1").fetch_one(&pool).await?;
        assert_eq!(res, 2);

        Ok(())
    }
}
