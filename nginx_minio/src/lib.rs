use awscreds::Credentials;
use s3::{Bucket, Region};
use std::error::Error;
use testcontainers::images::generic::{GenericImage, WaitFor};
use testcontainers::{clients, Container, Docker, Image, RunArgs};

pub fn nginx(docker: &clients::Cli) -> Container<'_, clients::Cli, GenericImage> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let from = format!("{}/config/", manifest_dir);
    let to = "/etc/nginx/conf.d/".to_string();

    let wait_for = WaitFor::message_on_stdout("Configuration complete");

    let nginx = GenericImage::new("nginx:1.21")
        .with_volume(from, to)
        .with_wait_for(wait_for);

    let run_args = RunArgs::default()
        .with_name("nginx")
        .with_network("nginx_minio");

    docker.run_with_args(nginx, run_args)
}

pub fn minio(docker: &clients::Cli) -> Container<'_, clients::Cli, GenericImage> {
    let minio = minio_container(docker);

    create_bucket_container(&docker);

    minio
}

fn minio_container(docker: &clients::Cli) -> Container<'_, clients::Cli, GenericImage> {
    let args = vec!["server".to_string(), "/data".to_string()];

    let wait_for = WaitFor::message_on_stdout("Detected default credentials");

    let minio = GenericImage::new("minio/minio:RELEASE.2021-11-03T03-36-36Z")
        .with_args(args)
        .with_wait_for(wait_for);

    let run_args = RunArgs::default()
        .with_name("minio")
        .with_network("nginx_minio");

    docker.run_with_args(minio, run_args)
}

fn create_bucket_container(docker: &clients::Cli) -> Container<'_, clients::Cli, GenericImage> {
    let wait_for = WaitFor::message_on_stdout("finished");

    let create_bucket = GenericImage::new("mc-create-bucket:latest").with_wait_for(wait_for);

    let run_args = RunArgs::default().with_network("nginx_minio");

    docker.run_with_args(create_bucket, run_args)
}

pub async fn put_text<P: AsRef<str>, C: AsRef<[u8]>>(
    path: P,
    content: C,
    minio: &Container<'_, clients::Cli, GenericImage>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let minio_port = minio.get_host_port(9000).ok_or("Minio has no port")?;
    let endpoint = format!("http://localhost:{}", minio_port);

    let region = Region::Custom {
        region: "".to_string(),
        endpoint,
    };

    let credentials = Credentials {
        access_key: Some("minioadmin".to_string()),
        secret_key: Some("minioadmin".to_string()),
        security_token: None,
        session_token: None,
    };

    let bucket = Bucket::new_with_path_style("static", region, credentials)?;

    bucket
        .put_object_with_content_type(path.as_ref(), content.as_ref(), "text/plain")
        .await?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = clients::Cli::default();

        let minio = minio(&docker);

        let nginx = nginx(&docker);
        let nginx_port = nginx.get_host_port(80).ok_or("Is empty")?;

        put_text("token", "Hello World", &minio).await?;

        let well_known = format!(
            "http://localhost:{}/.well-known/acme-challenge/token",
            nginx_port
        );
        let token = reqwest::get(well_known).await?.text().await?;
        assert_eq!(token, "Hello World");

        Ok(())
    }
}
