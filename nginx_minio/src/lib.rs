extern crate core;

use awscreds::Credentials;
use s3::{Bucket, Region};
use std::error::Error;
use testcontainers::core::{Container, WaitFor};
use testcontainers::images::generic::GenericImage;
use testcontainers::{clients, RunnableImage};

pub struct Nginx<'a>(Container<'a, GenericImage>);

pub fn nginx(docker: &clients::Cli) -> Nginx<'_> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let from = format!("{}/config/", manifest_dir);
    let to = "/etc/nginx/conf.d/".to_string();

    let wait_for = WaitFor::message_on_stdout("Configuration complete");

    let nginx = GenericImage::new("nginx", "1.21")
        .with_volume(from, to)
        .with_wait_for(wait_for);

    let nginx = RunnableImage::from(nginx)
        .with_container_name("nginx")
        .with_network("nginx_minio");

    Nginx(docker.run(nginx))
}

pub struct Minio<'a>(Container<'a, GenericImage>);

pub fn minio(docker: &clients::Cli) -> Minio<'_> {
    let minio = minio_container(docker);

    create_bucket_container(&docker);

    minio
}

fn minio_container(docker: &clients::Cli) -> Minio<'_> {
    let args = vec!["server".to_string(), "/data".to_string()];

    let wait_for = WaitFor::message_on_stdout("1 Online");

    let minio = GenericImage::new("quay.io/minio/minio", "RELEASE.2022-07-17T15-43-14Z")
        .with_wait_for(wait_for);

    let minio = RunnableImage::from((minio, args))
        .with_container_name("minio")
        .with_network("nginx_minio");

    Minio(docker.run(minio))
}

fn create_bucket_container(docker: &clients::Cli) -> Container<'_, GenericImage> {
    let wait_for = WaitFor::message_on_stdout("finished");

    let create_bucket = GenericImage::new("mc-create-bucket", "latest").with_wait_for(wait_for);

    let create_bucket = RunnableImage::from(create_bucket).with_network("nginx_minio");

    docker.run(create_bucket)
}

pub async fn put_text<P: AsRef<str>, C: AsRef<[u8]>>(
    path: P,
    content: C,
    minio: &Minio<'_>,
) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let minio_port = minio.0.get_host_port_ipv4(9000);
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
        let nginx_port = nginx.0.get_host_port_ipv4(80);

        put_text("token", "Hello World", &minio).await?;

        let well_known_url = format!(
            "http://localhost:{}/.well-known/acme-challenge/token",
            nginx_port
        );
        let token = reqwest::get(well_known_url).await?.text().await?;
        assert_eq!(token, "Hello World");

        Ok(())
    }
}
