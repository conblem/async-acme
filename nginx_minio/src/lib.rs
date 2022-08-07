use awscreds::Credentials;
use s3::{Bucket, Region};
use std::error::Error;
use testcontainers::clients::Cli;
use testcontainers::core::{Container, WaitFor};
use testcontainers::images::generic::GenericImage;
use testcontainers::RunnableImage;

pub struct Nginx<'a> {
    _inner: Container<'a, GenericImage>,
    port: u16,
}

impl<'a> Nginx<'a> {
    fn new(docker: &'a Cli, network: &str) -> Self {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let from = format!("{}/config/", manifest_dir);
        let to = "/etc/nginx/conf.d/".to_string();

        let wait_for = WaitFor::message_on_stdout("Configuration complete");

        let nginx = GenericImage::new("nginx", "1.21")
            .with_volume(from, to)
            .with_wait_for(wait_for);

        let nginx = RunnableImage::from(nginx)
            .with_container_name("nginx")
            .with_network(network);
        let inner = docker.run(nginx);
        let port = inner.get_host_port_ipv4(80);

        Self {
            _inner: inner,
            port,
        }
    }

    fn path(&self, path: &str) -> String {
        format!(
            "http://localhost:{}/.well-known/acme-challenge/{}",
            self.port, path
        )
    }
}

struct Minio<'a> {
    _inner: Container<'a, GenericImage>,
    bucket: Bucket,
}

impl<'a> Minio<'a> {
    fn new(docker: &'a Cli, network: &str) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let inner = Self::minio(docker, network);
        Self::create_bucket_container(docker, network);

        let bucket = Self::bucket(&inner)?;

        Ok(Self {
            _inner: inner,
            bucket,
        })
    }

    fn bucket(
        minio: &Container<'_, GenericImage>,
    ) -> Result<Bucket, Box<dyn Error + Send + Sync + 'static>> {
        let endpoint = format!("http://localhost:{}", minio.get_host_port_ipv4(9000));

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

        Ok(Bucket::new_with_path_style("static", region, credentials)?)
    }

    fn minio(docker: &'a Cli, network: &str) -> Container<'a, GenericImage> {
        let args = vec!["server".to_string(), "/data".to_string()];

        let wait_for = WaitFor::message_on_stdout("1 Online");

        let minio = GenericImage::new("quay.io/minio/minio", "RELEASE.2022-07-17T15-43-14Z")
            .with_wait_for(wait_for);

        let minio = RunnableImage::from((minio, args))
            .with_container_name("minio")
            .with_network(network);

        docker.run(minio)
    }

    fn create_bucket_container(docker: &'a Cli, network: &str) -> Container<'a, GenericImage> {
        let wait_for = WaitFor::message_on_stdout("finished");

        let create_bucket = GenericImage::new("mc-create-bucket", "latest").with_wait_for(wait_for);

        let create_bucket = RunnableImage::from(create_bucket).with_network(network);

        docker.run(create_bucket)
    }
}

pub struct WebserverWithApi<'a> {
    minio: Minio<'a>,
    nginx: Nginx<'a>,
}

impl<'a> WebserverWithApi<'a> {
    pub fn new(
        docker: &'a Cli,
        network: &str,
    ) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let minio = Minio::new(docker, network)?;
        let nginx = Nginx::new(docker, network);

        Ok(Self { minio, nginx })
    }

    pub async fn put_text<P: AsRef<str>, C: AsRef<[u8]>>(
        &self,
        path: P,
        content: C,
    ) -> Result<String, Box<dyn Error + Send + Sync + 'static>> {
        self.minio
            .bucket
            .put_object_with_content_type(path.as_ref(), content.as_ref(), "text/plain")
            .await?;

        Ok(self.nginx.path(path.as_ref()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let docker = Cli::default();

        let webserver = WebserverWithApi::new(&docker, "nginx_minio")?;

        let well_known_url = webserver.put_text("token", "Hello World").await?;

        let token = reqwest::get(well_known_url).await?.text().await?;
        assert_eq!(token, "Hello World");

        Ok(())
    }
}
