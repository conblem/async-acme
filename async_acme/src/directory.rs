use acme_core::{AcmeServerBuilder, AmceServerExt};
use hyper::client::HttpConnector;
use thiserror::Error;

use crate::{HyperAcmeServer, HyperAcmeServerBuilder, HyperAcmeServerError};

type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error(transparent)]
    HyperAcmeServerError(#[from] HyperAcmeServerError),
}

pub struct Directory {
    server: HyperAcmeServer<HttpsConnector>,
}

impl Directory {
    fn base_builder() -> HyperAcmeServerBuilder<HttpsConnector> {
        let connector = HttpsConnector::with_webpki_roots();
        let mut builder = HyperAcmeServer::builder();
        builder.connector(connector);

        builder
    }

    async fn finish(
        mut builder: HyperAcmeServerBuilder<HttpsConnector>,
    ) -> Result<Self, DirectoryError> {
        let server = builder.build().await?;

        Ok(Self { server })
    }

    pub async fn from_le_staging() -> Result<Self, DirectoryError> {
        let mut builder = Self::base_builder();
        builder.le_staging();
        Self::finish(builder).await
    }

    pub async fn from_le() -> Result<Self, DirectoryError> {
        let builder = Self::base_builder();
        Self::finish(builder).await
    }

    pub async fn from_url(url: String) -> Result<Self, DirectoryError> {
        let mut builder = Self::base_builder();
        builder.url(url);
        Self::finish(builder).await
    }

    pub async fn new_account(&self) -> Result<Account, DirectoryError> {
        //let _account = self.server.new_account().await?;
        let server = self.server.clone();

        Ok(Account { server })
    }
}

pub struct Account {
    server: HyperAcmeServer<HttpsConnector>,
}
