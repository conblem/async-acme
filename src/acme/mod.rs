use reqwest::header::HeaderValue;
use reqwest::Client;
use serde::ser::Error as SerError;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::Debug;
use thiserror::Error;
use tokio::io;

use dto::{ApiDirectory, ApiAccount, ApiAccountStatus};

mod dto;
mod jws;
mod persist;

#[derive(Error, Debug)]
pub(super) enum Error {
    #[error("Error while calling Api")]
    Reqwest(#[from] reqwest::Error),

    #[error("Tokio IO Error")]
    IO(#[from] io::Error),

    #[error("API did not return Nonce")]
    NoNonce,

    #[error("Nonce was not UTF 8 Compatible")]
    NonceFormatting,
}

#[derive(Debug)]
pub(super) struct Directory {
    directory: ApiDirectory,
    client: Client,
}

impl Directory {
    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    const REPLACE_NONCE_HEADER: &'static str = "Replay-Nonce";

    pub(super) async fn from_url(url: &str) -> Result<Directory, Error> {
        let directory: ApiDirectory = reqwest::get(url).await?.json().await?;

        Ok(Directory {
            directory,
            client: Client::new(),
        })
    }

    // todo: make private
    async fn get_nonce(&self) -> Result<String, Error> {
        let header = self
            .client
            .head(&self.directory.new_nonce)
            .send()
            .await?
            .headers_mut()
            .remove(Directory::REPLACE_NONCE_HEADER)
            .ok_or_else(|| Error::NoNonce)?;

        header
            .to_str()
            .map_err(|_| Error::NonceFormatting)
            .map(str::to_owned)
    }

    async fn new_account(&self, tos: bool) {
        let account = ApiAccount::new(vec![]);
        self.client.post(&self.directory.new_account);
    }
}
