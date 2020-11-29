use thiserror::Error;
use tokio::io;

use bytes::Bytes;
use dto::ApiDirectory;
use reqwest::header::{HeaderValue, ToStrError};
use reqwest::Client;
use serde::ser::Error as SerError;
use serde::{Serialize, Serializer};
use std::fmt::Debug;

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
}

#[derive(Debug)]
pub(super) struct Directory {
    directory: ApiDirectory,
}

impl Directory {
    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";

    const REPLACE_NONCE_HEADER: &'static str = "Replay-Nonce";

    pub(super) async fn from_url(url: &str) -> Result<Directory, Error> {
        let directory: ApiDirectory = reqwest::get(url).await?.json().await?;

        Ok(Directory { directory })
    }

    // todo: make private
    async fn get_nonce(&self) -> Result<impl Serialize, Error> {
        let header = Client::new()
            .head(&self.directory.new_nonce)
            .send()
            .await?
            .headers_mut()
            .remove(Directory::REPLACE_NONCE_HEADER)
            .ok_or_else(|| Error::NoNonce)?;

        Ok(HeaderValueHelper(header))
    }
}

struct HeaderValueHelper(HeaderValue);

impl Serialize for HeaderValueHelper {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        match self.0.to_str() {
            Ok(output) => serializer.serialize_str(output),
            Err(e) => Err(SerError::custom(e)),
        }
    }
}
