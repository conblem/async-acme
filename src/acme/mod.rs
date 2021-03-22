use serde::ser::Error as SerError;
use serde::{Serialize, Serializer};
use std::fmt::Debug;
use std::io;
use std::str;
use thiserror::Error;

use crate::acme::repo::Nonce;
use dto::{ApiAccount, ApiDirectory};
use jws::{Crypto, TestCrypto};
use repo::{Repo, RepoError};

mod dto;
mod jws;
mod persist;
mod repo;

#[derive(Error, Debug)]
pub(super) enum DirectoryError<C: Crypto> {
    #[error("IO Error")]
    IO(#[from] io::Error),

    #[error("Crypto Error")]
    Crypto(C::Error),

    // todo: does this make sense
    #[error("JSON Error")]
    Json(#[from] serde_json::Error),

    #[error("Repo Error")]
    RepoError(#[from] RepoError),
}

#[derive(Debug)]
pub(super) struct Directory<C> {
    directory: ApiDirectory,
    repo: Repo,
    crypto: C,
}

impl Directory<TestCrypto> {
    pub(super) async fn from_url(url: &str) -> Result<Self, DirectoryError<TestCrypto>> {
        let repo = Repo::new();
        let directory = repo.get_directory(url).await?;

        Ok(Directory {
            directory,
            repo,
            crypto: TestCrypto::new(),
        })
    }

    pub(super) const LE_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
}

impl<C: Crypto> Directory<C> {
    pub(super) async fn new_account(&self, tos: bool) -> Result<(), DirectoryError<C>> {
        let dir = &self.directory;
        let nonce = self.repo.get_nonce(&dir.new_nonce).await?;

        let keypair = match self.crypto.generate_key() {
            Err(err) => Err(DirectoryError::Crypto(err))?,
            Ok(keypair) => keypair,
        };

        let protected = Protected {
            alg: self.crypto.algorithm(&keypair),
            nonce,
            url: self.directory.new_account.clone(),
            jwk: &keypair,
        };
        let protected = serde_json::to_string(&protected)?;
        let protected = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);

        let account = ApiAccount::new(vec![], tos);
        let account = serde_json::to_string(&account)?;
        let account = base64::encode_config(account, base64::URL_SAFE_NO_PAD);

        let mut signature_input = String::with_capacity(protected.len() + account.len() + 1);
        signature_input += &protected;
        signature_input += ".";
        signature_input += &account;
        let signature = match self.crypto.sign(&keypair, signature_input) {
            Err(err) => Err(DirectoryError::Crypto(err))?,
            Ok(signature) => signature,
        };

        let body = SignedRequest {
            protected,
            payload: account,
            signature,
        };

        self.repo.crate_account(&dir.new_account, &body).await?;
        Ok(())
    }
}

#[derive(Serialize)]
struct Protected<K: Serialize> {
    alg: &'static str,
    nonce: Nonce,
    url: String,
    jwk: K,
}

#[derive(Serialize)]
pub(crate) struct SignedRequest<S: Serialize> {
    protected: String,
    payload: String,
    signature: S,
}

fn base64url<D: Serialize, S>(data: &D, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let data = match serde_json::to_string(data) {
        Err(err) => Err(SerError::custom(err))?,
        Ok(data) => data,
    };

    let data = base64::encode_config(data, base64::URL_SAFE_NO_PAD);

    serializer.serialize_str(&data)
}
