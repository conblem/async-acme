use ::hyper::header::{HeaderValue, ToStrError};
use serde::ser::Error as SerError;
use serde::{Serialize, Serializer};
use thiserror::Error;

#[cfg(feature = "__reqwest")]
mod reqwest;

#[cfg(feature = "__reqwest")]
pub(crate) use self::reqwest::ReqwestRepo as Repo;

#[cfg(not(feature = "__reqwest"))]
mod hyper;

#[cfg(not(feature = "__reqwest"))]
pub(crate) use self::hyper::HyperRepo as Repo;

#[derive(Error, Debug)]
pub(crate) enum RepoError {
    #[error("Api did not return a Nonce")]
    NoNonce,

    #[error("Could not turn Nonce into str")]
    InvalidNonce(#[from] ToStrError),

    #[cfg(feature = "__reqwest")]
    #[error("Reqwest error")]
    Reqwest(#[from] ::reqwest::Error),

    #[cfg(not(feature = "__reqwest"))]
    #[error("Self implemented HTTPS error")]
    HTTPS(#[from] self::hyper::HTTPSError),

    #[cfg(not(feature = "__reqwest"))]
    #[error("Hyper error")]
    Hyper(#[from] ::hyper::Error),

    #[cfg(not(feature = "__reqwest"))]
    #[error("Http error")]
    Http(#[from] ::hyper::http::Error),

    #[cfg(not(feature = "__reqwest"))]
    #[error("Serde error")]
    Serde(#[from] serde_json::Error),
}

pub(crate) struct Nonce(HeaderValue);

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0.to_str() {
            Ok(str) => serializer.serialize_str(str),
            Err(e) => Err(SerError::custom(e)),
        }
    }
}

impl From<HeaderValue> for Nonce {
    fn from(header: HeaderValue) -> Self {
        Nonce(header)
    }
}

const APPLICATION_JOSE_JSON: &str = "application/jose+json";
const REPLAY_NONCE_HEADER: &str = "replay-nonce";
