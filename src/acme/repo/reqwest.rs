use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::Client;
use serde::Serialize;

use super::{Nonce, RepoError, APPLICATION_JOSE_JSON, REPLAY_NONCE_HEADER};
use crate::acme::dto::ApiDirectory;
use crate::acme::SignedRequest;

#[derive(Debug)]
pub(crate) struct ReqwestRepo {
    client: Client,
    application_jose_json: HeaderValue,
    replay_nonce_header: HeaderName,
}

impl ReqwestRepo {
    pub(crate) fn new() -> Self {
        ReqwestRepo {
            client: Client::new(),
            application_jose_json: HeaderValue::from_static(APPLICATION_JOSE_JSON),
            replay_nonce_header: HeaderName::from_static(REPLAY_NONCE_HEADER),
        }
    }

    pub(crate) async fn get_nonce(&self, url: &str) -> Result<Nonce, RepoError> {
        let mut nonce_req = self.client.head(url).send().await?;

        let header = nonce_req
            .headers_mut()
            .remove(&self.replay_nonce_header)
            .ok_or_else(|| RepoError::NoNonce)?;

        Ok(header.into())
    }

    pub(crate) async fn get_directory(&self, url: &str) -> Result<ApiDirectory, RepoError> {
        let directory: ApiDirectory = self.client.get(url).send().await?.json().await?;
        Ok(directory)
    }

    // todo: fix return value
    pub(crate) async fn crate_account<S: Serialize>(
        &self,
        url: &str,
        body: &SignedRequest<S>,
    ) -> Result<(), RepoError> {
        let mut request = self.client.post(url).json(&body).build()?;

        // replace Content-Type header with JOSE header
        request
            .headers_mut()
            .insert(CONTENT_TYPE, self.application_jose_json.clone());

        self.client.execute(request).await?;

        Ok(())
    }
}
