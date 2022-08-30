use crate::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiAuthorization, ApiChallenge, ApiDirectory,
    ApiKeyChange, ApiNewOrder, ApiOrder, ApiOrderFinalization, SignedRequest, Uri,
};
use async_trait::async_trait;
use std::convert::Infallible;

#[async_trait]
impl AcmeServerBuilder for Infallible {
    type Server = Infallible;

    async fn build(&mut self) -> Result<Self::Server, <Self::Server as AcmeServer>::Error> {
        match *self {}
    }
}

#[async_trait]
impl AcmeServer for Infallible {
    type Error = Infallible;
    type Builder = Infallible;

    async fn new_nonce(&self) -> Result<String, Self::Error> {
        match *self {}
    }

    fn directory(&self) -> &ApiDirectory {
        match *self {}
    }

    async fn new_account(
        &self,
        _: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error> {
        match *self {}
    }

    async fn get_account(
        &self,
        _: &Uri,
        _: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, Self::Error> {
        match *self {}
    }

    async fn update_account(
        &self,
        _: &Uri,
        _: SignedRequest<ApiAccount<()>>,
    ) -> Result<ApiAccount<()>, Self::Error> {
        match *self {}
    }

    async fn change_key<K: Send>(
        &self,
        _: SignedRequest<SignedRequest<ApiKeyChange<K>>>,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    async fn new_order(
        &self,
        _: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error> {
        match *self {}
    }

    async fn get_order(&self, _: &Uri, _: SignedRequest<()>) -> Result<ApiOrder<()>, Self::Error> {
        match *self {}
    }

    async fn get_authorization(
        &self,
        _: &Uri,
        _: SignedRequest<()>,
    ) -> Result<ApiAuthorization, Self::Error> {
        match *self {}
    }

    async fn validate_challenge(
        &self,
        _: &Uri,
        _: SignedRequest<()>,
    ) -> Result<ApiChallenge, Self::Error> {
        match *self {}
    }

    async fn finalize(
        &self,
        _: &Uri,
        _: SignedRequest<ApiOrderFinalization>,
    ) -> Result<ApiOrder<()>, Self::Error> {
        match *self {}
    }

    async fn download_certificate(
        &self,
        _: &Uri,
        _: SignedRequest<()>,
    ) -> Result<Vec<u8>, Self::Error> {
        match *self {}
    }
}
