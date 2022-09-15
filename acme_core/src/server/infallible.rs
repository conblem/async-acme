use super::{AcmeServer, AcmeServerBuilder};
use crate::dto::{
    ApiAccount, ApiAuthorization, ApiChallenge, ApiDirectory, ApiKeyChange, ApiNewOrder, ApiOrder,
    ApiOrderFinalization, PostAsGet, Uri,
};
use crate::request::{Jwk, Request};
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
        _req: impl Request<ApiAccount, Jwk<()>>,
    ) -> Result<(ApiAccount, Uri), Self::Error> {
        match *self {}
    }

    async fn get_account(
        &self,
        _uri: &Uri,
        _req: impl Request<PostAsGet>,
    ) -> Result<ApiAccount, Self::Error> {
        match *self {}
    }

    async fn update_account(
        &self,
        _uri: &Uri,
        _req: impl Request<ApiAccount>,
    ) -> Result<ApiAccount, Self::Error> {
        match *self {}
    }

    async fn change_key<R: Request<ApiKeyChange<()>>>(
        &self,
        _req: impl Request<R>,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    async fn new_order(
        &self,
        _req: impl Request<ApiNewOrder>,
    ) -> Result<(ApiOrder, Uri), Self::Error> {
        match *self {}
    }

    async fn get_order(
        &self,
        _uri: &Uri,
        _req: impl Request<PostAsGet>,
    ) -> Result<ApiOrder, Self::Error> {
        match *self {}
    }

    async fn get_authorization(
        &self,
        _uri: &Uri,
        _req: impl Request<PostAsGet>,
    ) -> Result<ApiAuthorization, Self::Error> {
        match *self {}
    }

    async fn validate_challenge(
        &self,
        _uri: &Uri,
        _req: impl Request<PostAsGet>,
    ) -> Result<ApiChallenge, Self::Error> {
        match *self {}
    }

    async fn finalize(
        &self,
        _uri: &Uri,
        _req: impl Request<ApiOrderFinalization>,
    ) -> Result<ApiOrder, Self::Error> {
        match *self {}
    }

    async fn download_certificate(
        &self,
        _uri: &Uri,
        _req: impl Request<PostAsGet>,
    ) -> Result<Vec<u8>, Self::Error> {
        match *self {}
    }
}
