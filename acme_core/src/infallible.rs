use crate::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiAuthorization, ApiChallenge, ApiDirectory,
    ApiKeyChange, ApiNewOrder, ApiOrder, ApiOrderFinalization, Request, Uri,
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

    async fn new_account<'a>(
        &self,
        _req: impl Request<ApiAccount<()>> + 'a,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error> {
        match *self {}
    }

    async fn get_account<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<()> + 'a,
    ) -> Result<ApiAccount<()>, Self::Error> {
        match *self {}
    }

    async fn update_account<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<ApiAccount<()>> + 'a,
    ) -> Result<ApiAccount<()>, Self::Error> {
        match *self {}
    }

    async fn change_key<'a, R: Request<ApiKeyChange<()>>>(
        &self,
        _req: impl Request<R> + 'a,
    ) -> Result<(), Self::Error> {
        match *self {}
    }

    async fn new_order<'a>(
        &self,
        _req: impl Request<ApiNewOrder> + 'a,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error> {
        match *self {}
    }

    async fn get_order<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<()> + 'a,
    ) -> Result<ApiOrder<()>, Self::Error> {
        match *self {}
    }

    async fn get_authorization<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<()> + 'a,
    ) -> Result<ApiAuthorization, Self::Error> {
        match *self {}
    }

    async fn validate_challenge<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<()> + 'a,
    ) -> Result<ApiChallenge, Self::Error> {
        match *self {}
    }

    async fn finalize<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<ApiOrderFinalization> + 'a,
    ) -> Result<ApiOrder<()>, Self::Error> {
        match *self {}
    }

    async fn download_certificate<'a>(
        &self,
        _uri: &Uri,
        _req: impl Request<()> + 'a,
    ) -> Result<Vec<u8>, Self::Error> {
        match *self {}
    }
}
