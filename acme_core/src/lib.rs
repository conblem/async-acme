use async_trait::async_trait;
use std::error::Error;

mod dto;
mod dynamic;
mod infallible;
mod request;

pub use dto::*;
pub use dynamic::*;
pub use request::*;

#[async_trait]
pub trait AcmeServerBuilder: Send + Sync + 'static {
    type Server: AcmeServer;
    async fn build(&mut self) -> Result<Self::Server, <Self::Server as AcmeServer>::Error>;
}

pub trait AcmeServerExt: AcmeServer {
    fn builder() -> Self::Builder;
}

impl<A> AcmeServerExt for A
where
    A: AcmeServer,
    A::Builder: Default,
{
    fn builder() -> Self::Builder {
        A::Builder::default()
    }
}

#[async_trait]
pub trait AcmeServer: Send + Sync {
    type Error: Error + Send + Sync + 'static;
    type Builder: AcmeServerBuilder;

    async fn new_nonce(&self) -> Result<String, Self::Error>;

    fn directory(&self) -> &ApiDirectory;

    async fn new_account<'a>(
        &self,
        req: impl Request<ApiAccount<()>> + 'a,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error>;

    async fn get_account<'a>(
        &self,
        uri: &Uri,
        req: impl Request<()> + 'a,
    ) -> Result<ApiAccount<()>, Self::Error>;

    async fn update_account<'a>(
        &self,
        uri: &Uri,
        req: impl Request<ApiAccount<()>> + 'a,
    ) -> Result<ApiAccount<()>, Self::Error>;

    async fn change_key<'a, R: Request<ApiKeyChange<()>>>(
        &self,
        req: impl Request<R> + 'a,
    ) -> Result<(), Self::Error>;

    async fn new_order<'a>(
        &self,
        req: impl Request<ApiNewOrder> + 'a,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error>;

    async fn get_order<'a>(
        &self,
        uri: &Uri,
        req: impl Request<()> + 'a,
    ) -> Result<ApiOrder<()>, Self::Error>;

    async fn get_authorization<'a>(
        &self,
        uri: &Uri,
        req: impl Request<()> + 'a,
    ) -> Result<ApiAuthorization, Self::Error>;

    async fn validate_challenge<'a>(
        &self,
        uri: &Uri,
        req: impl Request<()> + 'a,
    ) -> Result<ApiChallenge, Self::Error>;

    async fn finalize<'a>(
        &self,
        uri: &Uri,
        req: impl Request<ApiOrderFinalization> + 'a,
    ) -> Result<ApiOrder<()>, Self::Error>;

    async fn download_certificate<'a>(
        &self,
        uri: &Uri,
        req: impl Request<()> + 'a,
    ) -> Result<Vec<u8>, Self::Error>;
}
