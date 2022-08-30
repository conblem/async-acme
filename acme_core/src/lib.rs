use async_trait::async_trait;
use std::error::Error;

mod dto;
mod dynamic;
mod infallible;
mod newpayload;

pub use dto::*;
pub use dynamic::*;

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

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error>;

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, Self::Error>;

    async fn update_account(
        &self,
        uri: &Uri,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<ApiAccount<()>, Self::Error>;

    async fn change_key<K: Send>(
        &self,
        req: SignedRequest<SignedRequest<ApiKeyChange<K>>>,
    ) -> Result<(), Self::Error>;

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error>;

    async fn get_order(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiOrder<()>, Self::Error>;

    async fn get_authorization(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAuthorization, Self::Error>;

    async fn validate_challenge(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiChallenge, Self::Error>;

    async fn finalize(
        &self,
        uri: &Uri,
        req: SignedRequest<ApiOrderFinalization>,
    ) -> Result<ApiOrder<()>, Self::Error>;

    async fn download_certificate(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<Vec<u8>, Self::Error>;
}
