use async_trait::async_trait;
use std::error::Error;

mod dto;

pub use dto::*;

#[async_trait]
pub trait AcmeServerBuilder: Send + Sync + 'static {
    type Server: AcmeServer;
    async fn build(&mut self) -> Result<Self::Server, <Self::Server as AcmeServer>::Error>;
}

pub trait AmceServerExt: AcmeServer {
    fn builder() -> Self::Builder;
}

impl<A> AmceServerExt for A
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
    type Builder: AcmeServerBuilder<Server = Self>;

    async fn new_nonce(&self) -> Result<String, Self::Error>;
    fn directory(&self) -> &ApiDirectory;

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<ApiAccount<()>, Self::Error>;

    async fn finalize(&self) -> Result<(), Self::Error>;
}
