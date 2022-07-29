use async_trait::async_trait;
use std::any::Any;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Formatter};

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
    ) -> Result<(ApiAccount<()>, Uri), Self::Error>;

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, Self::Error>;

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error>;

    async fn get_order(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiOrder<()>, Self::Error>;

    async fn finalize(&self) -> Result<(), Self::Error>;
}

type DynError = Box<dyn Error + Send + Sync + 'static>;

#[async_trait]
pub trait DynAcmeServer: Send + Sync + Any + Debug {
    async fn new_nonce(&self) -> Result<String, DynError>;

    fn directory(&self) -> &ApiDirectory;

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), DynError>;

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, DynError>;

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), DynError>;

    async fn get_order(&self, uri: &Uri, req: SignedRequest<()>) -> Result<ApiOrder<()>, DynError>;

    async fn finalize(&self) -> Result<(), DynError>;

    fn box_clone(&self) -> Box<dyn DynAcmeServer>;

    fn as_any(&self) -> &dyn Any;

    fn debug(&self, f: &mut Formatter<'_>) -> fmt::Result;
}

#[async_trait]
impl<T: AcmeServer + Clone + Debug + 'static> DynAcmeServer for T {
    async fn new_nonce(&self) -> Result<String, DynError> {
        Ok(self.new_nonce().await?)
    }

    fn directory(&self) -> &ApiDirectory {
        self.directory()
    }

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), DynError> {
        Ok(self.new_account(req).await?)
    }

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, DynError> {
        Ok(self.get_account(uri, req).await?)
    }

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), DynError> {
        Ok(self.new_order(req).await?)
    }

    async fn get_order(&self, uri: &Uri, req: SignedRequest<()>) -> Result<ApiOrder<()>, DynError> {
        Ok(self.get_order(uri, req).await?)
    }

    async fn finalize(&self) -> Result<(), DynError> {
        Ok(self.finalize().await?)
    }

    fn box_clone(&self) -> Box<dyn DynAcmeServer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.fmt(f)
    }
}

impl Clone for Box<dyn DynAcmeServer> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
