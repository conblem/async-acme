use crate::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiDirectory, ApiNewOrder, ApiOrder, SignedRequest,
    Uri,
};
use async_trait::async_trait;
use std::any::Any;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;

type DynError = Box<dyn Error + Send + Sync + 'static>;

use private::{Sealed, SealedImpl};
mod private {
    pub trait Sealed: Send + Sync + 'static {}
    pub struct SealedImpl;
    impl Sealed for SealedImpl {}
}

#[async_trait]
pub trait DynAcmeServer: Send + Sync + 'static {
    async fn new_nonce_dyn(&self, sealed: &dyn Sealed) -> Result<String, DynError>;

    fn directory_dyn(&self, sealed: &dyn Sealed) -> &ApiDirectory;

    async fn new_account_dyn(
        &self,
        req: SignedRequest<ApiAccount<()>>,
        _: &dyn Sealed,
    ) -> Result<(ApiAccount<()>, Uri), DynError>;

    async fn get_account_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Sealed,
    ) -> Result<ApiAccount<()>, DynError>;

    async fn new_order_dyn(
        &self,
        req: SignedRequest<ApiNewOrder>,
        _: &dyn Sealed,
    ) -> Result<(ApiOrder<()>, Uri), DynError>;

    async fn get_order_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Sealed,
    ) -> Result<ApiOrder<()>, DynError>;

    async fn finalize_dyn(&self, _: &dyn Sealed) -> Result<(), DynError>;

    fn box_clone(&self, _: &dyn Sealed) -> Box<dyn DynAcmeServer>;

    fn as_any(&self) -> &dyn Any;

    fn debug(&self, _f: &mut Formatter, _: &dyn Sealed) -> Option<fmt::Result> {
        None
    }
}

#[async_trait]
impl<T: AcmeServer + Clone + Debug + Send + Sync + 'static> DynAcmeServer for T {
    async fn new_nonce_dyn(&self, _: &dyn Sealed) -> Result<String, DynError> {
        Ok(self.new_nonce().await?)
    }

    fn directory_dyn(&self, _: &dyn Sealed) -> &ApiDirectory {
        self.directory()
    }

    async fn new_account_dyn(
        &self,
        req: SignedRequest<ApiAccount<()>>,
        _: &dyn Sealed,
    ) -> Result<(ApiAccount<()>, Uri), DynError> {
        Ok(self.new_account(req).await?)
    }

    async fn get_account_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Sealed,
    ) -> Result<ApiAccount<()>, DynError> {
        Ok(self.get_account(uri, req).await?)
    }

    async fn new_order_dyn(
        &self,
        req: SignedRequest<ApiNewOrder>,
        _: &dyn Sealed,
    ) -> Result<(ApiOrder<()>, Uri), DynError> {
        Ok(self.new_order(req).await?)
    }

    async fn get_order_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Sealed,
    ) -> Result<ApiOrder<()>, DynError> {
        Ok(self.get_order(uri, req).await?)
    }

    async fn finalize_dyn(&self, _: &dyn Sealed) -> Result<(), DynError> {
        Ok(self.finalize().await?)
    }

    fn box_clone(&self, _: &dyn Sealed) -> Box<dyn DynAcmeServer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug(&self, f: &mut Formatter, _: &dyn Sealed) -> Option<fmt::Result> {
        Some(self.fmt(f))
    }
}

#[async_trait]
impl AcmeServerBuilder for Infallible {
    type Server = Box<dyn DynAcmeServer>;

    async fn build(&mut self) -> Result<Self::Server, <Self::Server as AcmeServer>::Error> {
        match *self {}
    }
}

#[async_trait]
impl AcmeServer for Box<dyn DynAcmeServer> {
    type Error = ErrorWrapper;
    type Builder = Infallible;

    async fn new_nonce(&self) -> Result<String, Self::Error> {
        Ok(self.deref().new_nonce_dyn(&SealedImpl).await?)
    }

    fn directory(&self) -> &ApiDirectory {
        self.deref().directory_dyn(&SealedImpl)
    }

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error> {
        Ok(self.deref().new_account_dyn(req, &SealedImpl).await?)
    }

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, Self::Error> {
        Ok(self.deref().get_account_dyn(uri, req, &SealedImpl).await?)
    }

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error> {
        Ok(self.deref().new_order_dyn(req, &SealedImpl).await?)
    }

    async fn get_order(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiOrder<()>, Self::Error> {
        Ok(self.deref().get_order_dyn(uri, req, &SealedImpl).await?)
    }

    async fn finalize(&self) -> Result<(), Self::Error> {
        Ok(self.deref().finalize_dyn(&SealedImpl).await?)
    }
}

impl Clone for Box<dyn DynAcmeServer> {
    fn clone(&self) -> Self {
        self.box_clone(&SealedImpl)
    }
}

impl Debug for dyn DynAcmeServer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.debug(f, &SealedImpl) {
            Some(res) => res,
            None => f.write_str("DynAcmeServer"),
        }
    }
}

pub struct ErrorWrapper(pub DynError);

impl Display for ErrorWrapper {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for ErrorWrapper {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for ErrorWrapper {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<DynError> for ErrorWrapper {
    fn from(inner: DynError) -> Self {
        Self(inner)
    }
}
