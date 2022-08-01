use crate::{
    AcmeServer, AcmeServerBuilder, ApiAccount, ApiDirectory, ApiNewOrder, ApiOrder, SignedRequest,
    Uri,
};
use async_trait::async_trait;
use std::any::Any;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};

type DynError = Box<dyn Error + Send + Sync + 'static>;

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

pub trait Private: sealed::Sealed + Send + Sync + 'static {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::PrivateImpl {}
}

struct PrivateImpl;
impl Private for PrivateImpl {}

#[async_trait]
pub trait DynAcmeServerBuilder: Send + Sync + 'static {
    #[doc(hidden)]
    async fn build_dyn(&mut self, _: &dyn Private) -> Result<Box<dyn DynAcmeServer>, ErrorWrapper>;
}

#[async_trait]
impl<T: AcmeServerBuilder> DynAcmeServerBuilder for T
where
    T::Server: Clone + Debug,
{
    async fn build_dyn(&mut self, _: &dyn Private) -> Result<Box<dyn DynAcmeServer>, ErrorWrapper> {
        match self.build().await {
            Ok(server) => Ok(Box::new(server)),
            Err(err) => Err(ErrorWrapper(err.into())),
        }
    }
}

#[async_trait]
impl AcmeServerBuilder for Box<dyn DynAcmeServerBuilder> {
    type Server = Box<dyn DynAcmeServer>;

    async fn build(&mut self) -> Result<Self::Server, <Self::Server as AcmeServer>::Error> {
        self.deref_mut().build_dyn(&PrivateImpl).await
    }
}

#[async_trait]
pub trait DynAcmeServer: Send + Sync + 'static {
    #[doc(hidden)]
    async fn new_nonce_dyn(&self, sealed: &dyn Private) -> Result<String, DynError>;

    #[doc(hidden)]
    fn directory_dyn(&self, sealed: &dyn Private) -> &ApiDirectory;

    #[doc(hidden)]
    async fn new_account_dyn(
        &self,
        req: SignedRequest<ApiAccount<()>>,
        _: &dyn Private,
    ) -> Result<(ApiAccount<()>, Uri), DynError>;

    #[doc(hidden)]
    async fn get_account_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Private,
    ) -> Result<ApiAccount<()>, DynError>;

    #[doc(hidden)]
    async fn new_order_dyn(
        &self,
        req: SignedRequest<ApiNewOrder>,
        _: &dyn Private,
    ) -> Result<(ApiOrder<()>, Uri), DynError>;

    #[doc(hidden)]
    async fn get_order_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Private,
    ) -> Result<ApiOrder<()>, DynError>;

    #[doc(hidden)]
    async fn finalize_dyn(&self, _: &dyn Private) -> Result<(), DynError>;

    #[doc(hidden)]
    fn box_clone(&self, _: &dyn Private) -> Box<dyn DynAcmeServer>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn into_any(self: Box<Self>) -> Box<dyn Any>;

    #[doc(hidden)]
    fn debug(&self, _f: &mut Formatter, _: &dyn Private) -> Option<fmt::Result> {
        None
    }
}

#[async_trait]
impl<T: AcmeServer + Clone + Debug + Send + Sync + 'static> DynAcmeServer for T {
    async fn new_nonce_dyn(&self, _: &dyn Private) -> Result<String, DynError> {
        Ok(self.new_nonce().await?)
    }

    fn directory_dyn(&self, _: &dyn Private) -> &ApiDirectory {
        self.directory()
    }

    async fn new_account_dyn(
        &self,
        req: SignedRequest<ApiAccount<()>>,
        _: &dyn Private,
    ) -> Result<(ApiAccount<()>, Uri), DynError> {
        Ok(self.new_account(req).await?)
    }

    async fn get_account_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Private,
    ) -> Result<ApiAccount<()>, DynError> {
        Ok(self.get_account(uri, req).await?)
    }

    async fn new_order_dyn(
        &self,
        req: SignedRequest<ApiNewOrder>,
        _: &dyn Private,
    ) -> Result<(ApiOrder<()>, Uri), DynError> {
        Ok(self.new_order(req).await?)
    }

    async fn get_order_dyn(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
        _: &dyn Private,
    ) -> Result<ApiOrder<()>, DynError> {
        Ok(self.get_order(uri, req).await?)
    }

    async fn finalize_dyn(&self, _: &dyn Private) -> Result<(), DynError> {
        Ok(self.finalize().await?)
    }

    fn box_clone(&self, _: &dyn Private) -> Box<dyn DynAcmeServer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn debug(&self, f: &mut Formatter, _: &dyn Private) -> Option<fmt::Result> {
        Some(self.fmt(f))
    }
}

#[async_trait]
impl AcmeServer for Box<dyn DynAcmeServer> {
    type Error = ErrorWrapper;
    type Builder = Box<dyn DynAcmeServerBuilder>;

    async fn new_nonce(&self) -> Result<String, Self::Error> {
        Ok(self.deref().new_nonce_dyn(&PrivateImpl).await?)
    }

    fn directory(&self) -> &ApiDirectory {
        self.deref().directory_dyn(&PrivateImpl)
    }

    async fn new_account(
        &self,
        req: SignedRequest<ApiAccount<()>>,
    ) -> Result<(ApiAccount<()>, Uri), Self::Error> {
        Ok(self.deref().new_account_dyn(req, &PrivateImpl).await?)
    }

    async fn get_account(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiAccount<()>, Self::Error> {
        Ok(self.deref().get_account_dyn(uri, req, &PrivateImpl).await?)
    }

    async fn new_order(
        &self,
        req: SignedRequest<ApiNewOrder>,
    ) -> Result<(ApiOrder<()>, Uri), Self::Error> {
        Ok(self.deref().new_order_dyn(req, &PrivateImpl).await?)
    }

    async fn get_order(
        &self,
        uri: &Uri,
        req: SignedRequest<()>,
    ) -> Result<ApiOrder<()>, Self::Error> {
        Ok(self.deref().get_order_dyn(uri, req, &PrivateImpl).await?)
    }

    async fn finalize(&self) -> Result<(), Self::Error> {
        Ok(self.deref().finalize_dyn(&PrivateImpl).await?)
    }
}

impl Clone for Box<dyn DynAcmeServer> {
    fn clone(&self) -> Self {
        self.box_clone(&PrivateImpl)
    }
}

impl Debug for dyn DynAcmeServer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.debug(f, &PrivateImpl) {
            Some(res) => res,
            None => f.write_str("DynAcmeServer"),
        }
    }
}
