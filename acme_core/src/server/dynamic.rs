use super::AcmeServer;
use crate::dto::{
    ApiAccount, ApiAuthorization, ApiChallenge, ApiDirectory, ApiKeyChange, ApiNewOrder, ApiOrder,
    ApiOrderFinalization, PostAsGet, Uri,
};
use crate::request::{DynRequest, Jwk, Request, RequestImpl};
use async_trait::async_trait;
use std::any::Any;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;

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
pub trait DynAcmeServer: Send + Sync + 'static {
    #[doc(hidden)]
    async fn new_nonce_dyn(&self, sealed: &dyn Private) -> Result<String, DynError>;

    #[doc(hidden)]
    fn directory_dyn(&self, sealed: &dyn Private) -> &ApiDirectory;

    #[doc(hidden)]
    async fn new_account_dyn(
        &self,
        req: DynRequest<'_, ApiAccount, Jwk<()>>,
        _: &dyn Private,
    ) -> Result<(ApiAccount, Uri), DynError>;

    #[doc(hidden)]
    async fn get_account_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiAccount, DynError>;

    #[doc(hidden)]
    async fn update_account_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, ApiAccount>,
        _: &dyn Private,
    ) -> Result<ApiAccount, DynError>;

    // use erased serde serialize type here
    async fn change_key_dyn(
        &self,
        req: DynRequest<'_, DynRequest<ApiKeyChange<()>>>,
        _: &dyn Private,
    ) -> Result<(), DynError>;

    #[doc(hidden)]
    async fn new_order_dyn(
        &self,
        req: DynRequest<'_, ApiNewOrder>,
        _: &dyn Private,
    ) -> Result<(ApiOrder, Uri), DynError>;

    #[doc(hidden)]
    async fn get_order_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiOrder, DynError>;

    #[doc(hidden)]
    async fn get_authorization_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiAuthorization, DynError>;

    #[doc(hidden)]
    async fn validate_challenge_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiChallenge, DynError>;

    #[doc(hidden)]
    async fn finalize_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, ApiOrderFinalization>,
        _: &dyn Private,
    ) -> Result<ApiOrder, DynError>;

    #[doc(hidden)]
    async fn download_certificate_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<Vec<u8>, DynError>;

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
        req: DynRequest<'_, ApiAccount, Jwk<()>>,
        _: &dyn Private,
    ) -> Result<(ApiAccount, Uri), DynError> {
        Ok(self.new_account(req).await?)
    }

    async fn get_account_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiAccount, DynError> {
        Ok(self.get_account(uri, req).await?)
    }

    async fn update_account_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, ApiAccount>,
        _: &dyn Private,
    ) -> Result<ApiAccount, DynError> {
        Ok(self.update_account(uri, req).await?)
    }

    // todo: figure this out
    async fn change_key_dyn(
        &self,
        req: DynRequest<'_, DynRequest<ApiKeyChange<()>>>,
        _: &dyn Private,
    ) -> Result<(), DynError> {
        Ok(self.change_key(req).await?)
    }

    async fn new_order_dyn(
        &self,
        req: DynRequest<'_, ApiNewOrder>,
        _: &dyn Private,
    ) -> Result<(ApiOrder, Uri), DynError> {
        Ok(self.new_order(req).await?)
    }

    async fn get_order_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiOrder, DynError> {
        Ok(self.get_order(uri, req).await?)
    }

    async fn get_authorization_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiAuthorization, DynError> {
        Ok(self.get_authorization(uri, req).await?)
    }

    async fn validate_challenge_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<ApiChallenge, DynError> {
        Ok(self.validate_challenge(uri, req).await?)
    }

    async fn finalize_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, ApiOrderFinalization>,
        _: &dyn Private,
    ) -> Result<ApiOrder, DynError> {
        Ok(self.finalize(uri, req).await?)
    }

    async fn download_certificate_dyn(
        &self,
        uri: &Uri,
        req: DynRequest<'_, PostAsGet>,
        _: &dyn Private,
    ) -> Result<Vec<u8>, DynError> {
        Ok(self.download_certificate(uri, req).await?)
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
impl AcmeServer for dyn DynAcmeServer {
    type Error = ErrorWrapper;
    type Builder = Infallible;

    async fn new_nonce(&self) -> Result<String, Self::Error> {
        Ok(self.new_nonce_dyn(&PrivateImpl).await?)
    }

    fn directory(&self) -> &ApiDirectory {
        self.directory_dyn(&PrivateImpl)
    }

    async fn new_account(
        &self,
        req: impl Request<ApiAccount, Jwk<()>>,
    ) -> Result<(ApiAccount, Uri), Self::Error> {
        Ok(self
            .new_account_dyn(req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn get_account(
        &self,
        uri: &Uri,
        req: impl Request<PostAsGet>,
    ) -> Result<ApiAccount, Self::Error> {
        Ok(self
            .get_account_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn update_account(
        &self,
        uri: &Uri,
        req: impl Request<ApiAccount>,
    ) -> Result<ApiAccount, Self::Error> {
        Ok(self
            .update_account_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn change_key<R: Request<ApiKeyChange<()>>>(
        &self,
        req: impl Request<R>,
    ) -> Result<(), Self::Error> {
        let DynRequest {
            inner,
            protected_any,
            signer_any,
        } = req.as_dyn_request();

        let payload = inner.payload.as_dyn_request();

        let req = DynRequest {
            inner: RequestImpl {
                phantom: PhantomData,
                protected: inner.protected,
                payload: &payload,
                signer: inner.signer,
            },
            protected_any,
            signer_any,
        };

        Ok(self.change_key_dyn(req, &PrivateImpl).await?)
    }

    async fn new_order(
        &self,
        req: impl Request<ApiNewOrder>,
    ) -> Result<(ApiOrder, Uri), Self::Error> {
        Ok(self
            .new_order_dyn(req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn get_order(
        &self,
        uri: &Uri,
        req: impl Request<PostAsGet>,
    ) -> Result<ApiOrder, Self::Error> {
        Ok(self
            .get_order_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn get_authorization(
        &self,
        uri: &Uri,
        req: impl Request<PostAsGet>,
    ) -> Result<ApiAuthorization, Self::Error> {
        Ok(self
            .get_authorization_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn validate_challenge(
        &self,
        uri: &Uri,
        req: impl Request<PostAsGet>,
    ) -> Result<ApiChallenge, Self::Error> {
        Ok(self
            .validate_challenge_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn finalize(
        &self,
        uri: &Uri,
        req: impl Request<ApiOrderFinalization>,
    ) -> Result<ApiOrder, Self::Error> {
        Ok(self
            .finalize_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
    }

    async fn download_certificate(
        &self,
        uri: &Uri,
        req: impl Request<PostAsGet>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self
            .download_certificate_dyn(uri, req.as_dyn_request(), &PrivateImpl)
            .await?)
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::ptr;

    use super::*;

    // Type can't be zero sized for ptr equality test to work.
    #[derive(Clone, Debug, Default)]
    pub struct ServerImpl(usize);

    #[async_trait]
    impl AcmeServer for ServerImpl {
        type Error = Infallible;
        type Builder = Infallible;

        async fn new_nonce(&self) -> Result<String, Self::Error> {
            todo!()
        }

        fn directory(&self) -> &ApiDirectory {
            todo!()
        }

        async fn new_account(
            &self,
            _req: impl Request<ApiAccount, Jwk<()>>,
        ) -> Result<(ApiAccount, Uri), Self::Error> {
            todo!()
        }

        async fn get_account(
            &self,
            _uri: &Uri,
            _req: impl Request<PostAsGet>,
        ) -> Result<ApiAccount, Self::Error> {
            todo!()
        }

        async fn update_account(
            &self,
            _uri: &Uri,
            _req: impl Request<ApiAccount>,
        ) -> Result<ApiAccount, Self::Error> {
            todo!()
        }

        async fn change_key<R: Request<ApiKeyChange<()>>>(
            &self,
            _req: impl Request<R>,
        ) -> Result<(), Self::Error> {
            todo!()
        }

        async fn new_order(
            &self,
            _req: impl Request<ApiNewOrder>,
        ) -> Result<(ApiOrder, Uri), Self::Error> {
            todo!()
        }

        async fn get_order(
            &self,
            _uri: &Uri,
            _req: impl Request<PostAsGet>,
        ) -> Result<ApiOrder, Self::Error> {
            todo!()
        }

        async fn get_authorization(
            &self,
            _uri: &Uri,
            _req: impl Request<PostAsGet>,
        ) -> Result<ApiAuthorization, Self::Error> {
            todo!()
        }

        async fn validate_challenge(
            &self,
            _uri: &Uri,
            _req: impl Request<PostAsGet>,
        ) -> Result<ApiChallenge, Self::Error> {
            todo!()
        }

        async fn finalize(
            &self,
            _uri: &Uri,
            _req: impl Request<ApiOrderFinalization>,
        ) -> Result<ApiOrder, Self::Error> {
            todo!()
        }

        async fn download_certificate(
            &self,
            _uri: &Uri,
            _req: impl Request<PostAsGet>,
        ) -> Result<Vec<u8>, Self::Error> {
            todo!()
        }
    }

    #[tokio::test]
    async fn downcast_works() {
        let server: Box<dyn DynAcmeServer> = Box::new(ServerImpl::default());
        let _server: ServerImpl = *server.into_any().downcast::<ServerImpl>().unwrap();
    }

    #[tokio::test]
    async fn debug_works() {
        let server: Box<dyn DynAcmeServer> = Box::new(ServerImpl::default());
        assert_eq!("ServerImpl(0)", format!("{:?}", server));
    }

    #[tokio::test]
    async fn clone_works() {
        let server: Box<dyn DynAcmeServer> = Box::new(ServerImpl::default());
        let server_clone = server.clone();

        let server = server.into_any().downcast::<ServerImpl>().unwrap();
        let server_clone = server_clone.into_any().downcast::<ServerImpl>().unwrap();

        // This would not work with a zero sized type
        // because zero sized types all have the same ptr
        assert!(!ptr::eq(&*server, &*server_clone));
    }
}
