use super::{DynProtected, KeyType, Kid, NoNonce, NonceType, Request, RequestImpl, Signer};
use serde::{Serialize, Serializer};
use std::any::Any;
use std::marker::PhantomData;
use std::ops::Deref;

pub struct DynRequest<'a, B, K: KeyType = Kid, N: NonceType = NoNonce> {
    pub(crate) inner: RequestImpl<K, N, &'a dyn DynProtected, &'a B, &'a dyn Signer>,
    pub(crate) protected_any: &'a (dyn Any + Send + Sync),
    pub(crate) signer_any: &'a (dyn Any + Send + Sync),
}

impl<B, K: KeyType, N: NonceType> DynRequest<'_, B, K, N> {}

impl<'a, B: Serialize + Send + Sync, K: KeyType, N: NonceType> Request<B, K, N>
    for DynRequest<'a, B, K, N>
{
    fn as_dyn_request(&self) -> DynRequest<'_, B, K, N> {
        let DynRequest {
            inner,
            protected_any,
            signer_any,
        } = self;

        let RequestImpl {
            protected,
            payload,
            signer,
            ..
        } = inner;

        DynRequest {
            inner: RequestImpl {
                phantom: PhantomData,
                protected: protected.deref(),
                payload,
                signer: signer.deref(),
            },
            protected_any: protected_any.deref(),
            signer_any: signer_any.deref(),
        }
    }

    fn protected_as_any(&self) -> &(dyn Any + Send + Sync) {
        self.protected_any
    }

    fn signer_as_any(&self) -> &(dyn Any + Send + Sync) {
        self.signer_any
    }
}

impl<B: Serialize + Send + Sync, K: KeyType, N: NonceType> serde::Serialize
    for DynRequest<'_, B, K, N>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serializer)
    }
}
