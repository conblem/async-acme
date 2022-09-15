use base64::URL_SAFE_NO_PAD;
use ref_cast::RefCast;
use serde::ser::SerializeStruct;
use serde::Serializer;
use std::any::Any;
use std::marker::PhantomData;
use std::ops::Deref;

mod dyanmic;
mod protected;

pub use dyanmic::*;
pub use protected::*;

trait Serialize: serde::Serialize + Send + Sync {}

impl<T: serde::Serialize + Send + Sync> Serialize for T {}

// todo: add sealed back
// todo: change location of nonce
pub trait Request<B, K: KeyType = Kid, N: NonceType = NoNonce>:
    serde::Serialize + Send + Sync
{
    // todo: make private
    fn as_dyn_request(&self) -> DynRequest<'_, B, K, N>;

    fn protected_as_any(&self) -> &(dyn Any + Send + Sync);

    fn signer_as_any(&self) -> &(dyn Any + Send + Sync);
}

// maybe does not need to be public
pub struct RequestImpl<K, N, P, B, S> {
    pub(crate) phantom: PhantomData<(K, N)>,
    pub(crate) protected: P,
    pub(crate) payload: B,
    pub(crate) signer: S,
}

impl<
        'a,
        K: KeyType,
        N: NonceType,
        P: Protected<K, N>,
        B: serde::Serialize + Send + Sync,
        S: Signer,
    > RequestImpl<K, N, &'a P, &'a B, &'a S>
{
    pub fn new(protected: &'a P, payload: &'a B, signer: &'a S) -> Self {
        Self {
            phantom: PhantomData,
            protected,
            payload,
            signer,
        }
    }
}

impl<K: KeyType, N: NonceType, P: Protected<K, N> + AsAny, B: Serialize, S: Signer + AsAny>
    Request<B, K, N> for RequestImpl<K, N, P, B, S>
{
    fn as_dyn_request(&self) -> DynRequest<'_, B, K, N> {
        let RequestImpl {
            protected,
            payload,
            signer,
            ..
        } = self;

        let protected_any = protected.as_any();
        let protected = DynProtectedImpl::ref_cast(protected);

        DynRequest {
            inner: RequestImpl {
                phantom: PhantomData,
                protected,
                payload,
                signer,
            },
            protected_any,
            signer_any: signer.as_any(),
        }
    }

    fn protected_as_any(&self) -> &(dyn Any + Send + Sync) {
        self.protected.as_any()
    }

    fn signer_as_any(&self) -> &(dyn Any + Send + Sync) {
        self.signer.as_any()
    }
}

impl<K: KeyType, N: NonceType, P: Protected<K, N>, B: Serialize, S: Signer> serde::Serialize
    for RequestImpl<K, N, P, B, S>
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        let mut request_impl = serializer.serialize_struct("Request", 3)?;

        let protected = ProtectedWrapper::new(&self.protected);
        let protected = base64_and_serialize(&protected);
        request_impl.serialize_field("protected", &protected)?;

        let payload = base64_and_serialize(&self.payload);
        request_impl.serialize_field("payload", &payload)?;

        let signature = self.signer.sign(protected, payload);
        request_impl.serialize_field("signature", &signature)?;

        request_impl.end()
    }
}

fn base64_and_serialize<T: Serialize + ?Sized>(input: &T) -> String {
    // todo: remove unwrap
    let json = serde_json::to_vec(input).unwrap();
    base64::encode_config(json, URL_SAFE_NO_PAD)
}

pub trait Signer: Send + Sync {
    fn sign(&self, protected: String, payload: String) -> String;
}

impl<T: Signer + ?Sized> Signer for &T {
    fn sign(&self, protected: String, payload: String) -> String {
        self.deref().sign(protected, payload)
    }
}

trait AsAny {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
}

impl<T: Send + Sync> AsAny for T
where
    for<'a> &'a T: Any,
{
    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}
