use crate::Uri;
use base64::URL_SAFE_NO_PAD;
use ref_cast::RefCast;
use serde::de::Error as DeError;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serializer};
use std::any::Any;
use std::marker::PhantomData;
use std::ops::Deref;

pub struct PostAsGet;

impl serde::Serialize for PostAsGet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        "".serialize(serializer)
    }
}

pub enum NoExternalAccountBinding {}

impl serde::Serialize for NoExternalAccountBinding {
    fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {}
    }
}

impl<'de> Deserialize<'de> for NoExternalAccountBinding {
    fn deserialize<D>(_: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(DeError::custom("NoExternalAccountBinding cannot be deserialized and should always be used in conjunction with Option"))
    }
}

trait Serialize: serde::Serialize + Send + Sync {}

impl<T: serde::Serialize + Send + Sync> Serialize for T {}

mod sealed {
    use super::*;

    pub trait Sealed {}

    impl<'a, B, K: KeyType, N: NonceType> Sealed for DynRequest<'a, B, K, N> {}
    impl<'a, K, N, P, D, S: ?Sized> Sealed for RequestImpl<'a, K, N, P, D, S> {}

    impl Sealed for PrivateImpl {}

    impl Sealed for Kid {}
    impl<T> Sealed for Jwk<T> {}

    impl Sealed for Nonce {}
    impl Sealed for NoNonce {}
}

pub trait Private: sealed::Sealed + Send + Sync {}
struct PrivateImpl;
impl Private for PrivateImpl {}

// todo: change location of nonce
pub trait Request<B, K: KeyType = Kid, N: NonceType = NoNonce>:
    serde::Serialize + sealed::Sealed + Send + Sync
{
    // todo: make private
    fn as_dyn_request(&self) -> DynRequest<'_, B, K, N>;
}

// maybe does not need to be public
pub struct RequestImpl<'a, K, N, P, B, S: ?Sized> {
    pub(crate) phantom: PhantomData<(K, N)>,
    pub(crate) protected: P,
    pub(crate) payload: B,
    pub(crate) signer: S,
}

impl<
        'a,
        K: KeyType,
        N: NonceType,
        P: Protected<K, N> + 'static,
        B: serde::Serialize + Send + Sync,
        S: Signer + 'static,
    > RequestImpl<'a, K, N, P, B, S>
{
    pub fn new(protected: P, payload: &'a B, signer: &'a S) -> Self {
        Self {
            phantom: PhantomData,
            protected,
            payload,
            signer,
        }
    }
}

impl<
        'a,
        K: KeyType,
        N: NonceType,
        P: Protected<K, N> + 'static,
        B: Serialize,
        S: Signer + 'static,
    > Request<B, K, N> for RequestImpl<'a, K, N, P, B, S>
{
    fn as_dyn_request(&self) -> DynRequest<'_, B, K, N> {
        let RequestImpl {
            protected,
            payload,
            signer,
            ..
        } = self;

        let protected = DynProtectedImpl::ref_cast(protected);

        DynRequest {
            inner: RequestImpl {
                phantom: PhantomData,
                protected,
                payload,
                signer: signer.deref(),
            },
            protected_any: protected,
            signer_any: signer.deref(),
        }
    }
}

impl<'a, K: KeyType, N: NonceType, P: Protected<K, N>, B: Serialize, S: Signer + ?Sized>
    serde::Serialize for RequestImpl<'a, K, N, P, B, S>
{
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        let mut request_impl = serializer.serialize_struct("Request", 3)?;

        let protected = ProtectedWrapper(&self.protected, PhantomData);
        let protected = base64_and_serialize(&protected);
        request_impl.serialize_field("protected", &protected)?;

        let payload = base64_and_serialize(self.payload);
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

pub struct DynRequest<'a, B, K: KeyType = Kid, N: NonceType = NoNonce> {
    pub(crate) inner: RequestImpl<'a, K, N, &'a dyn DynProtected, B, dyn Signer>,
    pub(crate) protected_any: &'a (dyn Any + Send + Sync),
    pub(crate) signer_any: &'a (dyn Any + Send + Sync),
}

impl<B, K: KeyType, N: NonceType> DynRequest<'_, B, K, N> {
    pub fn protected_as_any(&self) -> &dyn Any {
        self.protected_any
    }

    pub fn signer_as_any(&self) -> &dyn Any {
        self.signer_any
    }
}

impl<'a, B: Serialize, K: KeyType, N: NonceType> Request<B, K, N> for DynRequest<'a, B, K, N> {
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
}

impl<B: Serialize, K: KeyType, N: NonceType> serde::Serialize for DynRequest<'_, B, K, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

pub trait Signer: Send + Sync {
    fn sign(&self, protected: String, payload: String) -> String;
}

impl<T: Signer + ?Sized> Signer for &T {
    fn sign(&self, protected: String, payload: String) -> String {
        self.deref().sign(protected, payload)
    }
}

pub trait Protected<K: KeyType, N: NonceType>: Send + Sync {
    fn alg(&self) -> &str;
    fn key(&self) -> &K;
    fn nonce(&self) -> &N;
    fn url(&self) -> &Uri;
}

trait JwkKey: Send + Sync + 'static {
    fn crv(&self) -> &str;
    fn kty(&self) -> &str;
    fn x(&self) -> &str;
    fn y(&self) -> &str;
}

// todo: remove this
impl JwkKey for () {
    fn crv(&self) -> &str {
        todo!()
    }

    fn kty(&self) -> &str {
        todo!()
    }

    fn x(&self) -> &str {
        todo!()
    }

    fn y(&self) -> &str {
        todo!()
    }
}

pub trait KeyType: sealed::Sealed + serde::Serialize + Send + Sync + 'static {}

pub struct Jwk<T>(T);

impl<T: JwkKey> KeyType for Jwk<T> {}

impl<T: JwkKey> serde::Serialize for Jwk<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut jwk = serializer.serialize_struct("Jwk", 4)?;
        jwk.serialize_field("crv", self.0.crv())?;
        jwk.serialize_field("kty", self.0.kty())?;
        jwk.serialize_field("x", self.0.x())?;
        jwk.serialize_field("y", self.0.y())?;

        jwk.end()
    }
}

pub struct Kid(String);

impl KeyType for Kid {}

impl serde::Serialize for Kid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

pub trait NonceType: sealed::Sealed + Send + Sync + 'static {}

pub struct NoNonce;

impl NonceType for NoNonce {}

pub struct Nonce(pub String);

impl NonceType for Nonce {}

pub trait DynProtected: Send + Sync {
    fn dyn_alg(&self) -> &str;
    fn dyn_key(&self) -> &dyn Any;
    fn dyn_nonce(&self) -> &dyn Any;
    fn dyn_url(&self) -> &Uri;
}

impl<K: KeyType, N: NonceType> Protected<K, N> for &'_ dyn DynProtected {
    fn alg(&self) -> &str {
        self.dyn_alg()
    }

    fn key(&self) -> &K {
        self.dyn_key().downcast_ref::<K>().unwrap()
    }

    fn nonce(&self) -> &N {
        self.dyn_nonce().downcast_ref::<N>().unwrap()
    }

    fn url(&self) -> &Uri {
        self.dyn_url()
    }
}

#[derive(RefCast)]
#[repr(transparent)]
struct DynProtectedImpl<K: KeyType, N: NonceType, T: Protected<K, N>> {
    inner: T,
    phantom: PhantomData<(K, N)>,
}

impl<K: KeyType, N: NonceType, T: Protected<K, N>> DynProtected for DynProtectedImpl<K, N, T> {
    fn dyn_alg(&self) -> &str {
        self.inner.alg()
    }

    fn dyn_key(&self) -> &dyn Any {
        self.inner.key()
    }

    fn dyn_nonce(&self) -> &dyn Any {
        self.inner.nonce()
    }

    fn dyn_url(&self) -> &Uri {
        self.inner.url()
    }
}

struct ProtectedWrapper<'a, K, N, P>(&'a P, PhantomData<(K, N)>);

impl<'a, K: KeyType, N: NonceType, P: Protected<K, N>> serde::Serialize
    for ProtectedWrapper<'a, K, N, P>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nonce = <dyn Any>::downcast_ref::<Nonce>(self.0.nonce());

        let mut protected = match nonce {
            // if we have a nonce an additional field will be present
            Some(_) => serializer.serialize_struct("Request", 4)?,
            None => serializer.serialize_struct("Request", 3)?,
        };

        protected.serialize_field("alg", self.0.alg())?;

        match <dyn Any>::downcast_ref::<Kid>(self.0.key()) {
            // K is Kid
            Some(_) => protected.serialize_field("kid", self.0.key())?,
            None => protected.serialize_field("jwk", self.0.key())?,
        };

        // serialize the additional nonce field
        if let Some(Nonce(nonce)) = nonce {
            protected.serialize_field("nonce", &nonce)?;
        }

        protected.serialize_field("url", self.0.url())?;

        protected.end()
    }
}
