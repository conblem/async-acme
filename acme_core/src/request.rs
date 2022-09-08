use crate::Uri;
use base64::URL_SAFE_NO_PAD;
use serde::de::Error as DeError;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serializer};
use std::any::Any;
use std::marker::PhantomData;
use std::ops::Deref;

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
    pub(crate) payload: &'a B,
    pub(crate) signer: &'a S,
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

        let dyn_protected = DynProtected {
            alg: protected.alg(),
            url: protected.url(),
            key: protected.key(),
            nonce: protected.nonce(),
        };

        DynRequest {
            inner: RequestImpl {
                phantom: PhantomData,
                protected: ProtectedCow::Owned(dyn_protected),
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
    pub(crate) inner:
        RequestImpl<'a, K, N, ProtectedCow<'a, DynProtected<'a, K, N>>, B, dyn Signer>,
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

        let protected = match protected {
            ProtectedCow::Borrowed(protected) => protected.deref(),
            ProtectedCow::Owned(protected) => protected,
        };

        DynRequest {
            inner: RequestImpl {
                phantom: PhantomData,
                protected: ProtectedCow::Borrowed(protected),
                payload,
                signer: signer.deref(),
            },
            protected_any: protected_any.deref(),
            signer_any: signer_any.deref(),
        }
    }
}

impl<'a, B: Serialize, K: KeyType, N: NonceType> serde::Serialize for DynRequest<'a, B, K, N> {
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

pub trait KeyType: sealed::Sealed + Send + Sync + 'static {
    type Key: serde::Serialize + Send + Sync;
}

pub struct Kid(&'static dyn Private);
impl KeyType for Kid {
    type Key = Uri;
}

pub struct Jwk<T>(PhantomData<T>, &'static dyn Private);
impl<T: Serialize + 'static> KeyType for Jwk<T> {
    type Key = T;
}

pub trait NonceType: Sized + sealed::Sealed + Send + Sync + 'static {
    type Nonce: serde::Serialize + Send + Sync + 'static;
}

pub struct Nonce(&'static dyn Private);
impl NonceType for Nonce {
    type Nonce = ();
}

pub struct NoNonce(&'static dyn Private);
impl NonceType for NoNonce {
    type Nonce = String;
}

pub trait Protected<K: KeyType, N: NonceType>: Send + Sync {
    fn alg(&self) -> &str;
    fn key(&self) -> &K::Key;
    fn nonce(&self) -> &N::Nonce;
    fn url(&self) -> &Uri;
}

pub(crate) struct DynProtected<'a, K: KeyType, N: NonceType> {
    nonce: &'a N::Nonce,
    key: &'a K::Key,
    alg: &'a str,
    url: &'a Uri,
}

impl<K: KeyType, N: NonceType> Protected<K, N> for DynProtected<'_, K, N> {
    fn alg(&self) -> &str {
        self.alg
    }

    fn key(&self) -> &K::Key {
        self.key
    }

    fn nonce(&self) -> &N::Nonce {
        self.nonce
    }

    fn url(&self) -> &Uri {
        self.url
    }
}

pub(crate) enum ProtectedCow<'a, T> {
    Borrowed(&'a T),
    Owned(T),
}

impl<K: KeyType, N: NonceType, T: Protected<K, N>> Protected<K, N> for ProtectedCow<'_, T> {
    fn alg(&self) -> &str {
        match self {
            ProtectedCow::Borrowed(this) => this.alg(),
            ProtectedCow::Owned(this) => this.alg(),
        }
    }

    fn key(&self) -> &K::Key {
        match self {
            ProtectedCow::Borrowed(this) => this.key(),
            ProtectedCow::Owned(this) => this.key(),
        }
    }

    fn nonce(&self) -> &N::Nonce {
        match self {
            ProtectedCow::Borrowed(this) => this.nonce(),
            ProtectedCow::Owned(this) => this.nonce(),
        }
    }

    fn url(&self) -> &Uri {
        match self {
            ProtectedCow::Borrowed(this) => this.url(),
            ProtectedCow::Owned(this) => this.url(),
        }
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
        let nonce = match <dyn Any>::downcast_ref::<N>(&NoNonce(&PrivateImpl)) {
            // N is NoNonce
            Some(_) => None,
            None => Some(self.0.nonce()),
        };

        let mut protected = match nonce {
            // if we have a nonce an additional field will be present
            Some(_) => serializer.serialize_struct("Request", 4)?,
            None => serializer.serialize_struct("Request", 3)?,
        };

        protected.serialize_field("alg", self.0.alg())?;

        match <dyn Any>::downcast_ref::<K>(&Kid(&PrivateImpl)) {
            // K is Kid
            Some(_) => protected.serialize_field("kid", self.0.key())?,
            None => protected.serialize_field("jwk", self.0.key())?,
        };

        // serialize the additional nonce field
        if let Some(nonce) = nonce {
            protected.serialize_field("nonce", nonce)?;
        }

        protected.serialize_field("url", self.0.url())?;

        protected.end()
    }
}

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

trait JwkKey: Send + Sync {
    fn crg(&self) -> &str;
    fn kty(&self) -> &str;
    fn x(&self) -> &str;
    fn y(&self) -> &str;
}
