use ref_cast::RefCast;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::any::Any;
use std::marker::PhantomData;

use crate::dto::Uri;

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

// todo: add sealed back
pub trait KeyType: Serialize + Send + Sync + 'static {}

pub struct Jwk<T>(T);

impl<T: JwkKey> KeyType for Jwk<T> {}

impl<T: JwkKey> Serialize for Jwk<T> {
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

pub trait NonceType: Send + Sync + 'static {}

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
pub(super) struct DynProtectedImpl<K: KeyType, N: NonceType, T: Protected<K, N>> {
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

pub(super) struct ProtectedWrapper<'a, K, N, P>(&'a P, PhantomData<(K, N)>);

impl<'a, K: KeyType, N: NonceType, P: Protected<K, N>> ProtectedWrapper<'a, K, N, P> {
    pub(super) fn new(protected: &'a P) -> Self {
        ProtectedWrapper(protected, PhantomData)
    }
}

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

        let key = self.0.key();
        match <dyn Any>::downcast_ref::<Kid>(key) {
            // K is Kid
            Some(kid) => protected.serialize_field("kid", kid)?,
            None => protected.serialize_field("jwk", key)?,
        };

        // serialize the additional nonce field
        if let Some(Nonce(nonce)) = nonce {
            protected.serialize_field("nonce", &nonce)?;
        }

        protected.serialize_field("url", self.0.url())?;

        protected.end()
    }
}
