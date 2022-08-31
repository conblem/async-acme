use serde::{Serialize, Serializer};
use std::any::Any;
use std::ops::Deref;

mod sealed {
    use super::*;

    pub trait Sealed {}
    impl<'a, B> Sealed for DynRequest<'a, B> {}
    impl<'a, S: Signature> Sealed for RequestImpl<'a, S> {}
    impl Sealed for PrivateImpl {}
}

pub trait Private: sealed::Sealed {}
struct PrivateImpl;
impl Private for PrivateImpl {}

pub trait Request<B>: sealed::Sealed {
    fn as_signed_request(&self, _: &dyn Private) -> String;
    fn as_dyn_request(&self) -> DynRequest<'_, B>;
}

struct RequestImpl<'a, S: Signature> {
    protected: &'a S::Protected,
    payload: &'a S::Payload,
    signature: &'a S,
}

impl<'a, S: Signature> Request<S::Payload> for RequestImpl<'a, S>
where
    S::Protected: Sized + 'static,
    S::Payload: Sized + 'static,
{
    fn as_signed_request(&self, _: &dyn Private) -> String {
        let RequestImpl {
            protected,
            payload,
            signature,
        } = self;
        signature.sign(protected, payload)
    }

    fn as_dyn_request(&self) -> DynRequest<'_, S::Payload> {
        let RequestImpl {
            protected,
            payload,
            signature,
        } = self;

        DynRequest {
            protected: protected.deref(),
            payload,
            signature: signature.deref(),
        }
    }
}

pub struct DynRequest<'a, B> {
    protected: &'a dyn DynProtected,
    payload: &'a B,
    signature: &'a dyn DynSignature,
}

impl<'a, B: Serialize + 'static> Request<B> for DynRequest<'a, B> {
    fn as_signed_request(&self, _: &dyn Private) -> String {
        let DynRequest {
            protected,
            payload,
            signature,
        } = self;
        signature.sign_dyn(protected.deref(), payload.deref(), &PrivateImpl)
    }

    fn as_dyn_request(&self) -> DynRequest<'_, B>
    where
        B: Sized,
    {
        let DynRequest {
            protected,
            payload,
            signature,
        } = self;

        DynRequest {
            protected: protected.deref(),
            payload,
            signature: signature.deref(),
        }
    }
}

pub trait Protected {
    fn alg(&self) -> &str;
}

impl<T: Protected> Protected for &T {
    fn alg(&self) -> &str {
        self.deref().alg()
    }
}

pub trait DynProtected {
    fn alg_dyn(&self, _: &dyn Private) -> &str;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Protected + 'static> DynProtected for T {
    fn alg_dyn(&self, _: &dyn Private) -> &str {
        self.alg()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Protected for dyn DynProtected {
    fn alg(&self) -> &str {
        self.alg_dyn(&PrivateImpl)
    }
}

pub trait DynSerialize: erased_serde::Serialize {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Serialize + 'static> DynSerialize for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Serialize for dyn DynSerialize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        erased_serde::serialize(self, serializer)
    }
}

pub trait Signature {
    type Protected: Protected + ?Sized;
    type Payload: Serialize + ?Sized;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String;
}

impl<'a, T: Signature> Signature for &'a T {
    type Protected = T::Protected;
    type Payload = T::Payload;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String {
        self.deref().sign(protected, payload)
    }
}

pub trait DynSignature {
    fn sign_dyn(
        &self,
        protected: &dyn DynProtected,
        payload: &dyn DynSerialize,
        _: &dyn Private,
    ) -> String;
}

impl<T: Signature> DynSignature for T
where
    T::Protected: Sized + 'static,
    T::Payload: Sized + 'static,
{
    fn sign_dyn(
        &self,
        protected: &dyn DynProtected,
        payload: &dyn DynSerialize,
        _: &dyn Private,
    ) -> String {
        let protected = protected.as_any().downcast_ref().unwrap();
        let payload = payload.as_any().downcast_ref().unwrap();
        self.sign(protected, payload)
    }
}

impl Signature for dyn DynSignature {
    type Protected = dyn DynProtected;
    type Payload = dyn DynSerialize;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String {
        self.sign_dyn(protected, payload, &PrivateImpl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Clone)]
    struct ProtectedImpl;

    impl Protected for ProtectedImpl {
        fn alg(&self) -> &str {
            "ES256"
        }
    }

    #[derive(Serialize, Clone)]
    struct PayloadImpl(String);

    struct SignatureImpl;

    impl Signature for SignatureImpl {
        type Protected = ProtectedImpl;
        type Payload = PayloadImpl;

        fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String {
            format!("{}.{}", protected.alg(), payload.0)
        }
    }

    #[test]
    fn test() {
        let protected = ProtectedImpl;
        let protected: &dyn DynProtected = &protected;

        let payload = PayloadImpl("hallo".to_string());

        let signature = SignatureImpl;
        let signature: &dyn DynSignature = &signature;

        let req = DynRequest {
            protected,
            payload: &payload,
            signature,
        };
        run(req)
    }

    fn run(req: impl Request<PayloadImpl>) {
        println!("{}", req.as_signed_request(&PrivateImpl));
        let dyn_req = req.as_dyn_request();
        println!("{}", dyn_req.as_signed_request(&PrivateImpl));
    }
}
