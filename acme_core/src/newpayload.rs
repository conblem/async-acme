use serde::{Serialize, Serializer};
use std::any::Any;
use std::borrow::Borrow;
use std::ops::Deref;

trait SerializeDyn: erased_serde::Serialize {
    fn as_any(&self) -> &dyn Any;
    fn box_clone(&self) -> Box<dyn SerializeDyn>;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl Serialize for dyn SerializeDyn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        erased_serde::serialize(self, serializer)
    }
}

impl ToOwned for dyn SerializeDyn {
    type Owned = Box<dyn SerializeDyn>;

    fn to_owned(&self) -> Self::Owned {
        self.box_clone()
    }
}

impl<T: Serialize + Clone + 'static> SerializeDyn for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn box_clone(&self) -> Box<dyn SerializeDyn> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Clone for Box<dyn SerializeDyn> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

struct RequestImpl<P, D, S> {
    protected: P,
    payload: D,
    signature: S,
}

mod sealed {
    use super::RequestImpl;

    pub(super) trait Private {}
    impl<P, D, S> Private for RequestImpl<P, D, S> {}
}

trait Request: sealed::Private {
    fn as_signed_request(&self) -> String;
}

impl<P, D, S> Request for RequestImpl<P, D, S>
where
    S: Signature,
    P: Borrow<S::Protected>,
    D: Borrow<S::Payload>,
{
    fn as_signed_request(&self) -> String {
        let RequestImpl {
            signature,
            protected,
            payload,
        } = self;

        signature.sign(protected.borrow(), payload.borrow())
    }
}

trait Protected: ToOwned {
    fn alg(&self) -> &str;
}

trait ProtectedDyn {
    fn alg_dyn(&self) -> &str;
    fn as_any(&self) -> &dyn Any;
    fn box_clone(&self) -> Box<dyn ProtectedDyn>;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T> ProtectedDyn for T
where
    T: Protected + Clone + 'static,
{
    fn alg_dyn(&self) -> &str {
        self.alg()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn box_clone(&self) -> Box<dyn ProtectedDyn> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ToOwned for dyn ProtectedDyn {
    type Owned = Box<dyn ProtectedDyn>;

    fn to_owned(&self) -> Self::Owned {
        self.box_clone()
    }
}

impl Clone for Box<dyn ProtectedDyn> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

impl Protected for dyn ProtectedDyn {
    fn alg(&self) -> &str {
        self.alg_dyn()
    }
}

impl<T: Protected + ?Sized> Protected for &T {
    fn alg(&self) -> &str {
        self.deref().alg()
    }
}

trait Signature {
    type Protected: Protected + ?Sized;
    type Payload: Serialize + ?Sized;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String;
}

trait SignatureDyn {
    fn sign_dyn(&self, protected: &dyn ProtectedDyn, payload: &dyn SerializeDyn) -> String;
}

impl<T> SignatureDyn for T
where
    T: Signature,
    T::Protected: Sized + 'static,
    T::Payload: Sized + 'static,
{
    fn sign_dyn(&self, protected: &dyn ProtectedDyn, payload: &dyn SerializeDyn) -> String {
        let protected = protected.as_any().downcast_ref().unwrap();
        let payload = payload.as_any().downcast_ref().unwrap();
        self.sign(protected, payload)
    }
}

impl<'a> Signature for dyn SignatureDyn {
    type Protected = dyn ProtectedDyn;
    type Payload = dyn SerializeDyn;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String {
        self.deref().sign_dyn(&*protected, &*payload)
    }
}

impl<'a, T: Signature + ?Sized> Signature for &'a T {
    type Protected = T::Protected;
    type Payload = T::Payload;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String {
        self.deref().sign(protected, payload)
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
        let protected: &dyn ProtectedDyn = &protected;

        let payload = PayloadImpl("hallo".to_string());
        let payload: &dyn SerializeDyn = &payload;

        let signature = SignatureImpl;
        let signature: &dyn SignatureDyn = &signature;

        let req = RequestImpl {
            protected,
            payload,
            signature,
        };
        run(req);
    }

    fn run(req: impl Request) {
        println!("{}", req.as_signed_request());
    }
}
