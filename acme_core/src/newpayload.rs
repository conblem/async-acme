use erased_serde::Serialize as SerializeDyn;
use serde::Serialize;
use std::any::Any;
use std::ops::Deref;

struct SignedRequest<P, D, S: Signature<Protected = P, Payload = D>> {
    protected: P,
    payload: D,
    signature: S,
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

trait Base64AndSerialize {
    fn serialize(&self) -> String;
}

trait Base64AndSerializeDyn {
    fn serialize_dyn(&self) -> String;
    fn as_any(&self) -> &dyn Any;
}

impl<T> Base64AndSerializeDyn for T
where
    T: Base64AndSerialize + 'static,
{
    fn serialize_dyn(&self) -> String {
        self.serialize()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Base64AndSerialize for dyn Base64AndSerializeDyn {
    fn serialize(&self) -> String {
        self.deref().serialize_dyn()
    }
}

impl<T: Base64AndSerialize + ?Sized> Base64AndSerialize for &T {
    fn serialize(&self) -> String {
        self.deref().serialize()
    }
}

trait Signature {
    type Protected: Protected + ?Sized;
    type Payload: Base64AndSerialize + ?Sized;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String;
}

trait SignatureDyn {
    fn sign_dyn(&self, protected: &dyn ProtectedDyn, payload: &dyn Base64AndSerializeDyn)
        -> String;
}

impl<T> SignatureDyn for T
where
    T: Signature,
    T::Protected: Sized + 'static,
    T::Payload: Sized + 'static,
{
    fn sign_dyn(
        &self,
        protected: &dyn ProtectedDyn,
        payload: &dyn Base64AndSerializeDyn,
    ) -> String {
        let protected = protected.as_any().downcast_ref().unwrap();
        let payload = payload.as_any().downcast_ref().unwrap();
        self.sign(protected, payload)
    }
}

impl Signature for dyn SignatureDyn {
    type Protected = dyn ProtectedDyn;
    type Payload = dyn Base64AndSerializeDyn;

    fn sign(&self, protected: &Self::Protected, payload: &Self::Payload) -> String {
        self.deref().sign_dyn(protected, payload)
    }
}

impl<'a, T: Signature + ?Sized> Signature for &'a T {
    type Protected = &'a T::Protected;
    type Payload = &'a T::Payload;

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

    #[derive(Serialize)]
    struct PayloadImpl(String);

    impl Base64AndSerialize for PayloadImpl {
        fn serialize(&self) -> String {
            let json = serde_json::to_vec(self).unwrap();
            base64::encode_config(json, URL_SAFE_NO_PAD)
        }
    }

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
        let payload: &dyn Base64AndSerializeDyn = &payload;

        let signature = SignatureImpl;
        let signature: &dyn SignatureDyn = &signature;

        let req = SignedRequest {
            protected,
            payload,
            signature,
        };

        let res = req.signature.sign(req.protected, req.payload);
        println!("{}", res);
    }
}
