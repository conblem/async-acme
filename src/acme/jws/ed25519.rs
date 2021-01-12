use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Serialize, Serializer};
use std::ops::Deref;

use super::base64_url_serialize;
use super::{Algorithm, Crypto};

struct RingCrpyto {
    random: SystemRandom,
}

impl RingCrpyto {
    fn new() -> Self {
        RingCrpyto {
            random: SystemRandom::new(),
        }
    }
}

impl Crypto<'_> for RingCrpyto {
    type Key = ();
    type Error = Unspecified;

    fn generate_key(&self) -> Result<Self::Key, Self::Error> {
        let key_pair = Ed25519KeyPair::generate_pkcs8(&self.random);
        unimplemented!()
    }
}

// ordering matters
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Ed25519<'a> {
    #[serde(rename = "crv")]
    curve: JWKCurve,
    #[serde(rename = "kty")]
    key_type: JWKKeyType,
    #[serde(rename = "x", serialize_with = "public_key_serialize")]
    public_key: &'a Ed25519KeyPair,
}

impl<'a> Ed25519<'a> {
    fn new(public_key: &'a Ed25519KeyPair) -> Self {
        Ed25519 {
            curve: JWKCurve::Ed25519,
            key_type: JWKKeyType::OKP,
            public_key,
        }
    }
}

#[derive(Serialize, Debug)]
enum JWKCurve {
    Ed25519,
}

#[derive(Serialize, Debug)]
enum JWKKeyType {
    OKP,
}

impl Algorithm for Ed25519<'_> {
    fn get_algorithm() -> &'static str {
        "EdDSA"
    }
}

fn public_key_serialize<T, S>(input: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Deref,
    T::Target: KeyPair,
{
    base64_url_serialize(&*input.public_key(), serializer)
}

#[cfg(test)]
mod tests {
    use super::Ed25519;
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    #[test]
    fn serialize_key() {
        let random = SystemRandom::new();
        let key_pair = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();

        let key = Ed25519::new(&key);
        let key = serde_json::to_string(&key).unwrap();
        println!("{}", key);
    }
}
