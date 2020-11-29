use ring::signature::KeyPair;
use serde::{Serialize, Serializer};
use std::ops::Deref;

use super::base64_serialize;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
// ordering matters
struct Ed25519<'a, K: KeyPair> {
    #[serde(rename = "crv")]
    curve: JWKCurve,
    #[serde(rename = "kty")]
    key_type: JWKKeyType,
    #[serde(rename = "x", serialize_with = "public_key_serialize")]
    public_key: &'a K,
}

#[derive(Serialize, Debug)]
enum JWKCurve {
    Ed25519,
}

#[derive(Serialize, Debug)]
enum JWKKeyType {
    OKP,
}

fn public_key_serialize<T, S>(input: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Deref,
    T::Target: KeyPair,
{
    base64_serialize(&*input.public_key(), serializer)
}
