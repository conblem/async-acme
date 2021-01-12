use base64::URL_SAFE_NO_PAD;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::convert::AsRef;
use std::error::Error;

mod ed25519;

trait Crypto<'a> {
    type Key: Serialize + Deserialize<'a>;
    type Error: Error;

    fn generate_key(&self) -> Result<Self::Key, Self::Error>;
}

fn base64_url_serialize<T, S>(input: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    let base = base64::encode_config(input, URL_SAFE_NO_PAD);

    serializer.serialize_str(base.as_str())
}

struct JWS {
    payload: String,
    protected: String,
    header: String,
    signature: String,
}

trait Algorithm {
    fn get_algorithm() -> &'static str;
}

struct JwsProtected<K> {
    key: K,
    url: String,
    nonce: String,
}

impl<K: Serialize + Algorithm> JwsProtected<K> {
    fn new(key: K, url: String, nonce: String) -> Self {
        JwsProtected { key, url, nonce }
    }
}

impl<K: Serialize + Algorithm> Serialize for JwsProtected<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = serializer.serialize_struct("JwsProtected", 4)?;

        output.serialize_field("alg", K::get_algorithm())?;
        output.serialize_field("url", &self.url)?;
        output.serialize_field("nonce", &self.nonce)?;
        output.serialize_field("jwk", &self.key)?;

        output.end()
    }
}
