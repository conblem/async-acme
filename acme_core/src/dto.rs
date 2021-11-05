use http::uri::InvalidUri;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;

const fn default_false() -> bool {
    false
}

#[derive(Serialize)]
pub struct SignedRequest<P> {
    pub protected: String,
    pub payload: Payload<P>,
    pub signature: String,
}

pub enum Payload<P> {
    Post {
        inner: String,
        phantom: PhantomData<P>,
    },
    Get,
}

impl<P> Payload<P> {
    pub fn len(&self) -> usize {
        match self {
            Payload::Post { inner, .. } => inner.len(),
            Payload::Get => 0,
        }
    }
}

impl<P> From<String> for Payload<P> {
    fn from(inner: String) -> Self {
        Self::Post {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<P> Default for Payload<P> {
    fn default() -> Self {
        Payload::Get
    }
}

impl<P> Serialize for Payload<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Payload::Post { inner, .. } => inner.serialize(serializer),
            Payload::Get => "".serialize(serializer),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uri(http::Uri);

impl TryFrom<String> for Uri {
    type Error = InvalidUri;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Uri(value.try_into()?))
    }
}

impl TryFrom<&str> for Uri {
    type Error = InvalidUri;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Uri(value.try_into()?))
    }
}

impl From<&Uri> for http::Uri {
    fn from(input: &Uri) -> Self {
        input.0.clone()
    }
}

impl Serialize for Uri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let uri = format!("{}", &self.0);
        serializer.serialize_str(&uri)
    }
}

struct UriVisitor;

impl<'de> Visitor<'de> for UriVisitor {
    type Value = Uri;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("An URI")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match v.try_into() {
            Ok(uri) => Ok(uri),
            Err(err) => Err(E::custom(err)),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match v.try_into() {
            Ok(uri) => Ok(uri),
            Err(err) => Err(E::custom(err)),
        }
    }
}

impl<'de> Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Uri, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(UriVisitor)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiDirectory {
    pub new_nonce: Uri,
    pub new_account: Uri,
    pub new_order: Uri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_authz: Option<Uri>,
    pub revoke_cert: Uri,
    pub key_change: Uri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ApiMeta>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    #[serde(default)]
    pub caa_identities: Vec<String>,
    #[serde(default = "default_false")]
    pub external_account_required: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ApiAccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

// todo: improve
pub struct Contact(String);

impl<'de> Deserialize<'de> for Contact {
    fn deserialize<D>(deserializer: D) -> Result<Contact, D::Error>
    where
        D: Deserializer<'de>,
    {
        let res = String::deserialize(deserializer)?;
        Ok(Contact(res))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiAccount<E> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ApiAccountStatus>,
    pub contact: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<E>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orders: Option<String>,
}

impl ApiAccount<()> {
    pub fn new(mail: String, tos: bool) -> Self {
        Self {
            contact: vec![mail],
            terms_of_service_agreed: Some(tos),
            ..Default::default()
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ApiOrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiIdentifier {
    #[serde(rename = "type")]
    pub type_field: String,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiNewOrder {
    pub identifiers: Vec<ApiIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiOrder<E> {
    pub status: ApiOrderStatus,
    // todo: make this a real timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    pub identifiers: Vec<ApiIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub error: Option<E>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    #[serde(rename = "type")]
    pub type_val: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use serde_test::{assert_tokens, Token};

    use super::*;

    const URIS: [&'static str; 4] = [
        "https://google.com",
        "http://google.com",
        "https://google.com/test",
        "https://google.com/test?hihi=was",
    ];

    #[test]
    fn uri_try_from_str() {
        for uri in URIS {
            Uri::try_from(uri).unwrap();
        }
    }

    #[test]
    fn uri_try_from_string() {
        for uri in URIS {
            Uri::try_from(uri.to_string()).unwrap();
        }
    }

    #[test]
    fn deserialize_uri() {
        let uri = Uri::try_from("https://google.com/").unwrap();
        assert_tokens(&uri, &[Token::Str("https://google.com/")]);
        assert_tokens(&uri, &[Token::String("https://google.com/")]);
    }

    #[test]
    fn uri_into() {
        let uri = Uri::try_from("https://google.com/").unwrap();
        let http_uri: http::Uri = (&uri).into();

        assert_eq!(uri.0, http_uri);
    }
}
