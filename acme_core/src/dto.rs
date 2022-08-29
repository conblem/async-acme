use http::uri::InvalidUri;
use serde::de::{self, Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::marker::PhantomData;
use time::serde::rfc3339::option as rfc3339_option;
use time::OffsetDateTime;

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

impl TryFrom<&String> for Uri {
    type Error = InvalidUri;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
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
        serializer.serialize_str(&self.0.to_string())
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

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
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

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
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
#[serde(rename_all = "lowercase")]
pub enum ApiIdentifierType {
    DNS,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiIdentifier {
    #[serde(rename = "type")]
    pub type_field: ApiIdentifierType,
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
pub struct ApiOrderFinalization {
    pub csr: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiOrder<E> {
    pub status: ApiOrderStatus,
    #[serde(skip_serializing_if = "Option::is_none", with = "rfc3339_option")]
    pub expires: Option<OffsetDateTime>,
    pub identifiers: Vec<ApiIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub error: Option<E>,
    pub authorizations: Vec<Uri>,
    pub finalize: Uri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Uri>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ApiAuthorizationStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiAuthorization {
    pub identifier: ApiIdentifier,
    pub status: ApiAuthorizationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    pub challenges: Vec<ApiChallenge>,
    #[serde(default = "default_false")]
    pub wildcard: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ApiChallengeType {
    DNS,
    TLS,
    HTTP,
}

impl Serialize for ApiChallengeType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::DNS => serializer.serialize_str("dns-01"),
            Self::TLS => serializer.serialize_str("tls-alpn-01"),
            Self::HTTP => serializer.serialize_str("http-01"),
        }
    }
}

impl<'de> Deserialize<'de> for ApiChallengeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        match str.as_str() {
            "dns-01" => Ok(Self::DNS),
            "tls-alpn-01" => Ok(Self::TLS),
            "http-01" => Ok(Self::HTTP),
            _ => Err(DeError::custom("invalid challenge type")),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ApiChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiChallenge {
    #[serde(rename = "type")]
    pub type_field: ApiChallengeType,
    pub url: String,
    pub status: ApiChallengeStatus,
    pub token: String,
    // todo: turn into rfc3339
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    #[serde(rename = "type")]
    pub type_val: ApiErrorType,
    pub detail: String,
    pub subproblems: Vec<ApiSubproblem>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiSubproblem {
    #[serde(rename = "type")]
    pub type_val: ApiErrorType,
    pub detail: String,
    pub identifier: ApiIdentifier,
}

#[derive(Clone, Debug)]
pub enum ApiErrorType {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCSR,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    CAA,
    Compound,
    Connection,
    DNS,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInternal,
    TLS,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
    UserActionRequired,
    Other(String),
}

impl AsRef<str> for ApiErrorType {
    fn as_ref(&self) -> &str {
        match self {
            Self::AccountDoesNotExist => "accountDoesNotExist",
            Self::AlreadyRevoked => "alreadyRevoked",
            Self::BadCSR => "badCSR",
            Self::BadNonce => "badNonce",
            Self::BadPublicKey => "badPublicKey",
            Self::BadRevocationReason => "badRevocationReason",
            Self::BadSignatureAlgorithm => "badSignatureAlgorithm",
            Self::CAA => "caa",
            Self::Compound => "compound",
            Self::Connection => "connection",
            Self::DNS => "dns",
            Self::ExternalAccountRequired => "externalAccountRequired",
            Self::IncorrectResponse => "incorrectResponse",
            Self::InvalidContact => "invalidContact",
            Self::Malformed => "malformed",
            Self::OrderNotReady => "orderNotReady",
            Self::RateLimited => "rateLimited",
            Self::RejectedIdentifier => "rejectedIdentifier",
            Self::ServerInternal => "serverInternal",
            Self::TLS => "tls",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedContact => "unsupportedContact",
            Self::UnsupportedIdentifier => "unsupportedIdentifier",
            Self::UserActionRequired => "userActionRequired",
            Self::Other(inner) => inner.as_str(),
        }
    }
}

impl Serialize for ApiErrorType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for ApiErrorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let this = <&'de str>::deserialize(deserializer)?;

        let this = match this {
            "accountDoesNotExist" => Self::AccountDoesNotExist,
            "alreadyRevoked" => Self::AlreadyRevoked,
            "badCSR" => Self::BadCSR,
            "badNonce" => Self::BadNonce,
            "badPublicKey" => Self::BadPublicKey,
            "badRevocationReason" => Self::BadRevocationReason,
            "badSignatureAlgorithm" => Self::BadSignatureAlgorithm,
            "caa" => Self::CAA,
            "compound" => Self::Compound,
            "connection" => Self::Connection,
            "dns" => Self::DNS,
            "externalAccountRequired" => Self::ExternalAccountRequired,
            "incorrectResponse" => Self::IncorrectResponse,
            "invalidContact" => Self::InvalidContact,
            "malformed" => Self::Malformed,
            "orderNotReady" => Self::OrderNotReady,
            "rateLimited" => Self::RateLimited,
            "rejectedIdentifier" => Self::RejectedIdentifier,
            "serverInternal" => Self::ServerInternal,
            "tls" => Self::TLS,
            "unauthorized" => Self::Unauthorized,
            "unsupportedContact" => Self::UnsupportedContact,
            "unsupportedIdentifier" => Self::UnsupportedIdentifier,
            "userActionRequired" => Self::UserActionRequired,
            this => Self::Other(this.to_string()),
        };

        Ok(this)
    }
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
    fn serde_uri() {
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

    #[test]
    fn serde_api_challenge_type() {
        assert_tokens(&ApiChallengeType::DNS, &[Token::Str("dns-01")]);
        assert_tokens(&ApiChallengeType::TLS, &[Token::Str("tls-alpn-01")]);
        assert_tokens(&ApiChallengeType::HTTP, &[Token::Str("http-01")]);
    }
}
