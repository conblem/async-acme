use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const fn default_false() -> bool {
    false
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApiDirectory {
    pub(super) new_nonce: String,
    pub(super) new_account: String,
    pub(super) new_order: String,
    pub(super) new_authz: Option<String>,
    pub(super) revoke_cert: String,
    pub(super) key_change: String,
    pub(super) meta: Option<ApiMeta>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApiMeta {
    terms_of_service: Option<String>,
    website: Option<String>,
    #[serde(default)]
    caa_identities: Vec<String>,
    #[serde(default = "default_false")]
    external_account_required: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApiAccount {
    status: ApiAccountStatus,
    #[serde(default)]
    contact: Vec<String>,
    #[serde(default = "default_false")]
    terms_of_service_agreed: bool,
    orders: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", remote = "ApiAccountStatus")]
enum ApiAccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

// todo: absolutely not needed
impl<'de> Deserialize<'de> for ApiAccountStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let status = String::deserialize(deserializer)?;
        match status.as_str() {
            "valid" => Ok(ApiAccountStatus::Valid),
            "deactivated" => Ok(ApiAccountStatus::Deactivated),
            "revoked" => Ok(ApiAccountStatus::Revoked),
            _ => Err(SerdeError::custom("Invalid ApiAccountStatus")),
        }
    }
}

// todo: absolutely not needed
impl Serialize for ApiAccountStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let status = match self {
            ApiAccountStatus::Valid => "valid",
            ApiAccountStatus::Revoked => "revoked",
            ApiAccountStatus::Deactivated => "deactivated",
        };
        serializer.serialize_str(status)
    }
}
