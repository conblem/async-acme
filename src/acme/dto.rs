use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApiAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ApiAccountStatus>,
    #[serde(default)]
    contact: Vec<String>,
    #[serde(default = "default_false")]
    terms_of_service_agreed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    orders: Option<String>,
}

impl ApiAccount {
    pub(super) fn new(contact: Vec<String>, terms_of_service_agreed: bool) -> Self {
        ApiAccount {
            contact,
            terms_of_service_agreed,
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(super) enum ApiAccountStatus {
    Valid,
    Deactivated,
    Revoked,
}
