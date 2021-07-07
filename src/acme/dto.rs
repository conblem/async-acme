use serde::{Deserialize, Serialize};

const fn default_false() -> bool {
    false
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiDirectory {
    pub(crate) new_nonce: String,
    pub(crate) new_account: String,
    pub(crate) new_order: String,
    pub(crate) new_authz: Option<String>,
    pub(crate) revoke_cert: String,
    pub(crate) key_change: String,
    pub(crate) meta: Option<ApiMeta>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiMeta {
    terms_of_service: Option<String>,
    website: Option<String>,
    #[serde(default)]
    caa_identities: Vec<String>,
    #[serde(default = "default_false")]
    external_account_required: bool,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ApiAccountStatus>,
    #[serde(default)]
    contact: Vec<String>,
    #[serde(default = "default_false")]
    terms_of_service_agreed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    orders: Option<String>,
}

impl ApiAccount {
    pub(crate) fn new(contact: Vec<String>, terms_of_service_agreed: bool) -> Self {
        ApiAccount {
            contact,
            terms_of_service_agreed,
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ApiAccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiIndentifier {
    #[serde(rename = "type")]
    pub(crate) type_field: &'static str,
    pub(crate) value: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiOrder {
    identifiers: Vec<ApiIndentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
}

impl ApiOrder {
    pub(crate) fn new(identifiers: Vec<String>) -> Self {
        let identifiers = identifiers
            .into_iter()
            .map(|identifier| ApiIndentifier {
                type_field: "dns",
                value: identifier,
            })
            .collect();

        ApiOrder {
            identifiers,
            ..Default::default()
        }
    }
}
