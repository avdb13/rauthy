use crate::cust_validation::{
    atproto::{validate_vec_grant_types, validate_vec_scopes},
    validate_vec_jwks, validate_vec_uri,
};
use rauthy_common::constants::{
    RE_ALNUM, RE_CLIENT_ID_EPHEMERAL, RE_CLIENT_NAME, RE_CODE_CHALLENGE, RE_URI,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct NewClientRequest {
    /// Validation: `^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,256}$`
    #[validate(regex(
        path = "*RE_CLIENT_ID_EPHEMERAL",
        code = "^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]{2,256}$"
    ))]
    pub id: String,
    /// Validation: `[a-zA-Z0-9À-ÿ-\\s]{2,128}`
    #[validate(regex(path = "*RE_CLIENT_NAME", code = "[a-zA-Z0-9À-ſ-\\s]{2,128}"))]
    pub name: Option<String>,
    /// Validation: `Vec<^(authorization_code|refresh_token)$>`
    #[validate(custom(function = "validate_vec_grant_types"))]
    pub flows_enabled: Vec<String>,
    /// Validation: `Vec<^(atproto|transition:generic|transition:chat.bsky)$>`
    #[validate(custom(function = "validate_vec_scopes"))]
    pub scopes: Vec<String>,
    /// Validation: `Vec<^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]+$>`
    #[validate(custom(function = "validate_vec_uri"))]
    pub redirect_uris: Vec<String>,
    /// Validation:
    #[validate(custom(function = "validate_vec_jwks"))]
    pub jwks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateClientRequest {
    /// Validation: `^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,256}$`
    #[validate(regex(
        path = "*RE_CLIENT_ID_EPHEMERAL",
        code = "^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]{2,256}$"
    ))]
    pub id: String,
    /// Validation: `[a-zA-Z0-9À-ÿ-\\s]{2,128}`
    #[validate(regex(path = "*RE_CLIENT_NAME", code = "[a-zA-Z0-9À-ſ-\\s]{2,128}"))]
    pub name: Option<String>,
    /// Validation: `Vec<^(authorization_code|refresh_token)$>`
    #[validate(custom(function = "validate_vec_grant_types"))]
    pub flows_enabled: Vec<String>,
    /// Validation: `Vec<^(atproto|transition:generic|transition:chat.bsky)$>`
    #[validate(custom(function = "validate_vec_scopes"))]
    pub scopes: Vec<String>,
    /// Validation: `Vec<^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]+$>`
    #[validate(custom(function = "validate_vec_uri"))]
    pub redirect_uris: Vec<String>,
    /// Validation:
    #[validate(custom(function = "validate_vec_jwks"))]
    pub jwks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClientResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub flows_enabled: Vec<String>,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub jwks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    /// Validation: `^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$`
    /// Validation: `^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`
    pub at_id: String,

    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$"))]
    pub redirect_uri: String,
    /// Validation: `Vec<^(atproto|transition:generic|transition:chat.bsky)$>`
    #[validate(custom(function = "validate_vec_scopes"))]
    pub scopes: Option<Vec<String>>,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$"))]
    pub state: Option<String>,
    /// Validation: `[a-zA-Z0-9-._~]{43,128}`
    #[validate(regex(path = "*RE_CODE_CHALLENGE", code = "[a-zA-Z0-9-._~]{43,128}"))]
    pub code_challenge: Option<String>,
    /// Validation: `[a-zA-Z0-9]`
    #[validate(regex(path = "*RE_ALNUM", code = "[a-zA-Z0-9]"))]
    pub code_challenge_method: Option<String>,

    // values for the callback from upstream
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$"))]
    pub pkce_challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CallbackRequest {
    /// Validation: `[a-zA-Z0-9]`
    #[validate(regex(path = "*RE_ALNUM", code = "[a-zA-Z0-9]"))]
    pub state: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$"))]
    pub code: String,
    /// Validation: `[a-zA-Z0-9]`
    #[validate(regex(path = "*RE_ALNUM", code = "[a-zA-Z0-9]"))]
    pub iss: Option<String>,
    /// Validation: `[a-zA-Z0-9]`
    #[validate(regex(path = "*RE_ALNUM", code = "[a-zA-Z0-9]"))]
    pub xsrf_token: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%]+$"))]
    pub pkce_verifier: String,
}
