use crate::cust_validation::validate_vec_scopes;
use actix_web::{http::Uri, Either};
use atrium_api::types::string::AtIdentifier;
use atrium_oauth_client::{
    AtprotoClientMetadata, AuthMethod, GrantType, OAuthClientMetadata, Scope,
};
use rauthy_common::constants::{
    PUB_URL_WITH_SCHEME, RE_ALNUM, RE_ALNUM, RE_CLIENT_ID_EPHEMERAL, RE_CLIENT_ID_EPHEMERAL,
    RE_CLIENT_NAME, RE_CODE_CHALLENGE, RE_CODE_CHALLENGE, RE_PEM, RE_SCOPE_SPACE, RE_URI, RE_URI,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct NewClientRequest {
    pub id: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub enabled: bool,
}
