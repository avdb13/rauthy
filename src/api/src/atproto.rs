use std::iter;

use actix_web::{
    get,
    http::{
        header::LOCATION,
        uri::{Parts, PathAndQuery},
        Uri,
    },
    post, put, web, HttpRequest, HttpResponse,
};
use actix_web_validator::{Json, Query};
use atrium_oauth_client::{
    AtprotoClientMetadata, AuthMethod, AuthorizeOptions, CallbackParams, GrantType,
    OAuthClientMetadata,
};
use cryptr::utils::secure_random_alnum;
use rauthy_api_types::atproto;
use rauthy_error::ErrorResponse;
use rauthy_models::{
    app_state::AppState,
    entity::{
        api_keys::{AccessGroup, AccessRights},
        auth_providers::{AuthProvider, AuthProviderCallback, AuthProviderType},
        clients::Client,
    },
};

use crate::ReqPrincipal;

/// Returns all existing atproto clients with all their information.
///
/// **Permissions**
/// - rauthy_admin
#[utoipa::path(
    get,
    path = "/atproto/clients",
    tag = "atproto",
    responses(
        (status = 200, description = "Ok", body = OAuthClientMetadata),
    ),
)]
#[tracing::instrument(skip_all)]
#[get("/atproto/clients")]
pub async fn get_clients(principal: ReqPrincipal) -> Result<HttpResponse, ErrorResponse> {
    principal.validate_api_key_or_admin_session(AccessGroup::Clients, AccessRights::Read)?;

    Ok(HttpResponse::Ok().json(Vec::new()))
}

/// Returns a single atproto clients by its *id* with all information's.
///
/// **Permissions**
/// - rauthy_admin
#[utoipa::path(
    get,
    path = "/atproto/clients/{id}",
    tag = "atproto",
    responses(
        (status = 200, description = "Ok", body = OAuthClientMetadata),
    ),
)]
#[get("/atproto/clients/{id}")]
pub async fn get_client_by_id(
    path: web::Path<String>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    principal.validate_api_key_or_admin_session(AccessGroup::Clients, AccessRights::Read)?;

    todo!()
}

/// Adds a new atproto client to the database.
///
/// **Permissions**
/// - rauthy_admin
#[utoipa::path(
    post,
    path = "/atproto/clients",
    tag = "clients",
    request_body = atproto::NewClientRequest,
    responses(
        (status = 200, description = "Ok"),
    ),
)]
#[post("/atproto/clients")]
pub async fn post_clients(
    data: web::Data<AppState>,
    client: actix_web_validator::Json<atproto::NewClientRequest>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    principal.validate_api_key_or_admin_session(AccessGroup::Clients, AccessRights::Create)?;

    let parts = data.public_url.parse().map(Uri::into_parts);

    let client_id = Uri::from_parts(Parts {
        path_and_query: Some(format!("/atproto/clients/{id}").parse().expect("todo")),
        ..parts.expect("invalid public_url in AppState")
    });

    let metadata = OAuthClientMetadata {
        client_id: client_id.map(Uri::to_string).expect("todo"),
        client_uri: None,
        redirect_uris: client.redirect_uris,
        scope: Some(format!("atproto {}", client.scopes.concat())),
        grant_types: Some(
            iter::once("authorization_code".to_owned())
                .chain(client.grant_types)
                .collect(),
        ),
        token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
        token_endpoint_auth_signing_alg: Some("ES256".to_owned()),
        dpop_bound_access_tokens: Some(true),
        jwks_uri: todo!(),
        jwks: todo!(),
    };

    Ok(HttpResponse::Ok())
}
