use std::sync::Arc;

use actix_web::{
    http::header::{HeaderValue, LOCATION},
    post, web, HttpRequest, HttpResponse,
};
use actix_web_validator::{Json, Query};
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig},
};
use atrium_oauth_client::{
    store::{session::MemorySessionStore, state::MemoryStateStore},
    AtprotoClientMetadata, AuthMethod, AuthorizeOptions, CallbackParams, DefaultHttpClient,
    GrantType, KnownScope, OAuthClientConfig, OAuthResolverConfig, Scope,
};
use rauthy_api_types::{
    atproto,
    auth_providers::{ProviderCallbackRequest, ProviderLoginRequest},
};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use rauthy_models::{app_state::AppState, entity::auth_providers::AuthProviderCallback};
use tokio::sync::OnceCell;

use crate::{map_auth_step, ReqPrincipal};
use resolvers::DnsTxtResolver;

type OAuthClient = atrium_oauth_client::OAuthClient<
    MemoryStateStore,
    MemorySessionStore,
    CommonDidResolver<DefaultHttpClient>,
    AtprotoHandleResolver<DnsTxtResolver, DefaultHttpClient>,
>;

#[allow(clippy::type_complexity)]
static CLIENT: OnceCell<OAuthClient> = OnceCell::const_new();

async fn init_oauth_client(public_url: &str) -> Result<OAuthClient, atrium_oauth_client::Error> {
    let http_client = Arc::new(DefaultHttpClient::default());

    OAuthClient::new(OAuthClientConfig {
        client_metadata: AtprotoClientMetadata {
            client_id: public_url.to_owned(),
            client_uri: public_url.to_owned(),
            redirect_uris: vec![format!("{public_url}/auth/v1/atproto/callback")],
            token_endpoint_auth_method: AuthMethod::PrivateKeyJwt,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: [
                KnownScope::Atproto,
                KnownScope::TransitionGeneric,
                KnownScope::TransitionChatBsky,
            ]
            .into_iter()
            .map(Scope::Known)
            .collect(),
            jwks_uri: Some(format!("{public_url}/oidc/certs")),
            token_endpoint_auth_signing_alg: Some(String::from("ES256")),
        },
        keys: None,
        resolver: OAuthResolverConfig {
            did_resolver: CommonDidResolver::new(CommonDidResolverConfig {
                plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
                http_client: http_client.clone(),
            }),
            handle_resolver: AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
                dns_txt_resolver: DnsTxtResolver::default(),
                http_client: http_client.clone(),
            }),
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        },
        state_store: MemoryStateStore::default(),
        session_store: MemorySessionStore::default(),
    })
}

/// Start the login flow for an atproto client
///
/// **Permissions**
/// - `session-init`
/// - `session-auth`
#[utoipa::path(
    post,
    path = "/atproto/login",
    tag = "atproto",
    responses(
        (status = 304, description = "Found"),
    ),
)]
#[post("/atproto/login")]
pub async fn post_login(
    data: web::Data<AppState>,
    payload: Json<atproto::LoginRequest>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    principal.validate_session_auth_or_init()?;

    let payload = payload.into_inner();

    let (cookie, xsrf_token, _location) = AuthProviderCallback::login_start(ProviderLoginRequest {
        email: Some(payload.at_id.clone()),
        client_id: data.public_url.clone(),
        redirect_uri: payload.redirect_uri,
        scopes: payload.scopes,
        state: payload.state,
        nonce: None,
        code_challenge: payload.code_challenge,
        code_challenge_method: payload.code_challenge_method,
        provider_id: String::from("atproto"),
        pkce_challenge: payload.pkce_challenge,
    })
    .await?;

    dbg!(&_location);

    let public_url = data.public_url.clone();
    let client = CLIENT
        .get_or_try_init(|| async move { init_oauth_client(&public_url).await })
        .await
        .unwrap();

    let location = client
        .authorize(&payload.at_id, AuthorizeOptions::default())
        .await
        .unwrap();
    let location = HeaderValue::from_str(&location).expect("Location HeaderValue to be correct");

    dbg!(&location);

    Ok(HttpResponse::Accepted()
        .insert_header((LOCATION, location))
        .cookie(cookie)
        .body(xsrf_token))
}

#[utoipa::path(
    post,
    path = "/atproto/callback",
    tag = "atproto",
    responses(
        (status = 200, description = "OK", body = ()),
    ),
)]
#[post("/atproto/callback")]
pub async fn post_callback(
    data: web::Data<AppState>,
    req: HttpRequest,
    payload: Query<atproto::CallbackRequest>,
    principal: ReqPrincipal,
) -> Result<HttpResponse, ErrorResponse> {
    principal.validate_session_auth_or_init()?;

    // Ok(());

    let payload = payload.into_inner();
    let session = principal.get_session()?;

    AuthProviderCallback::atproto_login_validate(
        &req,
        &ProviderCallbackRequest {
            state: payload.state.clone(),
            code: payload.code.clone(),
            xsrf_token: payload.xsrf_token.clone(),
            pkce_verifier: payload.pkce_verifier.clone(),
        },
        session.clone(),
    )
    .await?;

    let public_url = data.public_url.clone();
    let client = CLIENT
        .get_or_try_init(|| async move { init_oauth_client(&public_url).await })
        .await
        .unwrap();

    let params = CallbackParams {
        code: payload.code.clone(),
        state: Some(payload.state.clone()),
        iss: payload.iss.clone(),
    };
    let (atproto_session, _) = client.callback(params).await.unwrap();

    let token_set = atproto_session.token_set().await.unwrap();

    let ok = ProviderCallbackRequest {
        state: payload.state,
        code: payload.code,
        xsrf_token: payload.xsrf_token,
        pkce_verifier: payload.pkce_verifier,
    };
    let (auth_step, cookie) = AuthProviderCallback::atproto_login_finish(
        &data,
        &req,
        &ok,
        session.clone(),
        token_set.sub.as_str(),
    )
    .await?;

    let mut resp = map_auth_step(auth_step, &req).await?;
    resp.add_cookie(&cookie).map_err(|err| {
        ErrorResponse::new(
            ErrorResponseType::Internal,
            format!("Error adding cookie after map_auth_step: {}", err),
        )
    })?;
    Ok(resp)
}

mod resolvers {
    use std::error::Error;

    use hickory_resolver::{proto::rr::rdata::TXT, TokioAsyncResolver};

    pub struct DnsTxtResolver {
        resolver: TokioAsyncResolver,
    }

    impl Default for DnsTxtResolver {
        fn default() -> Self {
            Self {
                resolver: TokioAsyncResolver::tokio_from_system_conf()
                    .expect("failed to create resolver"),
            }
        }
    }

    impl atrium_identity::handle::DnsTxtResolver for DnsTxtResolver {
        async fn resolve(
            &self,
            query: &str,
        ) -> Result<Vec<String>, Box<dyn Error + Send + Sync + 'static>> {
            let txt_lookup = self.resolver.txt_lookup(query).await?;
            Ok(txt_lookup.iter().map(TXT::to_string).collect())
        }
    }
}
