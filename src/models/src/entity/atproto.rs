use std::sync::Arc;

use actix_web::{cookie::Cookie, http::header::HeaderValue, web};
use atrium_common::resolver::Resolver;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig},
};
use atrium_oauth_client::{
    generate_key, jose_jwk::Key, serde_html_form, AtprotoClientMetadata, AuthMethod,
    AuthorizationCodeChallengeMethod, AuthorizationResponseType, DefaultHttpClient, GrantType,
    KnownScope, OAuthClient, OAuthPushedAuthorizationRequestResponse, OAuthRequest, OAuthResolver,
    OAuthResolverConfig, OAuthServerAgent, PushedAuthorizationRequestParameters, Scope,
    TryIntoOAuthClientMetadata,
};
use cryptr::{utils::secure_random_alnum, EncKeys, EncValue};
use jwt_simple::prelude::{RS256KeyPair, RSAKeyPairLike};
use rauthy_api_types::atproto;
use rauthy_common::{
    constants::{COOKIE_UPSTREAM_CALLBACK, UPSTREAM_AUTH_CALLBACK_TIMEOUT_SECS},
    utils::get_rand,
};
use rauthy_error::ErrorResponse;
use resolvers::DnsTxtResolver;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{api_cookie::ApiCookie, app_state::AppState};

use super::jwk::{Jwk, JwkKeyPairAlg};

/// Will be created to start a new upstream login and afterward validate a callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Callback {
    pub callback_id: String,
    pub xsrf_token: String,

    pub dpop_key: Key,
    pub issuer: String,

    pub req_state: Option<String>,
    pub req_code_challenge: Option<String>,
    pub req_code_challenge_method: Option<String>,

    pub pkce_challenge: String,
}

// CRUD
impl Callback {
    pub async fn delete(callback_id: String) -> Result<(), ErrorResponse> {
        todo!()
    }

    pub async fn find(callback_id: String) -> Result<Self, ErrorResponse> {
        todo!()
    }

    async fn save(&self) -> Result<(), ErrorResponse> {
        todo!()
    }
}

impl Callback {
    /// returns (encrypted cookie, xsrf token, location header, optional allowed origins)
    pub async fn login_start<'a>(
        data: &'a web::Data<AppState>,
        payload: atproto::LoginRequest,
    ) -> Result<(Cookie<'a>, String, HeaderValue), ErrorResponse> {
        let redirect_uri = format!("{}/auth/v1/atproto/callback", &data.public_url);

        let client_metadata = AtprotoClientMetadata {
            client_id: data.public_url.clone(),
            client_uri: data.public_url.clone(),
            redirect_uris: vec![redirect_uri],
            token_endpoint_auth_method: AuthMethod::PrivateKeyJwt,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: [KnownScope::Atproto]
                .into_iter()
                .map(Scope::Known)
                .collect(),
            jwks_uri: Some(format!("{public_url}/oidc/certs")),
            token_endpoint_auth_signing_alg: Some(String::from("ES256")),
        };
        let client_metadata = client_metadata.try_into_client_metadata(&None).unwrap();

        let http_client = Arc::new(DefaultHttpClient::default());

        let resolver = Arc::new(OAuthResolver::new(
            OAuthResolverConfig {
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
            http_client.clone(),
        ));

        let (metadata, identity) = resolver.resolve(payload.at_id.as_ref()).await?;

        let dpop_key = generate_key(
            metadata
                .dpop_signing_alg_values_supported
                .as_deref()
                .unwrap(),
        )
        .unwrap();

        let (code_challenge, verifier) = OAuthClient::generate_pkce();
        let state = secure_random_alnum(32);

        let parameters = PushedAuthorizationRequestParameters {
            response_type: AuthorizationResponseType::Code,
            redirect_uri,
            state: state.clone(),
            scope: Some(String::from("atproto")),
            response_mode: None,
            code_challenge: code_challenge.clone(),
            code_challenge_method: AuthorizationCodeChallengeMethod::S256,
            login_hint: None,
            prompt: None,
        };

        let location = if metadata.pushed_authorization_request_endpoint.is_some() {
            let server = OAuthServerAgent::new(
                dpop_key.clone(),
                metadata,
                client_metadata.clone(),
                resolver.clone(),
                http_client.clone(),
                None,
            )?;
            let par_response = server
                .request::<OAuthPushedAuthorizationRequestResponse>(
                    OAuthRequest::PushedAuthorizationRequest(parameters),
                )
                .await?;

            #[derive(Serialize)]
            struct Parameters {
                client_id: String,
                request_uri: String,
            }
            metadata.authorization_endpoint
                + "?"
                + &serde_html_form::to_string(Parameters {
                    client_id: client_metadata.client_id.clone(),
                    request_uri: par_response.request_uri,
                })
                .unwrap()
        } else {
            panic!("server requires PAR but no endpoint is available");
        };

        let slf = Self {
            callback_id: secure_random_alnum(32),
            xsrf_token: secure_random_alnum(32),
            issuer: metadata.issuer.clone(),
            dpop_key,

            req_state: Some(state),
            req_code_challenge: Some(code_challenge),
            req_code_challenge_method: Some(String::from("S256")),

            pkce_challenge: payload.pkce_challenge,
        };
        slf.save().await?;

        let cookie = ApiCookie::build(
            COOKIE_UPSTREAM_CALLBACK,
            &slf.callback_id,
            UPSTREAM_AUTH_CALLBACK_TIMEOUT_SECS as i64,
        );

        Ok((
            cookie,
            slf.xsrf_token,
            HeaderValue::from_str(&location).expect("Location HeaderValue to be correct"),
        ));
    }
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
