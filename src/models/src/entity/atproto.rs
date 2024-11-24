use crate::app_state::{AppState, DbTxn};
use crate::database::{Cache, DB};
use crate::entity::jwk::JwkKeyPairAlg;
use crate::entity::scopes::Scope;
use crate::entity::users::User;
use crate::ListenScheme;
use actix_web::http::header::{self, HeaderName, HeaderValue};
use actix_web::{web, HttpRequest};
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig},
};
use atrium_oauth_client::{OAuthClient, OAuthClientConfig, OAuthResolverConfig};
use atrium_xrpc::{http::Response, HttpClient};
use chrono::Utc;
use cryptr::{utils, EncKeys, EncValue};
use hiqlite::{params, Param, Params};
use rauthy_api_types::{
    atproto,
    clients::{
        ClientResponse, DynamicClientRequest, DynamicClientResponse, EphemeralClientRequest,
        NewClientRequest,
    },
};
use rauthy_common::constants::{
    ADDITIONAL_ALLOWED_ORIGIN_SCHEMES, ADMIN_FORCE_MFA, APPLICATION_JSON, CACHE_TTL_APP,
    CACHE_TTL_DYN_CLIENT, CACHE_TTL_EPHEMERAL_CLIENT, DYN_CLIENT_DEFAULT_TOKEN_LIFETIME,
    DYN_CLIENT_SECRET_AUTO_ROTATE, ENABLE_EPHEMERAL_CLIENTS, EPHEMERAL_CLIENTS_ALLOWED_FLOWS,
    EPHEMERAL_CLIENTS_ALLOWED_SCOPES, EPHEMERAL_CLIENTS_FORCE_MFA, PROXY_MODE, RAUTHY_VERSION,
};
use rauthy_common::utils::{get_rand, real_ip_from_req};
use rauthy_common::{
    constants::{EMAIL_SUB_PREFIX, PUB_URL, RAUTHY_VERSION},
    is_hiqlite,
};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use reqwest::header::CONTENT_TYPE;
use reqwest::{tls, Url};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use std::{
    error::Error,
    ops::Deref,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tracing::{debug, error, trace, warn};
use utoipa::ToSchema;
use validator::Validate;

use super::clients::HTTP_CLIENT;

/**
# atproto Client

A few values here are saved as CSV Strings instead of having foreign keys and links to other
tables.
All deleting and modifying operations are a bit more expensive this way, but we gain a lot of
performance, when we do reads on clients, which we do most of the time.

`*_lifetime` values are meant to be in seconds.
 */
#[derive(Debug, Clone, PartialEq, Eq, FromRow, Deserialize, Serialize)]
pub struct Client {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    pub redirect_uris: String,
    pub allowed_origins: Option<String>,
    pub flows_enabled: String,
    pub scopes: String,
    pub jwks: Option<String>,
}

// CRUD
impl Client {
    #[inline]
    pub fn cache_idx(id: &str) -> String {
        format!("client_{}", id)
    }

    // have less cloning
    pub async fn create(mut client_req: atproto::NewClientRequest) -> Result<Self, ErrorResponse> {
        let mut client = Client::from(client_req);

        if is_hiqlite() {
            DB::client()
                .execute(
                    r#"
INSERT INTO atproto_clients (id, name, enabled, redirect_uris, allowed_origins, flows_enabled, scopes, jwks)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
                    params!(
                        &client.id,
                        &client.name,
                        client.enabled,
                        &client.redirect_uris,
                        &client.allowed_origins,
                        &client.flows_enabled,
                        &client.scopes,
                        &client.jwks
                    ),
                )
                .await?;
        } else {
            sqlx::query!(
                r#"
    INSERT INTO atproto_clients (id, name, enabled, redirect_uris, allowed_origins, flows_enabled, scopes, jwks)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
                client.id,
                client.name,
                client.enabled,
                client.redirect_uris,
                client.allowed_origins,
                client.flows_enabled,
                client.scopes,
                client.jwks,
            )
            .execute(DB::conn())
            .await?;
        }

        Ok(client)
    }

    // Deletes a client
    pub async fn delete(&self) -> Result<(), ErrorResponse> {
        if is_hiqlite() {
            DB::client()
                .execute(
                    "DELETE FROM atproto_clients WHERE id = $1",
                    params!(&self.id),
                )
                .await?;
        } else {
            sqlx::query!("DELETE FROM atproto_clients WHERE id = $1", self.id,)
                .execute(DB::conn())
                .await?;
        }

        self.delete_cache().await?;

        Ok(())
    }

    pub async fn delete_cache(&self) -> Result<(), ErrorResponse> {
        DB::client()
            .delete(Cache::App, Self::cache_idx(&self.id))
            .await?;

        Ok(())
    }

    pub async fn delete_cache_for(id: &str) -> Result<(), ErrorResponse> {
        DB::client().delete(Cache::App, Self::cache_idx(id)).await?;
        Ok(())
    }

    // Returns a client by id without its secret.
    pub async fn find(id: String) -> Result<Self, ErrorResponse> {
        let client = DB::client();
        if let Some(slf) = client.get(Cache::App, Self::cache_idx(&id)).await? {
            return Ok(slf);
        };

        let slf = if is_hiqlite() {
            client
                .query_as_one("SELECT * FROM atproto_clients WHERE id = $1", params!(id))
                .await?
        } else {
            sqlx::query_as::<_, Self>("SELECT * FROM atproto_clients WHERE id = $1")
                .bind(&id)
                .fetch_one(DB::conn())
                .await?
        };

        client
            .put(Cache::App, Self::cache_idx(&slf.id), &slf, CACHE_TTL_APP)
            .await?;

        Ok(slf)
    }

    pub async fn find_all() -> Result<Vec<Self>, ErrorResponse> {
        let clients = if is_hiqlite() {
            DB::client()
                .query_as("SELECT * FROM atproto_clients", params!())
                .await?
        } else {
            sqlx::query_as("SELECT * FROM atproto_clients")
                .fetch_all(DB::conn())
                .await?
        };

        Ok(clients)
    }

    pub fn save_txn_append(&self, txn: &mut Vec<(&str, Params)>) {
        txn.push((
            r#"
UPDATE atproto_clients
SET name = $1, enabled = $2, redirect_uris = $3, allowed_origins = $4, flows_enabled = $5, scopes = $6, jwks = $7
WHERE id = $8"#,
            params!(
                &self.name,
                self.enabled,
                &self.redirect_uris,
                &self.allowed_origins,
                &self.flows_enabled,
                &self.scopes,
                &self.jwks,
                &self.id
            ),
        ));
    }

    pub async fn save_txn(&self, txn: &mut DbTxn<'_>) -> Result<(), ErrorResponse> {
        sqlx::query!(
            r#"
UPDATE atproto_clients
SET name = $1, enabled = $2, redirect_uris = $3, allowed_origins = $4, flows_enabled = $5, scopes = $6, jwks = $7
WHERE id = $8"#,
            client.name,
            client.enabled,
            client.redirect_uris,
            client.allowed_origins,
            client.flows_enabled,
            client.scopes,
            client.jwks,
            client.id,
        )
        .execute(&mut **txn)
        .await?;

        Ok(())
    }

    pub async fn save_cache(&self) -> Result<(), ErrorResponse> {
        DB::client()
            .put(Cache::App, Client::cache_idx(&self.id), self, CACHE_TTL_APP)
            .await?;
        Ok(())
    }

    pub async fn save(&self) -> Result<(), ErrorResponse> {
        if is_hiqlite() {
            DB::client()
                .execute(
                    r#"
UPDATE atproto_clients
SET name = $1, enabled = $2, redirect_uris = $3, allowed_origins = $4, flows_enabled = $5, scopes = $6, jwks = $7
WHERE id = $8"#,
                    params!(
                        self.name.clone(),
                        self.enabled,
                        self.redirect_uris.clone(),
                        self.allowed_origins.clone(),
                        self.flows_enabled.clone(),
                        self.scopes.clone(),
                        self.jwks.clone(),
                        self.id.clone()
                    ),
                )
                .await?;
        } else {
            sqlx::query!(
                r#"
UPDATE atproto_clients
SET name = $1, enabled = $2, redirect_uris = $3, allowed_origins = $4, flows_enabled = $5, scopes = $6, jwks = $7
WHERE id = $8"#,
                client.name,
                client.enabled,
                client.redirect_uris,
                client.allowed_origins,
                client.flows_enabled,
                client.scopes,
                client.jwks,
                client.id,
            )
            .execute(DB::conn())
            .await?;
        }

        DB::client()
            .put(Cache::App, Client::cache_idx(&self.id), self, CACHE_TTL_APP)
            .await?;

        Ok(())
    }
}

impl Client {
    pub fn allow_refresh_token(&self) -> bool {
        self.flows_enabled.contains("refresh_token")
    }

    // TODO make a generic 'delete_from_csv' function out of this and re-use it in some other places
    pub fn delete_scope(&mut self, scope: &str) {
        // find the scope via index in the string
        // first entry: delete scope + ',' if it exists
        // last entry: delete scope + ',' in front if it exists
        // middle: delete scope + ',' in front if it exists
        // --> 2 cases: first entry or else
        let i_opt = self.scopes.find(scope);
        if i_opt.is_none() {
            return;
        }

        let i = i_opt.unwrap();
        let len = scope.bytes().len();
        if i == 0 {
            // the scope is the first entry
            if self.scopes.len() > len {
                let s = format!("{},", scope);
                self.scopes = self.scopes.replace(&s, "");
            } else {
                self.scopes = String::default();
            }
        } else {
            // the scope is at the end or in the middle
            let s = format!(",{}", scope);
            self.scopes = self.scopes.replace(&s, "");
        }
    }

    pub fn get_allowed_origins(&self) -> Option<Vec<String>> {
        self.allowed_origins.as_ref()?;
        let mut origins = Vec::new();
        self.allowed_origins
            .as_ref()
            .unwrap()
            .split(',')
            .for_each(|o| origins.push(o.trim().to_owned()));
        Some(origins)
    }

    pub fn get_flows(&self) -> Vec<String> {
        let mut res = Vec::new();
        self.flows_enabled
            .split(',')
            .map(|f| f.trim().to_owned())
            .for_each(|f| res.push(f));
        res
    }

    pub fn get_redirect_uris(&self) -> Vec<String> {
        self.redirect_uris
            .split(',')
            .map(|i| i.trim().to_string())
            .collect()
    }

    pub fn get_scopes(&self) -> Vec<String> {
        let mut res = Vec::new();
        self.scopes
            .split(',')
            .for_each(|s| res.push(s.trim().to_owned()));
        res
    }

    pub fn get_scope_as_str(&self) -> String {
        self.scopes.replace(',', " ")
    }

    /// Sanitizes the current scopes and deletes everything, which does not exist in the `scopes`
    /// table in the database
    pub async fn sanitize_scopes(scps: Vec<String>) -> Result<String, ErrorResponse> {
        let mut res = String::with_capacity(scps.len());
        Scope::find_all().await?.into_iter().for_each(|s| {
            if scps.contains(&s.name) {
                res.push_str(s.name.as_str());
                res.push(',');
            }
        });
        // remove the last comma
        if !res.is_empty() {
            res.remove(res.len() - 1);
        }
        // check for 'openid', which should always be there
        if res.is_empty() {
            res = "openid".to_string();
        } else if !res.contains("openid") {
            res = format!("openid,{}", res);
        }
        Ok(res)
    }

    /// Sanitizes the requested scopes on the authorization endpoint and matches them to the
    /// allowed scopes for this client.
    pub fn sanitize_login_scopes(
        &self,
        scopes: &Option<Vec<String>>,
    ) -> Result<Vec<String>, ErrorResponse> {
        if scopes.is_none() {
            return Ok(Vec::new());
        }

        let scopes = scopes.as_ref().unwrap();
        let mut res = Vec::with_capacity(scopes.len());

        for s in scopes {
            if self.scopes.contains(s) {
                res.push(s.clone());
            }
        }

        Ok(res)
    }

    // Validates the `Origin` HTTP Header from an incoming request and compares it to the
    // `allowed_origins`. If the Origin is an external one and allowed by the config, it returns
    // the correct `ACCESS_CONTROL_ALLOW_ORIGIN` header which can then be inserted into the
    // HttpResponse.
    pub fn validate_origin(
        &self,
        r: &HttpRequest,
        listen_scheme: &ListenScheme,
        pub_url: &str,
    ) -> Result<Option<(HeaderName, HeaderValue)>, ErrorResponse> {
        let (is_ext, origin) = super::clients::is_origin_external(r, listen_scheme, pub_url)?;
        if !is_ext {
            return Ok(None);
        }

        let err_msg = || {
            debug!("Client request from invalid origin");
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!(
                    "Coming from an external Origin '{}' which is not allowed",
                    origin
                ),
            ))
        };

        if self.allowed_origins.is_none() {
            debug!("Allowed origins is None");
            return err_msg();
        }

        let allowed_origins = self
            .allowed_origins
            .as_ref()
            .unwrap()
            .split(',')
            .filter(|&ao| {
                // in this case, we should accept http and https, so we just execute .ends_with
                if listen_scheme == &ListenScheme::HttpHttps {
                    ao.ends_with(origin)
                } else {
                    ao.eq(origin)
                }
            })
            .count();
        if allowed_origins == 0 {
            debug!("No match found for allowed origin");
            return err_msg();
        }

        Ok(Some((
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(origin).unwrap(),
        )))
    }

    pub fn validate_redirect_uri(&self, redirect_uri: &str) -> Result<(), ErrorResponse> {
        let matching_uris = self
            .get_redirect_uris()
            .iter()
            .filter(|uri| {
                (uri.ends_with('*') && redirect_uri.starts_with(uri.split_once('*').unwrap().0))
                    || uri.as_str().eq(redirect_uri)
            })
            .count();
        if matching_uris == 0 {
            trace!("Invalid `redirect_uri`");
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "Invalid redirect uri",
            ))
        } else {
            Ok(())
        }
    }

    pub fn validate_flow(&self, flow: &str) -> Result<(), ErrorResponse> {
        if flow.is_empty() || !self.flows_enabled.contains(flow) {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!("'{}' flow is not allowed for this client", flow),
            ));
        }
        Ok(())
    }
}

impl Default for Client {
    fn default() -> Self {
        Self {
            id: String::default(),
            name: None,
            enabled: true,
            redirect_uris: String::default(),
            allowed_origins: None,
            flows_enabled: "authorization_code".to_string(),
            scopes: "atproto".to_string(),
            jwks: None,
        }
    }
}

impl From<Client> for atproto::ClientResponse {
    fn from(client: Client) -> Self {
        todo!()
    }
}

// TODO
impl From<atproto::NewClientRequest> for Client {
    fn from(client: atproto::NewClientRequest) -> Self {
        let redirect_uris = client.redirect_uris.join(",");

        Self {
            id: client.id,
            name: client.name,
            redirect_uris,
            ..Default::default()
        }
    }
}

struct DnsTxtResolver {
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

impl DnsTxtResolver for DnsTxtResolver {
    async fn resolve(
        &self,
        query: &str,
    ) -> core::result::Result<Vec<String>, Box<dyn Error + Send + Sync + 'static>> {
        let txt_lookup = self.resolver.txt_lookup(query).await?;
        Ok(txt_lookup.iter().map(TXT::to_string).collect())
    }
}
