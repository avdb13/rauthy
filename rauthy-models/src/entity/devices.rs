use crate::app_state::AppState;
use actix_web::web;
use chrono::Utc;
use rauthy_common::constants::{
    CACHE_NAME_DEVICE_CODES, DEVICE_GRANT_USER_CODE_LENGTH, DEVICE_KEY_LENGTH, PUB_URL_WITH_SCHEME,
};
use rauthy_common::error_response::ErrorResponse;
use rauthy_common::utils::get_rand;
use redhac::{cache_del, cache_get, cache_get_from, cache_get_value, cache_put};
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as, FromRow};
use std::ops::Sub;
use tracing::info;

#[derive(Debug, FromRow)]
pub struct DeviceEntity {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub created: i64,
    pub access_exp: i64,
    pub refresh_exp: Option<i64>,
    pub peer_ip: String,
}

impl DeviceEntity {
    pub async fn insert(&self, data: &web::Data<AppState>) -> Result<(), ErrorResponse> {
        query!(
            r#"INSERT INTO devices
            (id, client_id, user_id, created, access_exp, refresh_exp, peer_ip)
            VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            self.id,
            self.client_id,
            self.user_id,
            self.created,
            self.access_exp,
            self.refresh_exp,
            self.peer_ip,
        )
        .execute(&data.db)
        .await?;
        Ok(())
    }

    pub async fn find(data: &web::Data<AppState>, id: &str) -> Result<Self, ErrorResponse> {
        let slf = query_as!(Self, "SELECT * FROM devices WHERE id = $1", id)
            .fetch_one(&data.db)
            .await?;
        Ok(slf)
    }

    /// Deletes all devices where access and refresh token expirations are in the past
    pub async fn delete_expired(data: &web::Data<AppState>) -> Result<(), ErrorResponse> {
        let exp = Utc::now()
            .sub(chrono::Duration::try_hours(1).unwrap())
            .timestamp();

        let res = query!(
            r#"DELETE FROM devices
            WHERE access_exp < $1 AND (refresh_exp < $1 OR refresh_exp is null)"#,
            exp
        )
        .execute(&data.db)
        .await?;
        info!("Cleaned up {} expires devices", res.rows_affected());

        Ok(())
    }

    pub async fn invalidate(data: &web::Data<AppState>, id: &str) -> Result<(), ErrorResponse> {
        query!("DELETE FROM devices WHERE id = $1", id)
            .execute(&data.db)
            .await?;
        // we don't need to manually clean up refresh_tokens because of FK cascades
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthCode {
    pub device_code: String,
    pub is_verified: bool,
}

impl DeviceAuthCode {
    /// DeviceAuthCode's live inside the cache only
    pub async fn new(data: &web::Data<AppState>) -> Result<Self, ErrorResponse> {
        let slf = Self {
            device_code: get_rand(DEVICE_KEY_LENGTH as usize),
            is_verified: false,
        };

        cache_put(
            CACHE_NAME_DEVICE_CODES.to_string(),
            slf.user_code().to_string(),
            &data.caches.ha_cache_config,
            &slf,
        )
        .await?;

        Ok(slf)
    }

    /// Needed for the device polling after the initial request
    pub async fn find_by_device_code(
        data: &web::Data<AppState>,
        device_code: String,
    ) -> Result<Option<Self>, ErrorResponse> {
        let key = &device_code.as_str()[..(*DEVICE_GRANT_USER_CODE_LENGTH as usize)];
        Self::find(data, key.to_string()).await
    }

    /// Needed for lookup during the user confirmation
    pub async fn find(
        data: &web::Data<AppState>,
        user_code: String,
    ) -> Result<Option<Self>, ErrorResponse> {
        let slf = cache_get!(
            Self,
            CACHE_NAME_DEVICE_CODES.to_string(),
            user_code,
            &data.caches.ha_cache_config,
            true
        )
        .await?;
        Ok(slf)
    }

    pub async fn delete(
        &self,
        data: &web::Data<AppState>,
        user_code: String,
    ) -> Result<(), ErrorResponse> {
        cache_del(
            CACHE_NAME_DEVICE_CODES.to_string(),
            user_code,
            &data.caches.ha_cache_config,
        )
        .await?;
        Ok(())
    }
}

impl DeviceAuthCode {
    /// Validates the given `user_code`
    pub fn user_code(&self) -> &str {
        &self.device_code[..(*DEVICE_GRANT_USER_CODE_LENGTH as usize)]
    }

    pub fn verification_uri(&self) -> String {
        // TODO config var if we should host at / as well for better UX ?
        format!("{}/auth/v1/devices", *PUB_URL_WITH_SCHEME)
    }

    pub fn verification_uri_complete(&self) -> String {
        format!("{}/auth/v1/devices", *PUB_URL_WITH_SCHEME)
    }
}