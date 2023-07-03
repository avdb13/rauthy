use crate::app_state::AppState;
use crate::request::{PasswordHashTimesRequest, PasswordPolicyRequest};
use actix_web::web;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, PasswordHasher, Version};
use rand_core::OsRng;
use rauthy_common::constants::{
    ARGON2ID_M_COST_MIN, ARGON2ID_T_COST_MIN, CACHE_NAME_12HR, IDX_PASSWORD_RULES,
};
use rauthy_common::error_response::ErrorResponse;
use redhac::{cache_get, cache_get_from, cache_get_value, cache_insert, AckLevel};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};
use std::cmp::max;
use tokio::time;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordHashTimes {
    pub results: Vec<PasswordHashTime>,
}

impl PasswordHashTimes {
    /// Computes the best settings for the argon2id hash algorithm depending on the given options.
    /// If only `target_time` is given, it will use default values for `m_cost` and `p_cost`.
    ///
    /// `target_time`: The time in ms it should take approximately to compute an argon2id hash
    pub async fn compute(req_data: PasswordHashTimesRequest) -> Result<Self, ErrorResponse> {
        let target = req_data.target_time;
        let m_cost = req_data.m_cost.unwrap_or(ARGON2ID_M_COST_MIN);
        let p_cost = req_data.p_cost.unwrap_or(num_cpus::get() as u32);

        let mut results = Vec::with_capacity(4);
        let mut time_taken = 0u32;

        // get a good baseline for t_cost == 1
        let params = argon2::Params::new(m_cost, 1, p_cost, None)?;
        let now = time::Instant::now();
        let _ = Self::new_password_hash("SuperRandomString1337", &params).await?;
        let t_one = now.elapsed().as_millis() as u32;

        // start computation ~50ms below the target
        let approx = (target - 50) / t_one;
        let mut t_cost = max(ARGON2ID_T_COST_MIN, approx);

        while time_taken < target {
            let params = argon2::Params::new(m_cost, t_cost, p_cost, None)?;

            let now = time::Instant::now();
            let _ = Self::new_password_hash("SuperRandomString1337", &params).await?;
            let elapsed = now.elapsed().as_millis();
            time_taken = if elapsed > u32::MAX as u128 {
                u32::MAX
            } else {
                elapsed as u32
            };

            results.push(PasswordHashTime {
                alg: "argon2id".to_string(),
                m_cost,
                t_cost,
                p_cost,
                time_taken,
            });

            if t_cost > 20 {
                t_cost += t_cost / 10;
            } else {
                t_cost += 1;
            }
        }

        // always show the latest computation on top
        results.reverse();
        Ok(Self { results })
    }

    /// Generates a new Argon2id hash from the given cleartext password and returns the hash.
    pub async fn new_password_hash(
        plain: &str,
        params: &argon2::Params,
    ) -> Result<String, ErrorResponse> {
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_owned());
        let plain_pwd = plain.to_owned();

        // hashing should not happen on the event loop
        let hash = web::block(move || {
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(plain_pwd.as_bytes(), &salt)
                .expect("Error hashing the Password")
                .to_string()
        })
        .await
        .map_err(ErrorResponse::from)?;

        Ok(hash)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordHashTime {
    pub alg: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub time_taken: u32,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub length_min: i32,
    pub length_max: i32,
    pub include_lower_case: Option<i32>,
    pub include_upper_case: Option<i32>,
    pub include_digits: Option<i32>,
    pub include_special: Option<i32>,
    pub valid_days: Option<i32>,
    pub not_recently_used: Option<i32>,
}

/// CRUD
impl PasswordPolicy {
    pub async fn find(data: &web::Data<AppState>) -> Result<Self, ErrorResponse> {
        let policy = cache_get!(
            PasswordPolicy,
            CACHE_NAME_12HR.to_string(),
            IDX_PASSWORD_RULES.to_string(),
            &data.caches.ha_cache_config,
            false
        )
        .await?;
        if policy.is_some() {
            return Ok(policy.unwrap());
        }

        let res = sqlx::query("select data from config where id = 'password_policy'")
            .fetch_one(&data.db)
            .await?;
        let bytes: Vec<u8> = res.get("data");
        let policy = bincode::deserialize::<Self>(&bytes)?;

        cache_insert(
            CACHE_NAME_12HR.to_string(),
            IDX_PASSWORD_RULES.to_string(),
            &data.caches.ha_cache_config,
            &policy,
            AckLevel::Quorum,
        )
        .await?;

        Ok(policy)
    }

    pub async fn save(&self, data: &web::Data<AppState>) -> Result<(), ErrorResponse> {
        let slf = bincode::serialize(&self).unwrap();

        sqlx::query("update config set data = $1 where id = 'password_policy'")
            .bind(slf)
            .execute(&data.db)
            .await?;

        cache_insert(
            CACHE_NAME_12HR.to_string(),
            IDX_PASSWORD_RULES.to_string(),
            &data.caches.ha_cache_config,
            &self,
            AckLevel::Quorum,
        )
        .await?;

        Ok(())
    }
}

impl PasswordPolicy {
    pub fn apply_req(&mut self, req: PasswordPolicyRequest) {
        self.length_min = req.length_min;
        self.length_max = req.length_max;
        self.include_lower_case = req.include_lower_case;
        self.include_upper_case = req.include_upper_case;
        self.include_digits = req.include_digits;
        self.include_special = req.include_special;
        self.valid_days = req.valid_days;
        self.not_recently_used = req.not_recently_used;
    }
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RecentPasswordsEntity {
    pub user_id: String,
    // password hashes separated by \n
    pub passwords: String,
}

impl RecentPasswordsEntity {
    pub async fn create(
        data: &web::Data<AppState>,
        user_id: &str,
        passwords: &String,
    ) -> Result<(), ErrorResponse> {
        sqlx::query("insert into recent_passwords (user_id, passwords) values ($1, $2)")
            .bind(user_id)
            .bind(passwords)
            .execute(&data.db)
            .await?;

        Ok(())
    }

    pub async fn find(data: &web::Data<AppState>, user_id: &str) -> Result<Self, ErrorResponse> {
        let res = sqlx::query_as::<_, Self>("select * from recent_passwords where user_id = $1")
            .bind(user_id)
            .fetch_one(&data.db)
            .await?;
        Ok(res)
    }

    pub async fn save(&self, data: &web::Data<AppState>) -> Result<(), ErrorResponse> {
        sqlx::query("update recent_passwords set passwords = $1 where user_id = $2")
            .bind(&self.passwords)
            .bind(&self.user_id)
            .execute(&data.db)
            .await?;
        Ok(())
    }
}
