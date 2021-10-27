#![allow(dead_code)]

use anyhow::Result;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;

#[derive(Clone, Debug, Deserialize)]
pub struct FirebaseServiceAccount {
    #[serde(rename = "type")]
    pub service_account_type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
}

impl FirebaseServiceAccount {
    pub fn from_file<P: AsRef<Path>>(service_account_file: P) -> Result<Self> {
        let service_account_file = std::fs::File::open(service_account_file)?;
        let account = serde_json::from_reader(service_account_file)?;
        Ok(account)
    }

    pub fn from_json(json: serde_json::Value) -> Result<Self> {
        let account = serde_json::from_value(json)?;
        Ok(account)
    }

    pub fn from_env_var<S: AsRef<str>>(name: S) -> Result<Self> {
        let account = serde_json::from_str(&std::env::var(name.as_ref())?)?;
        Ok(account)
    }

    pub fn from_default_env_var() -> Result<Self> {
        Self::from_env_var("FB_SERVICE_ACCOUNT")
    }
}

const GOOGLE_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v4/token";

#[derive(Debug, Serialize)]
pub struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Serialize)]
struct TokenRequest {
    grant_type: String,
    assertion: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    pub access_token: String,
    pub expires_in: Duration,
    pub token_type: String,
    pub requested_at: SystemTime,
    pub project_id: String,
}

impl TokenData {
    fn new(token_response: TokenResponse, project_id: String, requested_at: SystemTime) -> Self {
        let TokenResponse {
            access_token,
            expires_in,
            token_type,
        } = token_response;
        Self {
            access_token,
            token_type,
            expires_in: Duration::from_secs(expires_in),
            requested_at,
            project_id,
        }
    }

    fn expires_at(&self) -> SystemTime {
        self.requested_at + self.expires_in
    }

    /// Returns expiration time in unix epoch seconds
    fn expires_at_unix(&self) -> u64 {
        self.expires_at()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

pub type Scope = &'static str;

pub const USERINFO_EMAIL: Scope = "https://www.googleapis.com/auth/userinfo.email";
pub const FIREBASE_FIRESTORE: Scope = "https://www.googleapis.com/auth/datastore";
pub const FIREBASE_DATABASE: Scope = "https://www.googleapis.com/auth/firebase.database";

pub const CLOUD_PLATFORM: Scope = "https://www.googleapis.com/auth/cloud-platform";
pub const APPENGINE_ADMIN: Scope = "https://www.googleapis.com/auth/appengine.admin";
pub const COMPUTE: Scope = "https://www.googleapis.com/auth/compute";
pub const ACCOUNTS_REAUTH: Scope = "https://www.googleapis.com/auth/accounts.reauth";

#[derive(Debug, Clone)]
pub struct GToken {
    pub service_account: FirebaseServiceAccount,
    pub scopes: Vec<Scope>,
    pub token: Option<TokenData>,
    pub cache_file: Option<PathBuf>,
}

/// `GToken` represents an access token used to authenticate against realtimedb.
/// It is created from a firebase account information.
///
/// Example:
///
/// ```ignore
/// let account = FirebaseServiceAccount::from_file("serviceAccount.json")?;
/// let mut gtoken = GToken::new(account);
/// gtoken.refresh_if_necessary().await?;
/// let access_token = dbg!(gtoken.access_token());
/// // ...
/// ```
impl GToken {
    pub fn new(service_account: FirebaseServiceAccount, scopes: &[Scope]) -> Self {
        GToken {
            service_account,
            scopes: Vec::from(scopes),
            token: None,
            cache_file: None,
        }
    }

    async fn read_token_from_cache(&mut self) -> Result<()> {
        if let Some(cache_file) = &self.cache_file {
            let content = match fs::read(cache_file).await {
                Err(_) => {
                    log::debug!("Cannot read token cache file {}", cache_file.display());
                    return Ok(());
                }
                Ok(content) => content,
            };

            let token: TokenData = match serde_json::from_slice(&content) {
                Err(_) => {
                    log::debug!(
                        "Cannot parse token from cache file {}",
                        cache_file.display()
                    );
                    return Ok(());
                }
                Ok(token) => token,
            };

            let use_token = token.project_id == self.service_account.project_id
                && (self.token.is_none()
                    || self
                        .token
                        .as_ref()
                        .map(|my_token| token.expires_at() > my_token.expires_at())
                        .unwrap_or(false));

            if use_token {
                log::debug!("Token cache file {} loaded", cache_file.display());
                self.token = Some(token);
                return Ok(());
            };
        }

        Ok(())
    }

    async fn write_token_to_cache(&mut self) -> Result<()> {
        if let (Some(token), Some(cache_file)) = (&self.token, &self.cache_file) {
            log::debug!("Writing token to cache {}", cache_file.display());
            let contents = serde_json::to_string(token)?;
            fs::write(cache_file, contents).await?;
        }

        Ok(())
    }

    pub async fn cached<P: AsRef<Path>>(&mut self, file: P) -> Result<()> {
        self.cache_file = Some(file.as_ref().to_path_buf());
        self.read_token_from_cache().await?;
        Ok(())
    }

    pub fn access_token(&self) -> Result<String> {
        self.token
            .as_ref()
            .map(|token| token.access_token.trim_end_matches('.').to_string())
            .ok_or_else(|| anyhow::anyhow!("Could not get a valid google access token"))
    }

    pub async fn refresh_if_necessary(&mut self) -> Result<String> {
        match &self.token {
            Some(token) => {
                let now = SystemTime::now();
                if token.expires_at() <= now {
                    log::debug!("Google token is expired, refreshing");
                    return self.refresh().await;
                }
            }
            _ => return self.refresh().await,
        };
        self.access_token()
    }

    pub async fn refresh(&mut self) -> Result<String> {
        log::debug!("refreshing token");

        let scope = self.scopes.join(" ");

        let FirebaseServiceAccount {
            private_key: key,
            client_email: email,
            ..
        } = &self.service_account;

        // -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

        let now = std::time::SystemTime::now();
        let now_unix_epoch = now.duration_since(UNIX_EPOCH)?;
        let iat = now_unix_epoch.as_secs() as usize;

        let claims = Claims {
            iss: email.clone(),
            scope,
            aud: GOOGLE_TOKEN_URL.to_string(),
            exp: iat + 3600,
            iat,
        };
        let token_req = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(key.as_bytes())?,
        )?;
        let body = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned(),
            assertion: token_req,
        };
        let body = serde_json::to_string(&body)?;

        let res = reqwest::blocking::Client::new()
            .post(GOOGLE_TOKEN_URL)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .send()?;

        let token: TokenResponse = res.json()?;
        let project_id = self.service_account.project_id.clone();
        self.token = Some(TokenData::new(token, project_id, now));

        if self.cache_file.is_some() {
            self.write_token_to_cache().await?;
        }

        self.access_token()
    }
}
