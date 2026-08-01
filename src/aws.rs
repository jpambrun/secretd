use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_config::{BehaviorVersion, Region};
use aws_sdk_ssooidc::operation::create_token::CreateTokenError;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use zeroize::Zeroize;

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_TOKEN_GRANT: &str = "refresh_token";
const SSO_SCOPE: &str = "sso:account:access";
const EXPIRY_SKEW_SECONDS: u64 = 60;
pub const AWS_SESSION_EXPIRED: &str = "AWS SSO session has expired";

pub fn is_session_expired_error(error: &str) -> bool {
    error == AWS_SESSION_EXPIRED
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AwsAccessLevel {
    ReadOnly,
    Admin,
}

impl AwsAccessLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTarget {
    pub profile: String,
    pub account_id: String,
    pub read_only_role: String,
    pub admin_role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDiscoveredAccount {
    pub account_id: String,
    pub account_name: String,
    pub email_address: String,
    pub roles: Vec<String>,
}

impl AwsTarget {
    pub fn role(&self, level: AwsAccessLevel) -> &str {
        match level {
            AwsAccessLevel::ReadOnly => &self.read_only_role,
            AwsAccessLevel::Admin => &self.admin_role,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsOidcRegistration {
    pub client_id: String,
    pub client_secret: String,
    pub client_secret_expires_at: u64,
}

impl Drop for AwsOidcRegistration {
    fn drop(&mut self) {
        self.client_id.zeroize();
        self.client_secret.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSsoToken {
    pub access_token: String,
    pub access_token_expires_at: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
}

impl Drop for AwsSsoToken {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSettings {
    pub start_url: String,
    pub sso_region: String,
    pub targets: Vec<AwsTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_accounts: Vec<AwsDiscoveredAccount>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub discovery_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<AwsOidcRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<AwsSsoToken>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsConfiguration {
    pub start_url: String,
    pub sso_region: String,
    pub targets: Vec<AwsTarget>,
}

#[derive(Clone, Debug)]
pub struct AwsSettingsSummary {
    pub configuration: AwsConfiguration,
    pub discovered_accounts: Vec<AwsDiscoveredAccount>,
    pub discovery_complete: bool,
    pub logged_in: bool,
    pub access_token_expires_at: Option<u64>,
}

impl AwsSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !self.start_url.starts_with("https://") || self.start_url.chars().any(char::is_control) {
            return Err("AWS access portal URL must be an HTTPS URL".into());
        }
        validate_identifier(&self.sso_region, "SSO region")?;
        let mut profiles = std::collections::HashSet::new();
        for target in &self.targets {
            validate_aws_profile(&target.profile)?;
            if !profiles.insert(&target.profile) {
                return Err(format!("AWS profile '{}' is duplicated", target.profile));
            }
            if target.account_id.len() != 12
                || !target.account_id.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(format!(
                    "AWS profile '{}' has an invalid account ID",
                    target.profile
                ));
            }
            validate_identifier(&target.read_only_role, "read-only role")?;
            validate_identifier(&target.admin_role, "admin role")?;
            if !target.region.is_empty() {
                validate_identifier(&target.region, "AWS region")?;
            }
        }
        let mut accounts = std::collections::HashSet::new();
        for account in &self.discovered_accounts {
            if account.account_id.len() != 12
                || !account.account_id.bytes().all(|byte| byte.is_ascii_digit())
                || !accounts.insert(&account.account_id)
            {
                return Err("AWS discovery contains an invalid account ID".into());
            }
            if account.account_name.chars().any(char::is_control)
                || account.email_address.chars().any(char::is_control)
            {
                return Err("AWS discovery contains invalid account metadata".into());
            }
            for role in &account.roles {
                validate_identifier(role, "AWS role")?;
            }
        }
        if !self.discovered_accounts.is_empty() {
            for target in &self.targets {
                let account = self
                    .discovered_accounts
                    .iter()
                    .find(|account| account.account_id == target.account_id)
                    .ok_or_else(|| {
                        format!(
                            "AWS profile '{}' refers to an account that is no longer assigned",
                            target.profile
                        )
                    })?;
                if !account.roles.contains(&target.read_only_role)
                    || !account.roles.contains(&target.admin_role)
                {
                    return Err(format!(
                        "AWS profile '{}' refers to a role that is no longer assigned",
                        target.profile
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn target(&self, profile: &str) -> Result<&AwsTarget, String> {
        self.targets
            .iter()
            .find(|target| target.profile == profile)
            .ok_or_else(|| format!("AWS profile '{profile}' is not configured in secretd"))
    }

    pub fn logged_in(&self) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| !token.refresh_token.is_empty() || !token_expired(token))
    }

    pub fn summary(&self) -> AwsSettingsSummary {
        AwsSettingsSummary {
            configuration: AwsConfiguration {
                start_url: self.start_url.clone(),
                sso_region: self.sso_region.clone(),
                targets: self.targets.clone(),
            },
            discovered_accounts: self.discovered_accounts.clone(),
            discovery_complete: self.discovery_complete,
            logged_in: self.logged_in(),
            access_token_expires_at: self
                .token
                .as_ref()
                .map(|token| token.access_token_expires_at),
        }
    }

    pub fn update_configuration(&mut self, configuration: AwsConfiguration) -> Result<(), String> {
        let connection_changed = self.start_url != configuration.start_url
            || self.sso_region != configuration.sso_region;
        self.start_url = configuration.start_url;
        self.sso_region = configuration.sso_region;
        self.targets = configuration.targets;
        self.validate()?;
        if connection_changed {
            self.registration = None;
            self.token = None;
            self.discovered_accounts.clear();
            self.discovery_complete = false;
            self.targets.clear();
        }
        Ok(())
    }

    pub fn from_configuration(configuration: AwsConfiguration) -> Result<Self, String> {
        let settings = Self {
            start_url: configuration.start_url,
            sso_region: configuration.sso_region,
            targets: configuration.targets,
            discovered_accounts: Vec::new(),
            discovery_complete: false,
            registration: None,
            token: None,
        };
        settings.validate()?;
        Ok(settings)
    }
}

#[derive(Clone, Debug)]
pub struct AwsDeviceAuthorization {
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub user_code: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub enum AwsLoginStatus {
    Idle,
    Starting,
    AwaitingUser(AwsDeviceAuthorization),
    Discovering,
    LoggedIn { expires_at: u64 },
    Failed(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AwsCredentialProcessOutput {
    pub version: u8,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
    pub account_id: String,
}

impl Drop for AwsCredentialProcessOutput {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

#[derive(Clone)]
pub struct AwsBroker {
    runtime: Arc<Runtime>,
    operations: Arc<Mutex<()>>,
}

impl AwsBroker {
    pub fn new() -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("secretd-aws")
            .build()
            .map_err(|error| format!("Could not start AWS runtime: {error}"))?;
        Ok(Self {
            runtime: Arc::new(runtime),
            operations: Arc::new(Mutex::new(())),
        })
    }

    pub fn operation(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.operations
            .lock()
            .map_err(|_| "AWS operation state is unavailable".into())
    }

    pub fn login(
        &self,
        mut settings: AwsSettings,
        device_ready: impl FnOnce(AwsDeviceAuthorization),
    ) -> Result<AwsSettings, String> {
        settings.validate()?;
        self.runtime.block_on(async {
            let client = oidc_client(&settings.sso_region).await;
            ensure_registration(&client, &mut settings).await?;
            let registration = settings
                .registration
                .as_ref()
                .ok_or_else(|| "AWS OIDC client registration is unavailable".to_string())?;
            let authorization = client
                .start_device_authorization()
                .client_id(&registration.client_id)
                .client_secret(&registration.client_secret)
                .start_url(&settings.start_url)
                .send()
                .await
                .map_err(|error| format!("Could not start AWS SSO login: {error}"))?;
            let device_code = authorization
                .device_code()
                .ok_or_else(|| "AWS SSO did not return a device code".to_string())?
                .to_string();
            let verification_uri = authorization
                .verification_uri()
                .ok_or_else(|| "AWS SSO did not return a verification URL".to_string())?
                .to_string();
            let user_code = authorization
                .user_code()
                .ok_or_else(|| "AWS SSO did not return a user code".to_string())?
                .to_string();
            let expires_in = authorization.expires_in().max(1) as u64;
            let mut interval = authorization.interval().max(1) as u64;
            let deadline = now_seconds().saturating_add(expires_in);
            device_ready(AwsDeviceAuthorization {
                verification_uri,
                verification_uri_complete: authorization
                    .verification_uri_complete()
                    .map(str::to_string),
                user_code,
                expires_at: deadline,
            });

            loop {
                if now_seconds() >= deadline {
                    return Err("AWS SSO login expired before it was approved".into());
                }
                tokio::time::sleep(Duration::from_secs(interval)).await;
                let registration = settings
                    .registration
                    .as_ref()
                    .expect("registration was established");
                match client
                    .create_token()
                    .client_id(&registration.client_id)
                    .client_secret(&registration.client_secret)
                    .grant_type(DEVICE_CODE_GRANT)
                    .device_code(&device_code)
                    .send()
                    .await
                {
                    Ok(output) => {
                        settings.token = Some(token_from_output(&output, None)?);
                        return Ok(settings);
                    }
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(CreateTokenError::is_authorization_pending_exception) => {}
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(CreateTokenError::is_slow_down_exception) =>
                    {
                        interval = interval.saturating_add(5);
                    }
                    Err(error) => return Err(format!("AWS SSO login failed: {error}")),
                }
            }
        })
    }

    pub fn credentials(
        &self,
        settings: &mut AwsSettings,
        profile: &str,
        level: AwsAccessLevel,
    ) -> Result<AwsCredentialProcessOutput, String> {
        settings.validate()?;
        self.runtime.block_on(async {
            refresh_access_token(settings).await?;
            let target = settings.target(profile)?.clone();
            let access_token = settings
                .token
                .as_ref()
                .filter(|token| !token_expired(token))
                .map(|token| token.access_token.clone())
                .ok_or_else(|| AWS_SESSION_EXPIRED.to_string())?;
            let shared = anonymous_config(&settings.sso_region).await;
            let client = aws_sdk_sso::Client::new(&shared);
            let output = client
                .get_role_credentials()
                .account_id(&target.account_id)
                .role_name(target.role(level))
                .access_token(access_token)
                .send()
                .await
                .map_err(|error| {
                    if error.as_service_error().is_some_and(
                        aws_sdk_sso::operation::get_role_credentials::GetRoleCredentialsError::is_unauthorized_exception,
                    ) {
                        AWS_SESSION_EXPIRED.to_string()
                    } else {
                        format!(
                            "Could not get {} credentials for '{}': {error}",
                            level.label(),
                            target.profile
                        )
                    }
                })?;
            let credentials = output
                .role_credentials()
                .ok_or_else(|| "AWS SSO did not return role credentials".to_string())?;
            let expiration_millis = u64::try_from(credentials.expiration())
                .map_err(|_| "AWS SSO returned an invalid credential expiration".to_string())?;
            let expiration = chrono::DateTime::from_timestamp_millis(
                i64::try_from(expiration_millis)
                    .map_err(|_| "AWS SSO returned an invalid credential expiration".to_string())?,
            )
            .ok_or_else(|| "AWS SSO returned an invalid credential expiration".to_string())?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            Ok(AwsCredentialProcessOutput {
                version: 1,
                access_key_id: required(credentials.access_key_id(), "access key ID")?,
                secret_access_key: required(credentials.secret_access_key(), "secret access key")?,
                session_token: required(credentials.session_token(), "session token")?,
                expiration,
                account_id: target.account_id,
            })
        })
    }

    pub fn discover_accounts(&self, settings: &mut AwsSettings) -> Result<(), String> {
        settings.validate()?;
        self.runtime.block_on(async {
            refresh_access_token(settings).await?;
            let access_token = settings
                .token
                .as_ref()
                .filter(|token| !token_expired(token))
                .map(|token| token.access_token.clone())
                .ok_or_else(|| AWS_SESSION_EXPIRED.to_string())?;
            let shared = anonymous_config(&settings.sso_region).await;
            let client = aws_sdk_sso::Client::new(&shared);
            let mut accounts = Vec::new();
            let mut next_token = None;
            loop {
                let requested_token = next_token.take();
                let output = client
                    .list_accounts()
                    .access_token(&access_token)
                    .set_next_token(requested_token.clone())
                    .send()
                    .await
                    .map_err(|error| format!("Could not list AWS accounts: {error}"))?;
                for account in output.account_list() {
                    let account_id = required(account.account_id(), "account ID")?;
                    let roles = list_account_roles(&client, &access_token, &account_id).await?;
                    accounts.push(AwsDiscoveredAccount {
                        account_id,
                        account_name: account.account_name().unwrap_or_default().to_string(),
                        email_address: account.email_address().unwrap_or_default().to_string(),
                        roles,
                    });
                }
                next_token = output.next_token().map(str::to_string);
                if next_token.as_deref().is_none_or(str::is_empty) || next_token == requested_token
                {
                    break;
                }
            }
            accounts.sort_by(|left, right| {
                left.account_name
                    .to_ascii_lowercase()
                    .cmp(&right.account_name.to_ascii_lowercase())
                    .then_with(|| left.account_id.cmp(&right.account_id))
            });
            let mut seen = std::collections::HashSet::new();
            accounts.retain(|account| seen.insert(account.account_id.clone()));
            settings.targets.retain(|target| {
                accounts.iter().any(|account| {
                    account.account_id == target.account_id
                        && account.roles.contains(&target.read_only_role)
                        && account.roles.contains(&target.admin_role)
                })
            });
            settings.discovered_accounts = accounts;
            settings.discovery_complete = true;
            settings.validate()
        })
    }
}

async fn list_account_roles(
    client: &aws_sdk_sso::Client,
    access_token: &str,
    account_id: &str,
) -> Result<Vec<String>, String> {
    let mut roles = Vec::new();
    let mut next_token = None;
    loop {
        let requested_token = next_token.take();
        let output = client
            .list_account_roles()
            .access_token(access_token)
            .account_id(account_id)
            .set_next_token(requested_token.clone())
            .send()
            .await
            .map_err(|error| {
                format!("Could not list roles for AWS account {account_id}: {error}")
            })?;
        roles.extend(
            output
                .role_list()
                .iter()
                .filter_map(|role| role.role_name().map(str::to_string)),
        );
        next_token = output.next_token().map(str::to_string);
        if next_token.as_deref().is_none_or(str::is_empty) || next_token == requested_token {
            break;
        }
    }
    roles.sort_by_key(|role| role.to_ascii_lowercase());
    roles.dedup();
    Ok(roles)
}

async fn anonymous_config(region: &str) -> aws_config::SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .no_credentials()
        .load()
        .await
}

async fn oidc_client(region: &str) -> aws_sdk_ssooidc::Client {
    let shared = anonymous_config(region).await;
    aws_sdk_ssooidc::Client::new(&shared)
}

async fn ensure_registration(
    client: &aws_sdk_ssooidc::Client,
    settings: &mut AwsSettings,
) -> Result<(), String> {
    let valid = settings.registration.as_ref().is_some_and(|registration| {
        registration.client_secret_expires_at > now_seconds().saturating_add(EXPIRY_SKEW_SECONDS)
    });
    if valid {
        return Ok(());
    }
    settings.registration = None;
    settings.token = None;
    let output = client
        .register_client()
        .client_name("secretd")
        .client_type("public")
        .scopes(SSO_SCOPE)
        .grant_types(DEVICE_CODE_GRANT)
        .grant_types(REFRESH_TOKEN_GRANT)
        .send()
        .await
        .map_err(|error| format!("Could not register secretd with AWS SSO: {error}"))?;
    settings.registration = Some(AwsOidcRegistration {
        client_id: required(output.client_id(), "OIDC client ID")?,
        client_secret: required(output.client_secret(), "OIDC client secret")?,
        client_secret_expires_at: u64::try_from(output.client_secret_expires_at())
            .map_err(|_| "AWS SSO returned an invalid client expiration".to_string())?,
    });
    Ok(())
}

async fn refresh_access_token(settings: &mut AwsSettings) -> Result<(), String> {
    if settings
        .token
        .as_ref()
        .is_some_and(|token| !token_expired(token))
    {
        return Ok(());
    }
    let registration = settings
        .registration
        .as_ref()
        .filter(|registration| {
            registration.client_secret_expires_at
                > now_seconds().saturating_add(EXPIRY_SKEW_SECONDS)
        })
        .ok_or_else(|| AWS_SESSION_EXPIRED.to_string())?;
    let previous_refresh = settings
        .token
        .as_ref()
        .map(|token| token.refresh_token.clone())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AWS_SESSION_EXPIRED.to_string())?;
    let client = oidc_client(&settings.sso_region).await;
    let output = client
        .create_token()
        .client_id(&registration.client_id)
        .client_secret(&registration.client_secret)
        .grant_type(REFRESH_TOKEN_GRANT)
        .refresh_token(&previous_refresh)
        .send()
        .await
        .map_err(|_| AWS_SESSION_EXPIRED.to_string())?;
    settings.token = Some(token_from_output(&output, Some(previous_refresh))?);
    Ok(())
}

fn token_from_output(
    output: &aws_sdk_ssooidc::operation::create_token::CreateTokenOutput,
    fallback_refresh_token: Option<String>,
) -> Result<AwsSsoToken, String> {
    let access_token = required(output.access_token(), "SSO access token")?;
    let expires_in = output.expires_in();
    if expires_in <= 0 {
        return Err("AWS SSO returned an invalid token expiration".into());
    }
    Ok(AwsSsoToken {
        access_token,
        access_token_expires_at: now_seconds().saturating_add(expires_in as u64),
        refresh_token: output
            .refresh_token()
            .map(str::to_string)
            .or(fallback_refresh_token)
            .unwrap_or_default(),
    })
}

fn token_expired(token: &AwsSsoToken) -> bool {
    token.access_token_expires_at <= now_seconds().saturating_add(EXPIRY_SKEW_SECONDS)
}

fn required(value: Option<&str>, label: &str) -> Result<String, String> {
    value
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("AWS SSO did not return {label}"))
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

pub fn validate_aws_profile(profile: &str) -> Result<(), String> {
    if profile.is_empty()
        || profile.len() > 128
        || !profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("AWS profile is invalid".into());
    }
    Ok(())
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AwsSettings {
        AwsSettings {
            start_url: "https://example.awsapps.com/start".into(),
            sso_region: "ca-central-1".into(),
            targets: vec![AwsTarget {
                profile: "prod".into(),
                account_id: "123456789012".into(),
                read_only_role: "ReadOnly".into(),
                admin_role: "Administrator".into(),
                region: "ca-central-1".into(),
            }],
            discovered_accounts: Vec::new(),
            discovery_complete: false,
            registration: None,
            token: None,
        }
    }

    #[test]
    fn validates_settings_and_selects_roles() {
        let settings = settings();
        settings.validate().unwrap();
        let target = settings.target("prod").unwrap();
        assert_eq!(target.role(AwsAccessLevel::ReadOnly), "ReadOnly");
        assert_eq!(target.role(AwsAccessLevel::Admin), "Administrator");
    }

    #[test]
    fn rejects_duplicate_profiles_and_invalid_accounts() {
        let mut settings = settings();
        settings.targets.push(settings.targets[0].clone());
        assert!(settings.validate().is_err());
        settings.targets.pop();
        settings.targets[0].account_id = "123".into();
        assert!(settings.validate().is_err());
    }

    #[test]
    fn rejects_profile_aliases_the_credential_helper_cannot_use() {
        let mut settings = settings();
        settings.targets[0].profile = "prod.ca".into();
        assert_eq!(settings.validate().unwrap_err(), "AWS profile is invalid");
    }

    #[test]
    fn connection_can_be_saved_before_accounts_are_discovered() {
        let mut settings = settings();
        settings.targets.clear();
        settings.validate().unwrap();
        assert!(settings.target("prod").is_err());
    }

    #[test]
    fn changing_the_sso_connection_clears_discovery_and_aliases() {
        let mut settings = settings();
        settings.discovered_accounts = vec![AwsDiscoveredAccount {
            account_id: "123456789012".into(),
            account_name: "Production".into(),
            email_address: "prod@example.com".into(),
            roles: vec!["ReadOnly".into(), "Administrator".into()],
        }];
        settings
            .update_configuration(AwsConfiguration {
                start_url: "https://other.awsapps.com/start".into(),
                sso_region: "us-east-1".into(),
                targets: settings.targets.clone(),
            })
            .unwrap();
        assert!(settings.targets.is_empty());
        assert!(settings.discovered_accounts.is_empty());
    }

    #[test]
    fn credential_process_output_uses_aws_field_names() {
        let output = AwsCredentialProcessOutput {
            version: 1,
            access_key_id: "key".into(),
            secret_access_key: "secret".into(),
            session_token: "token".into(),
            expiration: "2026-07-31T12:00:00Z".into(),
            account_id: "123456789012".into(),
        };
        let value = serde_json::to_value(&output).unwrap();
        assert_eq!(value["Version"], 1);
        assert_eq!(value["AccessKeyId"], "key");
        assert_eq!(value["SecretAccessKey"], "secret");
        assert_eq!(value["SessionToken"], "token");
        assert_eq!(value["AccountId"], "123456789012");
    }

    #[test]
    fn identifies_an_expired_session_for_interactive_reauthentication() {
        assert!(is_session_expired_error(AWS_SESSION_EXPIRED));
        assert!(!is_session_expired_error(
            "Could not get admin credentials for 'prod'"
        ));
    }
}
