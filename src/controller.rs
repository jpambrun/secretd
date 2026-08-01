use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    aws::{
        AwsAccessLevel, AwsBroker, AwsConfiguration, AwsLoginStatus, AwsSettings,
        AwsSettingsSummary,
    },
    grants::{Grant, GrantScope, GrantStore, MAX_GRANT_SECONDS, now_millis},
    process::{ProcessIdentity, omit_secretd_client_processes},
    vault::{SecretSummary, VaultError, VaultStore, normalize_secret_name},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Deny,
    Once,
    Temporary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestResolution {
    Approved,
    Denied,
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    AllowedOnce,
    GrantedTemporarily,
    AutoGranted,
    Denied,
    TimedOut,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub id: String,
    pub occurred_at: u64,
    pub action: AuditAction,
    pub secret: String,
    pub group: Option<String>,
    pub scope: Option<GrantScope>,
    pub resource: Option<String>,
    pub ttl_seconds: Option<u64>,
    pub process: ProcessIdentity,
}

#[derive(Clone, Debug)]
pub struct PendingRequest {
    pub id: String,
    pub secret: String,
    pub group: Option<String>,
    pub verified: bool,
    pub process_tree: Vec<ProcessIdentity>,
    pub origin: ProcessIdentity,
    pub requested_at: u64,
}

#[derive(Clone, Debug)]
pub struct PendingAwsCredentialRequest {
    pub id: String,
    pub profile: String,
    pub verified: bool,
    pub process_tree: Vec<ProcessIdentity>,
    pub origin: ProcessIdentity,
    pub requested_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwsRequestResolution {
    Approved(AwsAccessLevel),
    Denied,
}

pub enum AwsRequestOutcome {
    Immediate(AwsAccessLevel),
    Pending {
        id: String,
        receiver: Receiver<AwsRequestResolution>,
    },
}

#[derive(Clone, Debug)]
pub struct AwsCredentialGrant {
    pub id: String,
    pub profile: String,
    pub level: AwsAccessLevel,
    pub process: ProcessIdentity,
    pub created_at: u64,
}

#[derive(Clone, Debug)]
pub struct AppSnapshot {
    pub vault_exists: bool,
    pub unlocked: bool,
    pub secrets: Vec<SecretSummary>,
    pub pending: Vec<PendingRequest>,
    pub pending_aws: Vec<PendingAwsCredentialRequest>,
    pub grants: Vec<Grant>,
    pub aws_grants: Vec<AwsCredentialGrant>,
    pub audit: Vec<AuditEntry>,
    pub max_grant_seconds: u64,
    pub aws: Option<AwsSettingsSummary>,
    pub aws_login: AwsLoginStatus,
}

pub enum RequestOutcome {
    Immediate(Zeroizing<String>),
    Pending {
        id: String,
        receiver: Receiver<RequestResolution>,
    },
}

pub struct Controller {
    vault: VaultStore,
    grants: GrantStore,
    pending: HashMap<String, PendingRequest>,
    pending_resolutions: HashMap<String, Sender<RequestResolution>>,
    waiting_for_unlock: HashSet<String>,
    audit: Vec<AuditEntry>,
    aws_broker: AwsBroker,
    pending_aws: HashMap<String, PendingAwsCredentialRequest>,
    pending_aws_resolutions: HashMap<String, Sender<AwsRequestResolution>>,
    aws_process_decisions: Vec<AwsCredentialGrant>,
    aws_login: AwsLoginStatus,
}

impl Controller {
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault: VaultStore::new(vault_path),
            grants: GrantStore::default(),
            pending: HashMap::new(),
            pending_resolutions: HashMap::new(),
            waiting_for_unlock: HashSet::new(),
            audit: Vec::new(),
            aws_broker: AwsBroker::new().expect("AWS runtime should start"),
            pending_aws: HashMap::new(),
            pending_aws_resolutions: HashMap::new(),
            aws_process_decisions: Vec::new(),
            aws_login: AwsLoginStatus::Idle,
        }
    }

    pub fn snapshot(&mut self) -> AppSnapshot {
        let vault_exists = self.vault.exists().unwrap_or(false);
        let unlocked = self.vault.unlocked();
        let secrets = if unlocked {
            self.vault.list().unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut pending: Vec<_> = self.pending.values().cloned().collect();
        pending.sort_by_key(|request| request.requested_at);
        let mut audit = self.audit.clone();
        audit.reverse();
        let mut pending_aws: Vec<_> = self.pending_aws.values().cloned().collect();
        pending_aws.sort_by_key(|request| request.requested_at);
        let aws = if unlocked {
            self.vault
                .aws_settings()
                .ok()
                .flatten()
                .map(|settings| settings.summary())
        } else {
            None
        };
        AppSnapshot {
            vault_exists,
            unlocked,
            secrets,
            pending,
            pending_aws,
            grants: self.grants.list(),
            aws_grants: self.aws_process_decisions.clone(),
            audit,
            max_grant_seconds: MAX_GRANT_SECONDS,
            aws,
            aws_login: self.aws_login.clone(),
        }
    }

    pub fn create_vault(&mut self, password: &str) -> Result<(), VaultError> {
        self.vault.create(password)?;
        self.prepare_waiting_requests();
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        self.vault.unlock(password)?;
        self.prepare_waiting_requests();
        Ok(())
    }

    pub fn lock(&mut self) {
        self.vault.lock();
        for grant in self.grants.list() {
            self.revoke_grant(&grant.id);
        }
        let pending: Vec<_> = self.pending.keys().cloned().collect();
        for id in pending {
            let _ = self.respond(&id, ApprovalDecision::Deny, None, GrantScope::Secret);
        }
        for sender in self
            .pending_aws_resolutions
            .drain()
            .map(|(_, sender)| sender)
        {
            let _ = sender.send(AwsRequestResolution::Denied);
        }
        self.pending_aws.clear();
        self.aws_process_decisions.clear();
        self.aws_login = AwsLoginStatus::Idle;
    }

    pub fn save_secret(
        &mut self,
        name: &str,
        value: &str,
        previous_name: Option<&str>,
        group: Option<&str>,
    ) -> Result<(), VaultError> {
        if let Some(previous) = previous_name
            && normalize_secret_name(previous)? != normalize_secret_name(name)?
        {
            self.vault.rename(previous, name)?;
        }
        self.vault.save_secret(name, value, group)
    }

    pub fn reveal_secret(&self, name: &str) -> Result<Zeroizing<String>, VaultError> {
        self.vault.reveal(name)
    }

    pub fn delete_secret(&mut self, name: &str) -> Result<(), VaultError> {
        let normalized = normalize_secret_name(name)?;
        self.vault.delete(&normalized)?;
        for grant in self.grants.list() {
            if grant.scope == GrantScope::Secret && grant.resource == normalized {
                self.revoke_grant(&grant.id);
            }
        }
        Ok(())
    }

    pub fn change_password(&mut self, password: &str) -> Result<(), VaultError> {
        self.vault.change_password(password)
    }

    pub fn save_aws_configuration(
        &mut self,
        configuration: AwsConfiguration,
    ) -> Result<(), VaultError> {
        let mut settings = match self.vault.aws_settings()? {
            Some(settings) => settings,
            None => AwsSettings::from_configuration(configuration.clone()).map_err(VaultError)?,
        };
        settings
            .update_configuration(configuration)
            .map_err(VaultError)?;
        self.vault.save_aws_settings(settings)?;
        self.aws_process_decisions.clear();
        self.aws_login = AwsLoginStatus::Idle;
        Ok(())
    }

    pub fn save_aws_connection(
        &mut self,
        start_url: String,
        sso_region: String,
    ) -> Result<(), VaultError> {
        let targets = self
            .vault
            .aws_settings()?
            .map_or_else(Vec::new, |settings| settings.targets);
        self.save_aws_configuration(AwsConfiguration {
            start_url,
            sso_region,
            targets,
        })
    }

    pub fn prepare_aws_login(&mut self) -> Result<(AwsBroker, AwsSettings), VaultError> {
        if matches!(
            self.aws_login,
            AwsLoginStatus::Starting
                | AwsLoginStatus::AwaitingUser(_)
                | AwsLoginStatus::Discovering
        ) {
            return Err(VaultError("AWS SSO login is already in progress".into()));
        }
        let settings = self
            .vault
            .aws_settings()?
            .ok_or_else(|| VaultError("Configure AWS SSO before logging in".into()))?;
        settings.validate().map_err(VaultError)?;
        self.aws_login = AwsLoginStatus::Starting;
        Ok((self.aws_broker.clone(), settings))
    }

    pub fn set_aws_login_status(&mut self, status: AwsLoginStatus) {
        self.aws_login = status;
    }

    pub fn complete_aws_login(&mut self, result: Result<AwsSettings, String>) {
        match result {
            Ok(settings) => {
                let expires_at = settings
                    .token
                    .as_ref()
                    .map_or(0, |token| token.access_token_expires_at);
                match self.persist_aws_session(&settings, true) {
                    Ok(()) => self.aws_login = AwsLoginStatus::LoggedIn { expires_at },
                    Err(error) => self.aws_login = AwsLoginStatus::Failed(error.to_string()),
                }
            }
            Err(error) => self.aws_login = AwsLoginStatus::Failed(error),
        }
    }

    pub fn complete_aws_discovery_failure(&mut self, settings: &AwsSettings, error: String) {
        self.aws_login = match self.persist_aws_session(settings, false) {
            Ok(()) => AwsLoginStatus::Failed(error),
            Err(persist_error) => AwsLoginStatus::Failed(format!(
                "{error}; the AWS session could not be saved: {persist_error}"
            )),
        };
    }

    pub fn begin_aws_request(
        &mut self,
        profile: &str,
        process_tree: Vec<ProcessIdentity>,
        verified: bool,
    ) -> Result<AwsRequestOutcome, VaultError> {
        let profile = normalize_aws_profile(profile)?;
        let process_tree = omit_secretd_client_processes(&process_tree);
        let Some(origin) = process_tree.first().cloned() else {
            return Err(VaultError(
                "Unable to determine the requesting process".into(),
            ));
        };
        if self.vault.unlocked() {
            self.vault
                .aws_settings()?
                .ok_or_else(|| VaultError("AWS SSO is not configured in SecretD".into()))?
                .target(&profile)
                .map_err(VaultError)?;
            if verified
                && let Some(decision) = self.aws_process_decisions.iter().find(|decision| {
                    decision.profile == profile
                        && crate::process::same_process(&decision.process, &origin)
                })
            {
                return Ok(AwsRequestOutcome::Immediate(decision.level));
            }
        }
        let id = Uuid::new_v4().to_string();
        let request = PendingAwsCredentialRequest {
            id: id.clone(),
            profile,
            verified,
            process_tree,
            origin,
            requested_at: now_millis(),
        };
        let (sender, receiver) = mpsc::channel();
        self.pending_aws.insert(id.clone(), request);
        self.pending_aws_resolutions.insert(id.clone(), sender);
        Ok(AwsRequestOutcome::Pending { id, receiver })
    }

    pub fn respond_aws(
        &mut self,
        id: &str,
        level: Option<AwsAccessLevel>,
    ) -> Result<(), VaultError> {
        let request = self
            .pending_aws
            .get(id)
            .cloned()
            .ok_or_else(|| VaultError("Request is no longer pending".into()))?;
        let resolution = if let Some(level) = level {
            if !self.vault.unlocked() {
                return Err(VaultError("Vault is locked".into()));
            }
            self.vault
                .aws_settings()?
                .ok_or_else(|| VaultError("AWS SSO is not configured in SecretD".into()))?
                .target(&request.profile)
                .map_err(VaultError)?;
            if request.verified {
                self.aws_process_decisions.push(AwsCredentialGrant {
                    id: Uuid::new_v4().to_string(),
                    profile: request.profile.clone(),
                    level,
                    process: request.origin,
                    created_at: now_millis(),
                });
            }
            AwsRequestResolution::Approved(level)
        } else {
            AwsRequestResolution::Denied
        };
        self.pending_aws.remove(id);
        if let Some(sender) = self.pending_aws_resolutions.remove(id) {
            let _ = sender.send(resolution);
        }
        Ok(())
    }

    pub fn timeout_aws_request(&mut self, id: &str) {
        self.pending_aws.remove(id);
        self.pending_aws_resolutions.remove(id);
    }

    pub fn revoke_aws_grant(&mut self, id: &str) {
        self.aws_process_decisions
            .retain(|decision| decision.id != id);
    }

    pub fn aws_credential_context(&self) -> Result<(AwsBroker, AwsSettings), VaultError> {
        let settings = self
            .vault
            .aws_settings()?
            .ok_or_else(|| VaultError("AWS SSO is not configured in SecretD".into()))?;
        Ok((self.aws_broker.clone(), settings))
    }

    pub fn persist_aws_settings(&mut self, settings: AwsSettings) -> Result<(), VaultError> {
        self.persist_aws_session(&settings, false)
    }

    fn persist_aws_session(
        &mut self,
        session: &AwsSettings,
        include_discovery: bool,
    ) -> Result<(), VaultError> {
        let mut current = self
            .vault
            .aws_settings()?
            .ok_or_else(|| VaultError("AWS SSO is not configured in SecretD".into()))?;
        if current.start_url != session.start_url || current.sso_region != session.sso_region {
            return Err(VaultError(
                "AWS SSO setup changed while the operation was in progress; retry it".into(),
            ));
        }
        current.registration = session.registration.clone();
        current.token = session.token.clone();
        if include_discovery {
            let discovered = session.discovered_accounts.clone();
            current.targets.retain(|target| {
                discovered.iter().any(|account| {
                    account.account_id == target.account_id
                        && account.roles.contains(&target.read_only_role)
                        && account.roles.contains(&target.admin_role)
                })
            });
            current.discovered_accounts = discovered;
            current.discovery_complete = session.discovery_complete;
        }
        self.vault.save_aws_settings(current)
    }

    pub fn revoke_grant(&mut self, id: &str) {
        let Some(grant) = self.grants.revoke(id) else {
            return;
        };
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::Revoked,
            secret: if grant.scope == GrantScope::Secret {
                grant.resource.clone()
            } else {
                String::new()
            },
            group: (grant.scope == GrantScope::Group).then(|| grant.resource.clone()),
            scope: Some(grant.scope),
            resource: Some(grant.resource),
            ttl_seconds: None,
            process: grant.process,
        });
    }

    pub fn begin_request(
        &mut self,
        secret_input: &str,
        process_tree: Vec<ProcessIdentity>,
        verified: bool,
    ) -> Result<RequestOutcome, VaultError> {
        let secret = normalize_secret_name(secret_input)?;
        let process_tree = omit_secretd_client_processes(&process_tree);
        let Some(origin) = process_tree.first().cloned() else {
            return Err(VaultError(
                "Unable to determine the requesting process".into(),
            ));
        };
        if !self.vault.unlocked() {
            return Ok(self.queue_request(secret, None, process_tree, origin, verified, true));
        }
        drop(self.vault.reveal(&secret)?);
        let group = self.vault.group(&secret)?;
        if verified && let Some(grant) = self.grants.find(&secret, group.as_deref(), &origin) {
            self.record_audit(AuditEntry {
                id: String::new(),
                occurred_at: 0,
                action: AuditAction::AutoGranted,
                secret: secret.clone(),
                group,
                scope: Some(grant.scope),
                resource: Some(grant.resource),
                ttl_seconds: None,
                process: origin,
            });
            return Ok(RequestOutcome::Immediate(self.vault.reveal(&secret)?));
        }
        Ok(self.queue_request(secret, group, process_tree, origin, verified, false))
    }

    fn queue_request(
        &mut self,
        secret: String,
        group: Option<String>,
        process_tree: Vec<ProcessIdentity>,
        origin: ProcessIdentity,
        verified: bool,
        waiting_for_unlock: bool,
    ) -> RequestOutcome {
        let id = Uuid::new_v4().to_string();
        let request = PendingRequest {
            id: id.clone(),
            secret,
            group,
            verified,
            process_tree,
            origin,
            requested_at: now_millis(),
        };
        let (sender, receiver) = mpsc::channel();
        self.pending.insert(id.clone(), request);
        self.pending_resolutions.insert(id.clone(), sender);
        if waiting_for_unlock {
            self.waiting_for_unlock.insert(id.clone());
        }
        RequestOutcome::Pending { id, receiver }
    }

    fn prepare_waiting_requests(&mut self) {
        let waiting: Vec<_> = self.waiting_for_unlock.drain().collect();
        for id in waiting {
            let Some(request) = self.pending.get(&id).cloned() else {
                continue;
            };
            let prepared = (|| {
                drop(self.vault.reveal(&request.secret)?);
                self.vault.group(&request.secret)
            })();
            match prepared {
                Ok(group) => {
                    if let Some(request) = self.pending.get_mut(&id) {
                        request.group = group;
                    }
                }
                Err(error) => {
                    self.pending.remove(&id);
                    if let Some(sender) = self.pending_resolutions.remove(&id) {
                        let _ = sender.send(RequestResolution::Failed(error.to_string()));
                    }
                }
            }
        }
    }

    pub fn respond(
        &mut self,
        id: &str,
        decision: ApprovalDecision,
        ttl_seconds: Option<u64>,
        mut scope: GrantScope,
    ) -> Result<(), VaultError> {
        let request = self
            .pending
            .get(id)
            .cloned()
            .ok_or_else(|| VaultError("Request is no longer pending".into()))?;
        if self.waiting_for_unlock.contains(id) && decision != ApprovalDecision::Deny {
            return Err(VaultError("Vault is locked".into()));
        }
        if decision != ApprovalDecision::Temporary {
            scope = GrantScope::Secret;
        }
        if scope == GrantScope::Group && request.group.is_none() {
            return Err(VaultError("This secret does not belong to a group".into()));
        }
        if decision == ApprovalDecision::Temporary && !request.verified {
            return Err(VaultError(
                "Unverified requests can only be allowed once".into(),
            ));
        }
        let resource = match scope {
            GrantScope::Secret => request.secret.clone(),
            GrantScope::Group => request.group.clone().expect("group scope was validated"),
        };
        if decision == ApprovalDecision::Temporary {
            self.grants
                .add(
                    scope,
                    resource.clone(),
                    request.origin.clone(),
                    ttl_seconds.unwrap_or(0),
                )
                .map_err(VaultError)?;
        }
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: match decision {
                ApprovalDecision::Deny => AuditAction::Denied,
                ApprovalDecision::Once => AuditAction::AllowedOnce,
                ApprovalDecision::Temporary => AuditAction::GrantedTemporarily,
            },
            secret: request.secret,
            group: request.group,
            scope: (decision != ApprovalDecision::Deny).then_some(scope),
            resource: (decision != ApprovalDecision::Deny).then_some(resource),
            ttl_seconds: (decision == ApprovalDecision::Temporary)
                .then_some(ttl_seconds.unwrap_or(0)),
            process: request.origin,
        });
        self.pending.remove(id);
        self.waiting_for_unlock.remove(id);
        if let Some(sender) = self.pending_resolutions.remove(id) {
            let resolution = if decision == ApprovalDecision::Deny {
                RequestResolution::Denied
            } else {
                RequestResolution::Approved
            };
            let _ = sender.send(resolution);
        }
        Ok(())
    }

    pub fn timeout_request(&mut self, id: &str) {
        let Some(request) = self.pending.remove(id) else {
            return;
        };
        self.pending_resolutions.remove(id);
        self.waiting_for_unlock.remove(id);
        self.record_audit(AuditEntry {
            id: String::new(),
            occurred_at: 0,
            action: AuditAction::TimedOut,
            secret: request.secret,
            group: request.group,
            scope: None,
            resource: None,
            ttl_seconds: None,
            process: request.origin,
        });
    }

    pub fn release_after_approval(&self, secret: &str) -> Result<Zeroizing<String>, VaultError> {
        self.vault.reveal(secret)
    }

    fn record_audit(&mut self, mut entry: AuditEntry) {
        entry.id = Uuid::new_v4().to_string();
        entry.occurred_at = now_millis();
        self.audit.push(entry);
        if self.audit.len() > 500 {
            self.audit.drain(..self.audit.len() - 500);
        }
    }
}

fn normalize_aws_profile(profile: &str) -> Result<String, VaultError> {
    let profile = profile.trim();
    if profile.is_empty()
        || profile.len() > 128
        || profile.chars().any(char::is_control)
        || !profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(VaultError("AWS profile is invalid".into()));
    }
    Ok(profile.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn process(pid: u32, executable: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            ppid: pid.saturating_sub(1),
            started_at: format!("start-{pid}"),
            executable: executable.into(),
            command: executable.into(),
        }
    }

    fn aws_configuration() -> AwsConfiguration {
        AwsConfiguration {
            start_url: "https://example.awsapps.com/start".into(),
            sso_region: "ca-central-1".into(),
            targets: vec![crate::aws::AwsTarget {
                profile: "prod".into(),
                account_id: "123456789012".into(),
                read_only_role: "ReadOnly".into(),
                admin_role: "Administrator".into(),
                region: "ca-central-1".into(),
            }],
        }
    }

    #[test]
    fn aws_role_is_chosen_by_approval_and_pinned_to_the_process() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let terraform = process(42, "/usr/local/bin/terraform-provider-aws");
        let outcome = controller
            .begin_aws_request("prod", vec![terraform.clone()], true)
            .unwrap();
        let AwsRequestOutcome::Pending { id, receiver } = outcome else {
            panic!("first request should require a decision");
        };
        controller
            .respond_aws(&id, Some(AwsAccessLevel::ReadOnly))
            .unwrap();
        assert_eq!(
            receiver.recv().unwrap(),
            AwsRequestResolution::Approved(AwsAccessLevel::ReadOnly)
        );
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.aws_grants.len(), 1);
        assert_eq!(snapshot.aws_grants[0].profile, "prod");
        assert_eq!(snapshot.aws_grants[0].level, AwsAccessLevel::ReadOnly);

        let outcome = controller
            .begin_aws_request("prod", vec![terraform.clone()], true)
            .unwrap();
        assert!(matches!(
            outcome,
            AwsRequestOutcome::Immediate(AwsAccessLevel::ReadOnly)
        ));

        let grant_id = snapshot.aws_grants[0].id.clone();
        controller.revoke_aws_grant(&grant_id);
        assert!(controller.snapshot().aws_grants.is_empty());
        assert!(matches!(
            controller
                .begin_aws_request("prod", vec![terraform], true)
                .unwrap(),
            AwsRequestOutcome::Pending { .. }
        ));
    }

    #[test]
    fn aws_session_refresh_does_not_overwrite_newer_profile_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_aws_configuration(aws_configuration())
            .unwrap();
        let (_, mut stale) = controller.aws_credential_context().unwrap();

        let mut updated = aws_configuration();
        updated.targets[0].admin_role = "NewAdministrator".into();
        controller.save_aws_configuration(updated).unwrap();
        stale.token = Some(crate::aws::AwsSsoToken {
            access_token: "access".into(),
            access_token_expires_at: u64::MAX,
            refresh_token: "refresh".into(),
        });
        controller.persist_aws_settings(stale).unwrap();

        let settings = controller.vault.aws_settings().unwrap().unwrap();
        assert_eq!(settings.targets[0].admin_role, "NewAdministrator");
        assert_eq!(
            settings
                .token
                .as_ref()
                .map(|token| token.access_token.as_str()),
            Some("access")
        );
    }

    #[test]
    fn approval_creates_group_grant_and_reuses_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret(
                "aws/access-key",
                "first",
                None,
                Some("deployment-read-only"),
            )
            .unwrap();
        controller
            .save_secret(
                "aws/secret-key",
                "second",
                None,
                Some("deployment-read-only"),
            )
            .unwrap();
        let origin = process(20, "/usr/local/bin/deploy");
        let outcome = controller
            .begin_request(
                "aws/access-key",
                vec![process(30, "/usr/local/bin/secretd"), origin.clone()],
                true,
            )
            .unwrap();
        let RequestOutcome::Pending { id, receiver } = outcome else {
            panic!("first request should require approval");
        };
        controller
            .respond(
                &id,
                ApprovalDecision::Temporary,
                Some(300),
                GrantScope::Group,
            )
            .unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            RequestResolution::Approved
        );
        let reused = controller
            .begin_request("aws/secret-key", vec![origin], true)
            .unwrap();
        let RequestOutcome::Immediate(value) = reused else {
            panic!("group grant should be reused");
        };
        assert_eq!(&*value, "second");
        assert_eq!(
            controller.snapshot().audit[0].action,
            AuditAction::AutoGranted
        );
    }

    #[test]
    fn locked_request_waits_for_unlock_and_then_requires_approval() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller
            .save_secret("qwer", "correct password", None, Some("ro"))
            .unwrap();
        controller.lock();

        let outcome = controller
            .begin_request("qwer", vec![process(20, "/usr/local/bin/tool")], true)
            .unwrap();
        let RequestOutcome::Pending { id, receiver } = outcome else {
            panic!("locked request should wait for unlock");
        };
        assert_eq!(controller.snapshot().pending.len(), 1);

        controller.unlock("correct horse").unwrap();
        assert_eq!(
            controller.snapshot().pending[0].group.as_deref(),
            Some("ro")
        );
        controller
            .respond(&id, ApprovalDecision::Once, None, GrantScope::Secret)
            .unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            RequestResolution::Approved
        );
        assert_eq!(
            &*controller.release_after_approval("qwer").unwrap(),
            "correct password"
        );
    }

    #[test]
    fn locked_request_reports_validation_error_after_unlock() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(directory.path().join("vault.json"));
        controller.create_vault("correct horse").unwrap();
        controller.lock();

        let outcome = controller
            .begin_request("missing", vec![process(20, "/usr/local/bin/tool")], true)
            .unwrap();
        let RequestOutcome::Pending { receiver, .. } = outcome else {
            panic!("locked request should wait for unlock");
        };

        controller.unlock("correct horse").unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            RequestResolution::Failed("Secret not found".into())
        );
        assert!(controller.snapshot().pending.is_empty());
    }
}
