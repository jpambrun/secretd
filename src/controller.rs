use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
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
pub struct AppSnapshot {
    pub vault_exists: bool,
    pub unlocked: bool,
    pub secrets: Vec<SecretSummary>,
    pub pending: Vec<PendingRequest>,
    pub grants: Vec<Grant>,
    pub audit: Vec<AuditEntry>,
    pub max_grant_seconds: u64,
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
        AppSnapshot {
            vault_exists,
            unlocked,
            secrets,
            pending,
            grants: self.grants.list(),
            audit,
            max_grant_seconds: MAX_GRANT_SECONDS,
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
