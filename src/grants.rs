use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::process::{ProcessIdentity, same_process};

pub const MAX_GRANT_SECONDS: u64 = 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantScope {
    Secret,
    Group,
}

impl GrantScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Group => "group",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub id: String,
    pub scope: GrantScope,
    pub resource: String,
    pub process: ProcessIdentity,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Default)]
pub struct GrantStore {
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn add(
        &mut self,
        scope: GrantScope,
        resource: String,
        process: ProcessIdentity,
        seconds: u64,
    ) -> Result<Grant, String> {
        if seconds == 0 || seconds > MAX_GRANT_SECONDS {
            return Err(format!(
                "Grant duration must be between 1 and {MAX_GRANT_SECONDS} seconds"
            ));
        }
        let now = now_millis();
        let grant = Grant {
            id: Uuid::new_v4().to_string(),
            scope,
            resource,
            process,
            created_at: now,
            expires_at: now.saturating_add(seconds.saturating_mul(1_000)),
        };
        self.grants.push(grant.clone());
        Ok(grant)
    }

    pub fn find(
        &mut self,
        secret: &str,
        group: Option<&str>,
        process_tree: &[ProcessIdentity],
    ) -> Option<Grant> {
        self.cleanup();
        process_tree.iter().find_map(|process| {
            self.grants
                .iter()
                .rev()
                .find(|grant| {
                    let resource_matches = match grant.scope {
                        GrantScope::Secret => grant.resource == secret,
                        GrantScope::Group => group.is_some_and(|group| grant.resource == group),
                    };
                    resource_matches && same_process(&grant.process, process)
                })
                .cloned()
        })
    }

    pub fn list(&mut self) -> Vec<Grant> {
        self.cleanup();
        let mut grants = self.grants.clone();
        grants.sort_by_key(|grant| grant.expires_at);
        grants
    }

    pub fn revoke(&mut self, id: &str) -> Option<Grant> {
        let index = self.grants.iter().position(|grant| grant.id == id)?;
        Some(self.grants.remove(index))
    }

    fn cleanup(&mut self) {
        let now = now_millis();
        self.grants.retain(|grant| grant.expires_at > now);
    }
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> ProcessIdentity {
        ProcessIdentity {
            pid: 42,
            ppid: 1,
            started_at: "start".into(),
            executable: "/bin/tool".into(),
            command: "tool".into(),
        }
    }

    #[test]
    fn matches_secret_and_group_scopes() {
        let mut grants = GrantStore::default();
        grants
            .add(GrantScope::Group, "aws-read-only".into(), process(), 30)
            .unwrap();
        assert!(
            grants
                .find("aws/key", Some("aws-read-only"), &[process()])
                .is_some()
        );
        assert!(
            grants
                .find("aws/key", Some("aws-admin"), &[process()])
                .is_none()
        );
    }

    #[test]
    fn a_grant_for_an_ancestor_matches_its_descendants() {
        let ancestor = process();
        let mut child = process();
        child.pid = 43;
        child.ppid = ancestor.pid;
        child.started_at = "child-start".into();
        child.executable = "/bin/child".into();
        let mut grants = GrantStore::default();
        grants
            .add(GrantScope::Secret, "token".into(), ancestor.clone(), 30)
            .unwrap();

        assert!(grants.find("token", None, &[child, ancestor]).is_some());
    }
}
