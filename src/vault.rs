use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{SecondsFormat, Utc};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::paths::ensure_parent;

pub const VAULT_VERSION: u8 = 1;
pub const PBKDF2_ITERATIONS: u32 = 600_000;
pub const MIN_MASTER_PASSWORD_LENGTH: usize = 7;
const MAX_VAULT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultError(pub String);

impl std::fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for VaultError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretSummary {
    pub name: String,
    pub group: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultEntry {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    created_at: String,
    updated_at: String,
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultPlaintext {
    version: u8,
    revision: u64,
    secrets: BTreeMap<String, VaultEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultFile {
    version: u8,
    kdf: KdfHeader,
    cipher: CipherHeader,
    ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct KdfHeader {
    name: String,
    hash: String,
    iterations: u32,
    salt: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CipherHeader {
    name: String,
    iv: String,
}

pub struct VaultStore {
    pub path: PathBuf,
    key: Option<Zeroizing<[u8; 32]>>,
    salt: Option<Zeroizing<Vec<u8>>>,
    iterations: u32,
    data: Option<VaultPlaintext>,
}

impl VaultStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            key: None,
            salt: None,
            iterations: PBKDF2_ITERATIONS,
            data: None,
        }
    }

    pub fn unlocked(&self) -> bool {
        self.key.is_some() && self.salt.is_some() && self.data.is_some()
    }

    pub fn exists(&self) -> Result<bool, VaultError> {
        match fs::metadata(&self.path) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(VaultError(error.to_string())),
        }
    }

    pub fn create(&mut self, password: &str) -> Result<(), VaultError> {
        validate_password(password)?;
        if self.exists()? {
            return Err(VaultError("Vault already exists".into()));
        }
        let mut salt = Zeroizing::new(vec![0_u8; 16]);
        getrandom::fill(&mut salt).map_err(|error| VaultError(error.to_string()))?;
        let key = derive_key(password, &salt, PBKDF2_ITERATIONS)?;
        let data = VaultPlaintext {
            version: VAULT_VERSION,
            revision: 0,
            secrets: BTreeMap::new(),
        };
        save_with(&self.path, &data, &key, &salt, PBKDF2_ITERATIONS)?;
        self.key = Some(key);
        self.salt = Some(salt);
        self.iterations = PBKDF2_ITERATIONS;
        self.data = Some(data);
        Ok(())
    }

    pub fn unlock(&mut self, password: &str) -> Result<(), VaultError> {
        validate_password(password)?;
        let file = read_vault_file(&self.path)?;
        validate_header(&file)?;
        let salt = Zeroizing::new(
            BASE64
                .decode(&file.kdf.salt)
                .map_err(|_| VaultError("Vault salt is invalid".into()))?,
        );
        if salt.len() < 16 {
            return Err(VaultError("Vault salt is invalid".into()));
        }
        let iv = Zeroizing::new(
            BASE64
                .decode(&file.cipher.iv)
                .map_err(|_| VaultError("Vault IV is invalid".into()))?,
        );
        if iv.len() != 12 {
            return Err(VaultError("Vault IV is invalid".into()));
        }
        let ciphertext = Zeroizing::new(
            BASE64
                .decode(&file.ciphertext)
                .map_err(|_| VaultError("Vault ciphertext is invalid".into()))?,
        );
        let key = derive_key(password, &salt, file.kdf.iterations)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| VaultError("Vault key is invalid".into()))?;
        let aad = additional_data(&file);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    iv.as_slice().into(),
                    Payload {
                        msg: &ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| VaultError("Invalid password or corrupted vault".into()))?,
        );
        let data: VaultPlaintext = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError("Vault plaintext is invalid".into()))?;
        validate_plaintext(&data)?;
        self.key = Some(key);
        self.salt = Some(salt);
        self.iterations = file.kdf.iterations;
        self.data = Some(data);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.key = None;
        self.salt = None;
        self.iterations = PBKDF2_ITERATIONS;
        self.data = None;
    }

    pub fn list(&self) -> Result<Vec<SecretSummary>, VaultError> {
        let data = self.require_data()?;
        Ok(data
            .secrets
            .iter()
            .map(|(name, entry)| SecretSummary {
                name: name.clone(),
                group: entry.group.clone(),
                created_at: entry.created_at.clone(),
                updated_at: entry.updated_at.clone(),
            })
            .collect())
    }

    pub fn reveal(&self, name: &str) -> Result<Zeroizing<String>, VaultError> {
        let normalized = normalize_secret_name(name)?;
        self.require_data()?
            .secrets
            .get(&normalized)
            .map(|entry| Zeroizing::new(entry.value.clone()))
            .ok_or_else(|| VaultError("Secret not found".into()))
    }

    pub fn group(&self, name: &str) -> Result<Option<String>, VaultError> {
        let normalized = normalize_secret_name(name)?;
        self.require_data()?
            .secrets
            .get(&normalized)
            .map(|entry| entry.group.clone())
            .ok_or_else(|| VaultError("Secret not found".into()))
    }

    pub fn save_secret(
        &mut self,
        name: &str,
        value: &str,
        group: Option<&str>,
    ) -> Result<(), VaultError> {
        let normalized = normalize_secret_name(name)?;
        let normalized_group = match group {
            Some(value) => normalize_secret_group(value)?,
            None => self
                .require_data()?
                .secrets
                .get(&normalized)
                .and_then(|entry| entry.group.clone()),
        };
        let now = now();
        let data = self.require_data_mut()?;
        let created_at = data
            .secrets
            .get(&normalized)
            .map_or_else(|| now.clone(), |entry| entry.created_at.clone());
        data.secrets.insert(
            normalized,
            VaultEntry {
                value: value.into(),
                group: normalized_group,
                created_at,
                updated_at: now,
            },
        );
        data.revision = data.revision.saturating_add(1);
        self.save()
    }

    pub fn rename(&mut self, old_name: &str, new_name: &str) -> Result<(), VaultError> {
        let old = normalize_secret_name(old_name)?;
        let new = normalize_secret_name(new_name)?;
        let data = self.require_data_mut()?;
        if old != new && data.secrets.contains_key(&new) {
            return Err(VaultError("A secret with that name already exists".into()));
        }
        let Some(mut entry) = data.secrets.remove(&old) else {
            return Err(VaultError("Secret not found".into()));
        };
        entry.updated_at = now();
        data.secrets.insert(new, entry);
        data.revision = data.revision.saturating_add(1);
        self.save()
    }

    pub fn delete(&mut self, name: &str) -> Result<(), VaultError> {
        let normalized = normalize_secret_name(name)?;
        let data = self.require_data_mut()?;
        if data.secrets.remove(&normalized).is_none() {
            return Err(VaultError("Secret not found".into()));
        }
        data.revision = data.revision.saturating_add(1);
        self.save()
    }

    pub fn change_password(&mut self, password: &str) -> Result<(), VaultError> {
        validate_password(password)?;
        let mut salt = Zeroizing::new(vec![0_u8; 16]);
        getrandom::fill(&mut salt).map_err(|error| VaultError(error.to_string()))?;
        let key = derive_key(password, &salt, PBKDF2_ITERATIONS)?;
        save_with(
            &self.path,
            self.require_data()?,
            &key,
            &salt,
            PBKDF2_ITERATIONS,
        )?;
        self.key = Some(key);
        self.salt = Some(salt);
        self.iterations = PBKDF2_ITERATIONS;
        Ok(())
    }

    fn require_data(&self) -> Result<&VaultPlaintext, VaultError> {
        if !self.unlocked() {
            return Err(VaultError("Vault is locked".into()));
        }
        Ok(self.data.as_ref().expect("unlocked vault has data"))
    }

    fn require_data_mut(&mut self) -> Result<&mut VaultPlaintext, VaultError> {
        if !self.unlocked() {
            return Err(VaultError("Vault is locked".into()));
        }
        Ok(self.data.as_mut().expect("unlocked vault has data"))
    }

    fn save(&self) -> Result<(), VaultError> {
        save_with(
            &self.path,
            self.require_data()?,
            self.key.as_ref().expect("unlocked vault has key"),
            self.salt.as_ref().expect("unlocked vault has salt"),
            self.iterations,
        )
    }
}

pub fn normalize_secret_name(name: &str) -> Result<String, VaultError> {
    let normalized = name.trim().replace('\\', "/");
    if normalized.is_empty() || normalized.chars().count() > 256 {
        return Err(VaultError("Secret name is invalid".into()));
    }
    if normalized.chars().any(char::is_control) {
        return Err(VaultError("Secret name contains control characters".into()));
    }
    for segment in normalized.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(VaultError(
                "Secret name contains an invalid path segment".into(),
            ));
        }
        if matches!(segment, "__proto__" | "prototype" | "constructor") {
            return Err(VaultError(
                "Secret name contains a reserved path segment".into(),
            ));
        }
    }
    Ok(normalized)
}

pub fn normalize_secret_group(group: &str) -> Result<Option<String>, VaultError> {
    let normalized = group.trim();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.chars().count() > 128 || normalized.chars().any(char::is_control) {
        return Err(VaultError("Secret group is invalid".into()));
    }
    Ok(Some(normalized.into()))
}

fn validate_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
        return Err(VaultError(format!(
            "Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters"
        )));
    }
    Ok(())
}

fn derive_key(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if !(100_000..=10_000_000).contains(&iterations) {
        return Err(VaultError("Vault KDF parameters are invalid".into()));
    }
    let password = Zeroizing::new(password.as_bytes().to_vec());
    let mut key = Zeroizing::new([0_u8; 32]);
    pbkdf2_hmac::<Sha256>(&password, salt, iterations, key.as_mut());
    Ok(key)
}

fn validate_header(file: &VaultFile) -> Result<(), VaultError> {
    if file.version != VAULT_VERSION
        || file.kdf.name != "PBKDF2"
        || file.kdf.hash != "SHA-256"
        || !(100_000..=10_000_000).contains(&file.kdf.iterations)
        || file.cipher.name != "AES-GCM"
    {
        return Err(VaultError("Vault file has an unsupported format".into()));
    }
    Ok(())
}

fn validate_plaintext(data: &VaultPlaintext) -> Result<(), VaultError> {
    if data.version != VAULT_VERSION {
        return Err(VaultError(
            "Vault plaintext has an unsupported format".into(),
        ));
    }
    for (name, entry) in &data.secrets {
        normalize_secret_name(name)?;
        if let Some(group) = &entry.group {
            normalize_secret_group(group)?;
        }
    }
    Ok(())
}

fn additional_data(file: &VaultFile) -> String {
    format!(
        "secretd:{}:{}:{}:{}:{}",
        file.version, file.kdf.name, file.kdf.hash, file.kdf.iterations, file.kdf.salt
    )
}

fn read_vault_file(path: &Path) -> Result<VaultFile, VaultError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VaultError("Vault does not exist".into())
        } else {
            VaultError(error.to_string())
        }
    })?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES {
        return Err(VaultError("Vault file is invalid".into()));
    }
    let bytes = fs::read(path).map_err(|error| VaultError(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| VaultError("Vault file is not valid JSON".into()))
}

fn save_with(
    path: &Path,
    data: &VaultPlaintext,
    key: &[u8; 32],
    salt: &[u8],
    iterations: u32,
) -> Result<(), VaultError> {
    let mut iv = Zeroizing::new([0_u8; 12]);
    getrandom::fill(iv.as_mut()).map_err(|error| VaultError(error.to_string()))?;
    let mut file = VaultFile {
        version: VAULT_VERSION,
        kdf: KdfHeader {
            name: "PBKDF2".into(),
            hash: "SHA-256".into(),
            iterations,
            salt: BASE64.encode(salt),
        },
        cipher: CipherHeader {
            name: "AES-GCM".into(),
            iv: BASE64.encode(iv.as_slice()),
        },
        ciphertext: String::new(),
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(data)
            .map_err(|error| VaultError(format!("Could not encode vault: {error}")))?,
    );
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| VaultError("Vault key is invalid".into()))?;
    let aad = additional_data(&file);
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                iv.as_slice().into(),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| VaultError("Could not encrypt vault".into()))?,
    );
    file.ciphertext = BASE64.encode(ciphertext.as_slice());
    let mut contents = serde_json::to_vec_pretty(&file)
        .map_err(|error| VaultError(format!("Could not encode vault: {error}")))?;
    contents.push(b'\n');
    atomic_write(path, &contents)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let directory = ensure_parent(path).map_err(VaultError)?;
    create_private_directory(directory).map_err(|error| VaultError(error.to_string()))?;
    let temporary = directory.join(format!(".secretd-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&temporary)
            .map_err(|error| VaultError(error.to_string()))?;
        output
            .write_all(contents)
            .and_then(|()| output.sync_all())
            .map_err(|error| VaultError(error.to_string()))?;
        fs::rename(&temporary, path).map_err(|error| VaultError(error.to_string()))?;
        #[cfg(unix)]
        {
            if let Ok(directory_file) = fs::File::open(directory) {
                let _ = directory_file.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_vault_and_changes_password() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.json");
        let mut vault = VaultStore::new(path.clone());
        vault.create("correct horse").unwrap();
        vault
            .save_secret(" services/example ", "very secret", Some(" read-only "))
            .unwrap();
        vault.lock();

        let mut reopened = VaultStore::new(path);
        reopened.unlock("correct horse").unwrap();
        assert_eq!(
            &*reopened.reveal("services/example").unwrap(),
            "very secret"
        );
        assert_eq!(
            reopened.group("services/example").unwrap().as_deref(),
            Some("read-only")
        );
        reopened.change_password("different horse").unwrap();
        reopened.lock();
        assert!(reopened.unlock("correct horse").is_err());
        reopened.unlock("different horse").unwrap();
    }

    #[test]
    fn opens_vault_written_by_deno_implementation() {
        const DENO_VAULT: &str = r#"{
  "version": 1,
  "kdf": {
    "name": "PBKDF2",
    "hash": "SHA-256",
    "iterations": 600000,
    "salt": "7nERh6PROz5ZPgpoZFBBwQ=="
  },
  "cipher": {
    "name": "AES-GCM",
    "iv": "KEsN6BDULJzxvHeX"
  },
  "ciphertext": "SKwkmOrsPmaNtzwGvqP4bkSEhtHIwUENc3vUyMM6yrge6TjiWT2+gjG6hWEyhIyoFM8i129i8SIzzloMhrEiFvqVlcmyOF2jxsN0F6iRcAsFWP+Ja+1CX/RcjaOqjL0igL+lFtMcFHaBSLXQqzjRlBw9vDzJ6MXbMZlXl9NDnp5CB4bawuHb9GMzwihcIsVDnmUp1eTPvskNkHLXn9b2m/XEZs8B5LYjnsIu0sKSsh+oOX2i0uWD8xiF0ykA4cxrpX+E1RXqbEoaeYhApz+awyz51g=="
}"#;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.json");
        fs::write(&path, DENO_VAULT).unwrap();
        let mut vault = VaultStore::new(path);
        vault.unlock("correct horse").unwrap();
        assert_eq!(
            &*vault.reveal("services/github/token").unwrap(),
            "deno-secret"
        );
        assert_eq!(
            vault.group("services/github/token").unwrap().as_deref(),
            Some("deployment-read-only")
        );
    }

    #[test]
    fn rejects_invalid_names_and_groups() {
        assert_eq!(
            normalize_secret_name(" services/example ").unwrap(),
            "services/example"
        );
        for name in ["", "a//b", "a/../b", "a/__proto__/b", "a\nb"] {
            assert!(normalize_secret_name(name).is_err(), "{name}");
        }
        assert_eq!(
            normalize_secret_group(" read-only ").unwrap().as_deref(),
            Some("read-only")
        );
        assert_eq!(normalize_secret_group(" ").unwrap(), None);
    }
}
