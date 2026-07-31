use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    controller::{Controller, RequestOutcome, RequestResolution},
    paths::ensure_parent,
    process::{inspect_process_tree, verify_connection_owner},
};

use super::protocol::{EndpointFile, GetRequest};

const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MAX_CONNECTIONS: usize = 64;

pub struct RequestServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    runtime_path: PathBuf,
}

impl RequestServer {
    pub fn start(
        controller: Arc<Mutex<Controller>>,
        runtime_path: PathBuf,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("Could not start request server: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let mut token_bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(token_bytes.as_mut()).map_err(|error| error.to_string())?;
        let token = BASE64.encode(token_bytes.as_slice());
        write_endpoint(
            &runtime_path,
            &EndpointFile {
                version: 1,
                host: "127.0.0.1".into(),
                port,
                token: token.clone(),
            },
        )?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::Builder::new()
            .name("secretd-request-server".into())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((connection, _)) => {
                            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                                active.fetch_sub(1, Ordering::AcqRel);
                                let _ = write_response(
                                    connection,
                                    json!({"ok": false, "error": "Too many pending requests"}),
                                );
                                continue;
                            }
                            let controller = Arc::clone(&controller);
                            let token = token.clone();
                            let notify = Arc::clone(&notify);
                            let active = Arc::clone(&active);
                            let _ = thread::Builder::new().name("secretd-request".into()).spawn(
                                move || {
                                    let _guard = ActiveConnection(active);
                                    handle_connection(connection, &token, &controller, &notify);
                                },
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            eprintln!("secretd request listener: {error}");
                            break;
                        }
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
            runtime_path,
        })
    }

    pub fn close(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.runtime_path);
    }
}

impl Drop for RequestServer {
    fn drop(&mut self) {
        self.close();
    }
}

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_connection(
    mut connection: TcpStream,
    token: &str,
    controller: &Arc<Mutex<Controller>>,
    notify: &Arc<dyn Fn() + Send + Sync>,
) {
    let result = (|| -> Result<Zeroizing<String>, String> {
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let request = read_request(&mut connection)?;
        if !constant_time_equal(&request.token, token) {
            return Err("Authentication failed".into());
        }
        if request.version != 1
            || request.action != "get"
            || request.pid == 0
            || request.secret.is_empty()
        {
            return Err("Invalid request".into());
        }
        let verified = verify_connection_owner(request.pid, &connection);
        let tree = inspect_process_tree(request.pid, 12)?;
        if tree.is_empty() {
            return Err("Unable to inspect the requesting process".into());
        }
        let outcome = controller
            .lock()
            .map_err(|_| "SecretD state is unavailable".to_string())?
            .begin_request(&request.secret, tree, verified)
            .map_err(|error| error.to_string())?;
        match outcome {
            RequestOutcome::Immediate(value) => Ok(value),
            RequestOutcome::Pending { id, receiver } => {
                notify();
                match receiver.recv_timeout(REQUEST_TIMEOUT) {
                    Ok(RequestResolution::Approved) => {
                        let value = controller
                            .lock()
                            .map_err(|_| "SecretD state is unavailable".to_string())?
                            .release_after_approval(&request.secret)
                            .map_err(|error| error.to_string());
                        notify();
                        value
                    }
                    Ok(RequestResolution::Denied) => {
                        notify();
                        Err("Request denied or timed out".into())
                    }
                    Ok(RequestResolution::Failed(error)) => {
                        notify();
                        Err(error)
                    }
                    Err(_) => {
                        if let Ok(mut controller) = controller.lock() {
                            controller.timeout_request(&id);
                        }
                        notify();
                        Err("Request denied or timed out".into())
                    }
                }
            }
        }
    })();

    match result {
        Ok(value) => {
            let _ = write_response(connection, json!({"ok": true, "value": &*value}));
        }
        Err(error) => {
            let _ = write_response(connection, json!({"ok": false, "error": error}));
        }
    }
}

fn read_request(connection: &mut TcpStream) -> Result<GetRequest, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    BufReader::new(connection)
        .take(MAX_REQUEST_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "Invalid request".to_string())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("Request is too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid request".into())
}

fn write_response(mut connection: TcpStream, value: serde_json::Value) -> Result<(), String> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(&value).map_err(|error| error.to_string())?);
    bytes.push(b'\n');
    connection
        .write_all(&bytes)
        .map_err(|error| error.to_string())
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(left.get(index).copied().unwrap_or(0))
            ^ usize::from(right.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

fn write_endpoint(path: &Path, endpoint: &EndpointFile) -> Result<(), String> {
    let directory = ensure_parent(path)?;
    create_private_directory(directory).map_err(|error| error.to_string())?;
    let temporary = directory.join(format!(".secretd-runtime-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        let mut bytes = serde_json::to_vec(endpoint).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_checks_length_and_contents() {
        assert!(constant_time_equal("abc", "abc"));
        assert!(!constant_time_equal("abc", "abd"));
        assert!(!constant_time_equal("abc", "abcx"));
    }
}
