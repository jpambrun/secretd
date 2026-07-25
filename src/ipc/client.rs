use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::Path,
    time::Duration,
};

use zeroize::Zeroizing;

use super::protocol::{EndpointFile, GetRequest, GetResponse};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

pub fn get_secret(runtime_path: &Path, secret: &str) -> Result<Zeroizing<String>, String> {
    let endpoint: EndpointFile = serde_json::from_slice(
        &fs::read(runtime_path).map_err(|_| "SecretD desktop is not running".to_string())?,
    )
    .map_err(|_| "SecretD runtime file is invalid".to_string())?;
    if endpoint.version != 1 || endpoint.host != "127.0.0.1" || endpoint.token.is_empty() {
        return Err("SecretD runtime file is invalid".into());
    }
    let mut connection = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .map_err(|error| format!("Could not connect to SecretD: {error}"))?;
    connection
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let request = GetRequest {
        version: 1,
        token: endpoint.token,
        action: "get".into(),
        secret: secret.into(),
        pid: std::process::id(),
    };
    let mut bytes = Zeroizing::new(
        serde_json::to_vec(&request).map_err(|_| "Could not encode secret request".to_string())?,
    );
    bytes.push(b'\n');
    connection
        .write_all(&bytes)
        .map_err(|error| format!("Could not send secret request: {error}"))?;
    let mut response = Zeroizing::new(Vec::new());
    BufReader::new(connection)
        .take(MAX_RESPONSE_BYTES)
        .read_until(b'\n', &mut response)
        .map_err(|error| format!("Could not read SecretD response: {error}"))?;
    if response.is_empty() {
        return Err("SecretD closed the request".into());
    }
    let parsed: GetResponse = serde_json::from_slice(&response)
        .map_err(|_| "SecretD returned an invalid response".to_string())?;
    if parsed.ok {
        return parsed
            .value
            .map(Zeroizing::new)
            .ok_or_else(|| "SecretD returned an invalid response".to_string());
    }
    Err(parsed
        .error
        .unwrap_or_else(|| "Secret request failed".into()))
}
