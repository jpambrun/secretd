use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EndpointFile {
    pub version: u8,
    pub host: String,
    pub port: u16,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetRequest {
    pub version: u8,
    pub token: String,
    pub action: String,
    pub secret: String,
    pub pid: u32,
}

#[derive(Debug, Deserialize)]
pub struct GetResponse {
    pub ok: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}
