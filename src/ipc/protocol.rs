use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EndpointFile {
    pub version: u8,
    pub host: String,
    pub port: u16,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientRequest {
    pub version: u8,
    pub token: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub pid: u32,
}

#[derive(Debug, Deserialize)]
pub struct ClientResponse {
    pub ok: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}
