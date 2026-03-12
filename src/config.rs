use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

fn default_listen() -> String {
    "127.0.0.1:1080".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: String,
    pub key: String,
    pub fingerprint: String,
    #[serde(default = "default_listen")]
    pub listen: String,
}

fn default_bind() -> String {
    "0.0.0.0:443".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    pub key: String,
    #[serde(default)]
    pub disguise: String,
    pub fingerprint: Option<String>,
}

impl ClientConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read client config")?;
        let cfg: Self = serde_json::from_str(&content).context("Failed to parse client JSON")?;

        if cfg.server.is_empty() {
            return Err(anyhow!("server is required"));
        }

        if cfg.key.is_empty() {
            return Err(anyhow!("key is required"));
        }

        if cfg.fingerprint.is_empty() {
            return Err(anyhow!("fingerprint is required"));
        }

        Ok(cfg)
    }
}

impl ServerConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read server config")?;
        let cfg: Self = serde_json::from_str(&content).context("Failed to parse server JSON")?;

        if cfg.bind.is_empty() {
            return Err(anyhow!("bind is required"));
        }

        if cfg.key.is_empty() {
            return Err(anyhow!("key is required"));
        }

        if cfg.disguise.is_empty() && cfg.fingerprint.is_none() {
            return Err(anyhow!("either disguise or fingerprint is required"));
        }

        Ok(cfg)
    }
}
