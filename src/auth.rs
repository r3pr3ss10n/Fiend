use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::mux;
use crate::transport::FakeTlsStream;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub version: u32,
    pub proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub proof: String,
}

pub async fn write_msg(w: &mut FakeTlsStream, msg: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec(msg)?;
    let len_buf = (data.len() as u32).to_be_bytes();
    w.write_all(&len_buf)
        .await
        .map_err(|e| anyhow!("write msg len: {}", e))?;
    w.write_all(&data)
        .await
        .map_err(|e| anyhow!("write msg data: {}", e))?;
    Ok(())
}

pub async fn read_msg<T: DeserializeOwned>(r: &mut FakeTlsStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|e| anyhow!("read msg len: {}", e))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 65536 {
        return Err(anyhow!("message too large: {}", n));
    }
    let mut data = vec![0u8; n];
    r.read_exact(&mut data)
        .await
        .map_err(|e| anyhow!("read msg data: {}", e))?;
    Ok(serde_json::from_slice(&data)?)
}

pub fn smux_config() -> mux::Config {
    mux::Config {
        version: 2,
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_secs(10),
        keep_alive_timeout: Duration::from_secs(30),
        max_frame_size: 65535,
        max_receive_buffer: 32 * 1024 * 1024,
        max_stream_buffer: 8 * 1024 * 1024,
    }
}
