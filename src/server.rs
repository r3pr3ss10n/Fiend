use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::auth;
use crate::crypto::{auth_proof, verify_auth_proof};
use crate::mux;
use crate::proxy;
use crate::transport;
use crate::transport::disguise::replay::ReplayGuard;

const MAX_CONCURRENT_FORWARDS: usize = 32;
const MAX_CONNECTIONS: usize = 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    replay: Arc<ReplayGuard>,
    forward_limit: Arc<Semaphore>,
    conn_limit: Arc<Semaphore>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            replay: Arc::new(ReplayGuard::new(Duration::from_secs(5 * 60))),
            forward_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARDS)),
            conn_limit: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    pub async fn listen(&self, addr: &str, secret: &[u8], domain: &str, psk: &[u8]) -> Result<()> {
        let sock_addr: SocketAddr = addr
            .parse()
            .map_err(|e| anyhow!("parse bind addr: {}", e))?;

        let socket = transport::new_tcp_socket(sock_addr)?;
        socket
            .set_reuseaddr(true)
            .map_err(|e| anyhow!("reuseaddr: {}", e))?;
        socket.bind(sock_addr).map_err(|e| anyhow!("bind: {}", e))?;
        let listener = socket.listen(1024).map_err(|e| anyhow!("listen: {}", e))?;

        loop {
            let (stream, addr) = listener.accept().await?;
            let permit = match self.conn_limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("connection limit reached, dropping {}", addr);
                    continue;
                }
            };
            let secret = secret.to_vec();
            let domain = domain.to_string();
            let psk = psk.to_vec();
            let replay = self.replay.clone();
            let forward_limit = self.forward_limit.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_conn(
                    stream,
                    addr,
                    &secret,
                    &domain,
                    &psk,
                    &replay,
                    &forward_limit,
                )
                .await
                {
                    tracing::debug!("{}: {}", addr, e);
                }
                drop(permit);
            });
        }
    }
}

async fn handle_conn(
    raw: TcpStream,
    peer: SocketAddr,
    secret: &[u8],
    domain: &str,
    psk: &[u8],
    replay: &ReplayGuard,
    forward_limit: &Arc<Semaphore>,
) -> Result<()> {
    let mut tls = transport::accept(raw, secret, domain, replay, forward_limit).await?;

    let req: auth::AuthRequest = tokio::time::timeout(AUTH_TIMEOUT, auth::read_msg(&mut tls))
        .await
        .map_err(|_| anyhow!("auth read timeout"))??;

    if req.version != 2 {
        return Err(anyhow!("unsupported version: {}", req.version));
    }

    if !verify_auth_proof(psk, "stw-auth", &req.proof) {
        return Err(anyhow!("auth failed"));
    }

    let resp = auth::AuthResponse {
        proof: auth_proof(psk, "stw-auth-ok"),
    };
    auth::write_msg(&mut tls, &resp).await?;

    tracing::info!("[session] new from {}", peer);

    let (br, bw) = transport::bridge(tls);
    let session = mux::server(br, bw, auth::smux_config())?;
    let srv = proxy::server::Server::new(session, proxy::protocol::COPY_BUF);
    srv.serve().await;

    tracing::info!("[session] ended ({})", peer);
    Ok(())
}
