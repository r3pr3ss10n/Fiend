use anyhow::{Result, anyhow};
use socket2::SockRef;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::Semaphore;

use super::disguise::replay::ReplayGuard;
use super::disguise::tls::{self, FakeTlsStream};

const TCP_BUFFER_SIZE: u32 = 4 * 1024 * 1024;

pub async fn dial(
    addr: &str,
    secret: &[u8],
    template: &crate::fingerprint::FingerprintTemplate,
) -> Result<FakeTlsStream> {
    let sock_addr: SocketAddr = addr.parse().map_err(|e| anyhow!("parse addr: {}", e))?;

    let socket = new_tcp_socket(sock_addr)?;
    let stream = socket
        .connect(sock_addr)
        .await
        .map_err(|e| anyhow!("tcp dial: {}", e))?;

    post_configure(&stream);
    set_tcp_congestion(&stream, "bbr");

    tls::client_tls_templated(stream, secret, template).await
}

pub async fn accept(
    stream: TcpStream,
    secret: &[u8],
    domain: &str,
    guard: &ReplayGuard,
    forward_limit: &Arc<Semaphore>,
) -> Result<FakeTlsStream> {
    post_configure(&stream);
    set_tcp_congestion(&stream, "bbr");

    tls::server_tls(stream, secret, domain, guard, forward_limit).await
}

pub fn new_tcp_socket(addr: SocketAddr) -> Result<TcpSocket> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| anyhow!("create socket: {}", e))?;

    let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);

    Ok(socket)
}

fn post_configure(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(10));
    let _ = sock.set_tcp_keepalive(&keepalive);
}

#[cfg(target_os = "linux")]
fn set_tcp_congestion(stream: &TcpStream, algo: &str) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let ret = unsafe { libc_setsockopt(fd, 6, 13, algo.as_ptr().cast(), algo.len() as u32) };
    if ret != 0 {
        tracing::warn!(
            "setsockopt TCP_CONGESTION: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    #[link_name = "setsockopt"]
    fn libc_setsockopt(
        socket: i32,
        level: i32,
        optname: i32,
        optval: *const std::ffi::c_void,
        optlen: u32,
    ) -> i32;
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_congestion(_stream: &TcpStream, _algo: &str) {}
