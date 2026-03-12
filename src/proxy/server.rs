use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::mux::{MuxStream, Session};
use crate::socks5::Address;

use super::protocol::*;

pub struct Server {
    session: Session,
    copy_buf_size: usize,
}

impl Server {
    pub fn new(session: Session, copy_buf_size: usize) -> Self {
        Self {
            session,
            copy_buf_size,
        }
    }

    pub async fn serve(&self) {
        loop {
            let stream = match self.session.accept_stream().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let buf_size = self.copy_buf_size;
            tokio::spawn(async move {
                if let Err(e) = handle_stream(stream, buf_size).await {
                    tracing::warn!("proxy stream: {}", e);
                }
            });
        }
    }
}

async fn handle_stream(stream: MuxStream, buf_size: usize) -> Result<()> {
    let hdr = read_stream_header(&stream).await?;

    let proto = if hdr.stream_type == STREAM_TCP {
        "tcp"
    } else {
        "udp"
    };
    tracing::debug!("[proxy-srv] {} -> {}", proto, hdr.dst);

    if is_blocked(&hdr.dst) {
        return Err(anyhow::anyhow!("blocked destination: {}", hdr.dst));
    }

    match hdr.stream_type {
        STREAM_TCP => handle_tcp(stream, hdr.dst, buf_size).await,
        STREAM_UDP => handle_udp(stream, hdr.dst).await,
        _ => Ok(()),
    }
}

fn is_blocked(addr: &Address) -> bool {
    match addr {
        Address::Ipv4(ip, _) => is_blocked_v4(*ip),
        Address::Ipv6(ip, _) => is_blocked_v6(*ip),
        Address::Domain(_, _) => false,
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || is_cgnat(ip)
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let segs = ip.segments();
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(v4);
    }
    false
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && o[1] >= 64 && o[1] <= 127
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

async fn resolve_addr(dst: &Address) -> Result<SocketAddr> {
    match dst {
        Address::Ipv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(*ip), *port)),
        Address::Ipv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(*ip), *port)),
        Address::Domain(host, port) => {
            let addr_str = format!("{}:{}", host, port);
            let resolved =
                tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(&addr_str))
                    .await
                    .map_err(|_| anyhow::anyhow!("dns resolve timeout: {}", host))??
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("dns resolve failed: {}", host))?;
            Ok(resolved)
        }
    }
}

async fn handle_tcp(stream: MuxStream, dst: Address, buf_size: usize) -> Result<()> {
    let addr = resolve_addr(&dst).await?;
    if is_blocked_ip(addr.ip()) {
        return Err(anyhow::anyhow!("blocked destination: {}", dst));
    }
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
    let _ = tcp.set_nodelay(true);
    tracing::debug!("[proxy-srv] tcp connected -> {}", dst);
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let stream = Arc::new(stream);

    let s1 = stream.clone();
    let s2 = stream.clone();

    let stream_to_tcp = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            match s1.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    });

    let tcp_to_stream = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s2.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = s2.shutdown_write().await;
    });

    let _ = tokio::join!(stream_to_tcp, tcp_to_stream);
    let _ = stream.close().await;
    Ok(())
}

async fn handle_udp(stream: MuxStream, dst: Address) -> Result<()> {
    let addr = resolve_addr(&dst).await?;
    if is_blocked_ip(addr.ip()) {
        return Err(anyhow::anyhow!("blocked destination: {}", dst));
    }
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;

    let idle_timeout = if addr.port() == 53 {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(60)
    };
    let buf_size = u16::MAX as usize;

    let stream = Arc::new(stream);
    let sock = Arc::new(sock);

    let s1 = stream.clone();
    let sock1 = sock.clone();

    let stream_to_udp = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            let mut len_buf = [0u8; 2];
            if read_exact(&s1, &mut len_buf).await.is_err() {
                break;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            if n > buf.len() {
                buf.resize(n, 0);
            }
            if read_exact(&s1, &mut buf[..n]).await.is_err() {
                break;
            }
            match tokio::time::timeout(idle_timeout, sock1.send(&buf[..n])).await {
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
    });

    let s2 = stream.clone();
    let sock2 = sock.clone();

    let udp_to_stream = tokio::spawn(async move {
        let mut buf = vec![0u8; 2 + buf_size];
        loop {
            let recv = tokio::time::timeout(idle_timeout, sock2.recv(&mut buf[2..])).await;
            match recv {
                Ok(Ok(n)) => {
                    buf[0] = (n >> 8) as u8;
                    buf[1] = (n & 0xff) as u8;
                    if s2.write(&buf[..2 + n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    let _ = tokio::join!(stream_to_udp, udp_to_stream);
    let _ = stream.close().await;
    Ok(())
}
