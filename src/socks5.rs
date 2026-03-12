use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use crate::mux::{MuxStream, Session};
use crate::proxy;

const SOCKS5_VER: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ipv4(ip, port) => write!(f, "{}:{}", ip, port),
            Address::Ipv6(ip, port) => write!(f, "[{}]:{}", ip, port),
            Address::Domain(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

pub async fn listen(addr: &str, session: Session) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("socks5 listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let session = session.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, session).await {
                tracing::debug!("[socks5] {}: {}", peer, e);
            }
        });
    }
}

async fn handle_client(mut stream: TcpStream, session: Session) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(&stream);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let mut buf = [0u8; 258];
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != SOCKS5_VER {
        return Err(anyhow!("not socks5"));
    }
    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    if !buf[..nmethods].contains(&AUTH_NONE) {
        stream.write_all(&[SOCKS5_VER, 0xFF]).await?;
        return Err(anyhow!("no acceptable auth method"));
    }
    stream.write_all(&[SOCKS5_VER, AUTH_NONE]).await?;

    stream.read_exact(&mut buf[..4]).await?;
    if buf[0] != SOCKS5_VER {
        return Err(anyhow!("invalid request version"));
    }
    let cmd = buf[1];
    let atyp = buf[3];

    let dst = read_address(&mut stream, atyp).await?;

    match cmd {
        CMD_CONNECT => handle_connect(stream, session, dst).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(stream, session).await,
        _ => {
            send_reply(
                &mut stream,
                REP_CMD_NOT_SUPPORTED,
                &Address::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await?;
            Err(anyhow!("unsupported cmd: 0x{:02x}", cmd))
        }
    }
}

async fn read_address(stream: &mut TcpStream, atyp: u8) -> Result<Address> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Address::Ipv4(ip, port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len + 2];
            stream.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf[..len].to_vec())?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            Ok(Address::Domain(domain, port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&buf[..16]).map_err(|_| anyhow!("invalid ipv6"))?,
            );
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Address::Ipv6(ip, port))
        }
        _ => Err(anyhow!("unsupported atyp: 0x{:02x}", atyp)),
    }
}

async fn send_reply(stream: &mut TcpStream, rep: u8, bind: &Address) -> Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.extend_from_slice(&[SOCKS5_VER, rep, 0x00]);
    match bind {
        Address::Ipv4(ip, port) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6(ip, port) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain(host, port) => {
            if host.len() > 255 {
                return Err(anyhow!("domain name too long"));
            }
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&buf).await?;
    Ok(())
}

async fn handle_connect(mut stream: TcpStream, session: Session, dst: Address) -> Result<()> {
    tracing::debug!("[socks5] CONNECT -> {}", dst);

    let mux_stream = match session.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            send_reply(
                &mut stream,
                REP_GENERAL_FAILURE,
                &Address::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await?;
            return Err(e);
        }
    };

    if let Err(e) = proxy::protocol::write_stream_header(&mux_stream, &dst).await {
        send_reply(
            &mut stream,
            REP_GENERAL_FAILURE,
            &Address::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
        )
        .await?;
        return Err(e);
    }

    send_reply(
        &mut stream,
        REP_SUCCESS,
        &Address::Ipv4(Ipv4Addr::UNSPECIFIED, 0),
    )
    .await?;

    let mux_stream = Arc::new(mux_stream);
    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let buf_size = proxy::protocol::COPY_BUF;

    let s1 = mux_stream.clone();
    let tcp_to_mux = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s1.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = s1.shutdown_write().await;
    });

    let s2 = mux_stream.clone();
    let mux_to_tcp = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            match s2.read(&mut buf).await {
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

    let _ = tokio::join!(tcp_to_mux, mux_to_tcp);
    let _ = mux_stream.close().await;
    Ok(())
}

async fn handle_udp_associate(mut stream: TcpStream, session: Session) -> Result<()> {
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let relay_addr = relay.local_addr()?;
    tracing::debug!("[socks5] UDP ASSOCIATE relay={}", relay_addr);

    let bind_addr = match relay_addr {
        SocketAddr::V4(a) => Address::Ipv4(*a.ip(), a.port()),
        SocketAddr::V6(a) => Address::Ipv6(*a.ip(), a.port()),
    };
    send_reply(&mut stream, REP_SUCCESS, &bind_addr).await?;

    let relay = Arc::new(relay);
    let streams: Arc<Mutex<HashMap<Address, Arc<MuxStream>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let r = relay.clone();
    let s = session.clone();
    let st = streams.clone();
    let ca = client_addr.clone();

    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = match r.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };

            {
                let mut addr = ca.lock().await;
                if addr.is_none() {
                    *addr = Some(from);
                }
            }

            if n < 4 {
                continue;
            }

            let frag = buf[2];
            if frag != 0 {
                continue;
            }

            let _atyp = buf[3];
            let (dst, header_len) = match parse_udp_header(&buf[3..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let payload = &buf[3 + header_len..n];
            if payload.is_empty() {
                continue;
            }

            let existing = { st.lock().await.get(&dst).cloned() };
            let mux_stream = if let Some(s) = existing {
                s
            } else {
                let ms = match s.open_stream().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("[socks5] udp open_stream failed: {}", e);
                        continue;
                    }
                };
                if proxy::protocol::write_stream_header_udp(&ms, &dst)
                    .await
                    .is_err()
                {
                    continue;
                }

                let ms = Arc::new(ms);
                let mut map = st.lock().await;
                if let Some(existing) = map.get(&dst) {
                    let existing = existing.clone();
                    drop(map);
                    let _ = ms.close().await;
                    existing
                } else {
                    map.insert(dst.clone(), ms.clone());

                    let r2 = r.clone();
                    let ms2 = ms.clone();
                    let ca2 = ca.clone();
                    let dst2 = dst.clone();
                    let st2 = st.clone();
                    tokio::spawn(async move {
                        udp_read_loop(r2, ms2, ca2, dst2, st2).await;
                    });

                    drop(map);
                    ms
                }
            };

            let len = payload.len();
            let mut frame = Vec::with_capacity(2 + len);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
            frame.extend_from_slice(payload);
            if mux_stream.write(&frame).await.is_err() {
                st.lock().await.remove(&dst);
            }
        }
    });

    let mut ping = [0u8; 1];
    tokio::select! {
        _ = stream.read(&mut ping) => {}
        _ = session.closed() => {}
    }

    udp_task.abort();

    let to_close: Vec<_> = streams.lock().await.drain().map(|(_, s)| s).collect();
    for s in to_close {
        let _ = s.close().await;
    }

    Ok(())
}

fn parse_udp_header(buf: &[u8]) -> Result<(Address, usize)> {
    if buf.is_empty() {
        return Err(anyhow!("empty header"));
    }
    let atyp = buf[0];
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 7 {
                return Err(anyhow!("short ipv4"));
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Address::Ipv4(ip, port), 7))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Err(anyhow!("short domain"));
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(anyhow!("short domain data"));
            }
            let domain = String::from_utf8(buf[2..2 + len].to_vec())?;
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((Address::Domain(domain, port), 2 + len + 2))
        }
        ATYP_IPV6 => {
            if buf.len() < 19 {
                return Err(anyhow!("short ipv6"));
            }
            let ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&buf[1..17]).map_err(|_| anyhow!("invalid ipv6"))?,
            );
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Address::Ipv6(ip, port), 19))
        }
        _ => Err(anyhow!("unknown atyp: 0x{:02x}", atyp)),
    }
}

async fn udp_read_loop(
    relay: Arc<UdpSocket>,
    mux_stream: Arc<MuxStream>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    dst: Address,
    streams: Arc<Mutex<HashMap<Address, Arc<MuxStream>>>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let mut len_buf = [0u8; 2];
        if proxy::protocol::read_exact(&mux_stream, &mut len_buf)
            .await
            .is_err()
        {
            break;
        }
        let n = u16::from_be_bytes(len_buf) as usize;
        if n > buf.len() {
            buf.resize(n, 0);
        }
        if proxy::protocol::read_exact(&mux_stream, &mut buf[..n])
            .await
            .is_err()
        {
            break;
        }

        let client = { *client_addr.lock().await };
        let Some(client) = client else { continue };

        let mut packet = Vec::with_capacity(3 + 32 + n);
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        if encode_address(&dst, &mut packet).is_err() {
            continue;
        }
        packet.extend_from_slice(&buf[..n]);

        let _ = relay.send_to(&packet, client).await;
    }

    streams.lock().await.remove(&dst);
}

fn encode_address(addr: &Address, buf: &mut Vec<u8>) -> Result<()> {
    match addr {
        Address::Ipv4(ip, port) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6(ip, port) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain(host, port) => {
            if host.len() > 255 {
                return Err(anyhow!("domain name too long"));
            }
            buf.push(ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}
