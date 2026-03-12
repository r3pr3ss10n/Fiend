use anyhow::{Result, anyhow};

use crate::mux::MuxStream;
use crate::socks5::Address;

pub const STREAM_TCP: u8 = 0x01;
pub const STREAM_UDP: u8 = 0x02;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const COPY_BUF: usize = 256 * 1024;

pub struct StreamHeader {
    pub stream_type: u8,
    pub dst: Address,
}

pub async fn write_stream_header(stream: &MuxStream, dst: &Address) -> Result<()> {
    let mut buf = Vec::with_capacity(32);
    buf.push(STREAM_TCP);
    encode_address(dst, &mut buf)?;
    stream.write(&buf).await?;
    Ok(())
}

pub async fn write_stream_header_udp(stream: &MuxStream, dst: &Address) -> Result<()> {
    let mut buf = Vec::with_capacity(32);
    buf.push(STREAM_UDP);
    encode_address(dst, &mut buf)?;
    stream.write(&buf).await?;
    Ok(())
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

pub async fn read_stream_header(stream: &MuxStream) -> Result<StreamHeader> {
    let mut type_buf = [0u8; 1];
    read_exact(stream, &mut type_buf).await?;
    let stream_type = type_buf[0];

    if stream_type != STREAM_TCP && stream_type != STREAM_UDP {
        return Err(anyhow!("unknown stream type: 0x{:02x}", stream_type));
    }

    let mut atyp_buf = [0u8; 1];
    read_exact(stream, &mut atyp_buf).await?;

    let dst = match atyp_buf[0] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            read_exact(stream, &mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Address::Ipv4(ip, port)
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            read_exact(stream, &mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len + 2];
            read_exact(stream, &mut buf).await?;
            let domain = String::from_utf8(buf[..len].to_vec())?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            Address::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            read_exact(stream, &mut buf).await?;
            let ip = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&buf[..16]).map_err(|_| anyhow!("invalid ipv6"))?,
            );
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Address::Ipv6(ip, port)
        }
        other => return Err(anyhow!("unknown atyp: 0x{:02x}", other)),
    };

    Ok(StreamHeader { stream_type, dst })
}

pub async fn read_exact(stream: &MuxStream, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = stream.read(&mut buf[offset..]).await?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF"));
        }
        offset += n;
    }
    Ok(())
}
