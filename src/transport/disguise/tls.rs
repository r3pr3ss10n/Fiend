use anyhow::{Result, anyhow};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use super::replay::ReplayGuard;
use crate::crypto::RecordCipher;

const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
const TLS_VERSION_12: [u8; 2] = [0x03, 0x03];
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const MAX_TLS_RECORD: usize = 16384;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct ProbeForwarded;

impl std::fmt::Display for ProbeForwarded {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "probe forwarded to real server")
    }
}

impl std::error::Error for ProbeForwarded {}

pub struct FakeTlsStream {
    inner: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_cipher: Option<RecordCipher>,
    read_cipher: Option<RecordCipher>,
}

impl FakeTlsStream {
    fn encrypted(inner: TcpStream, write_cipher: RecordCipher, read_cipher: RecordCipher) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
            write_cipher: Some(write_cipher),
            read_cipher: Some(read_cipher),
        }
    }

    pub(crate) fn into_split(self) -> (FakeTlsReadHalf, FakeTlsWriteHalf) {
        let (r, w) = self.inner.into_split();
        (
            FakeTlsReadHalf {
                inner: tokio::io::BufReader::with_capacity(256 * 1024, r),
                read_buf: self.read_buf,
                read_pos: self.read_pos,
                cipher: self.read_cipher,
                hdr_buf: [0u8; 5],
                hdr_filled: 0,
                body_filled: 0,
            },
            FakeTlsWriteHalf {
                inner: w,
                cipher: self.write_cipher,
                write_buf: Vec::new(),
                write_pos: 0,
            },
        )
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos >= self.read_buf.len() {
            self.read_record().await?;
        }
        let available = &self.read_buf[self.read_pos..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.read_pos += n;
        Ok(n)
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected eof",
                ));
            }
            filled += n;
        }
        Ok(())
    }

    pub async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        if let Some(cipher) = &mut self.write_cipher {
            tls_write_all_encrypted(&mut self.inner, data, cipher).await
        } else {
            tls_write_all(&mut self.inner, data).await
        }
    }

    async fn read_record(&mut self) -> std::io::Result<()> {
        tls_read_record(&mut self.inner, &mut self.read_buf, &mut self.read_pos).await?;
        if let Some(cipher) = &mut self.read_cipher {
            cipher
                .decrypt(&mut self.read_buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        }
        Ok(())
    }
}

pub struct FakeTlsReadHalf {
    pub(crate) inner: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    pub(crate) read_buf: Vec<u8>,
    pub(crate) read_pos: usize,
    pub(crate) cipher: Option<RecordCipher>,
    pub(crate) hdr_buf: [u8; 5],
    pub(crate) hdr_filled: usize,
    pub(crate) body_filled: usize,
}

impl FakeTlsReadHalf {}

pub struct FakeTlsWriteHalf {
    pub(crate) inner: tokio::net::tcp::OwnedWriteHalf,
    pub(crate) cipher: Option<RecordCipher>,
    pub(crate) write_buf: Vec<u8>,
    pub(crate) write_pos: usize,
}

impl FakeTlsWriteHalf {
    pub(crate) fn encode_bridge_frame(&mut self, hdr: &[u8; 8], data: &[u8], pad_len: usize) {
        self.write_buf.clear();
        self.append_bridge_frame(hdr, data, pad_len);
        self.write_pos = 0;
    }

    pub(crate) fn append_bridge_frame(&mut self, hdr: &[u8; 8], data: &[u8], pad_len: usize) {
        if let Some(cipher) = &mut self.cipher {
            encode_bridge_tls_encrypted(hdr, data, pad_len, cipher, &mut self.write_buf);
        } else {
            encode_bridge_tls_plain(hdr, data, pad_len, &mut self.write_buf);
        }
    }

    pub(crate) fn encode_bridge_frame_multi(
        &mut self,
        hdr: &[u8; 8],
        slices: &[&[u8]],
        pad_len: usize,
    ) {
        self.write_buf.clear();
        if let Some(cipher) = &mut self.cipher {
            encode_bridge_tls_encrypted_multi(hdr, slices, pad_len, cipher, &mut self.write_buf);
        } else {
            encode_bridge_tls_plain_multi(hdr, slices, pad_len, &mut self.write_buf);
        }
        self.write_pos = 0;
    }
}

impl AsyncRead for FakeTlsReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.read_pos < this.read_buf.len() {
                let avail = &this.read_buf[this.read_pos..];
                let n = buf.remaining().min(avail.len());
                buf.put_slice(&avail[..n]);
                this.read_pos += n;
                return Poll::Ready(Ok(()));
            }

            if this.hdr_filled < 5 {
                let mut hdr_rb = ReadBuf::new(&mut this.hdr_buf[this.hdr_filled..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut hdr_rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = hdr_rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.hdr_filled += n;
                    }
                }
                if this.hdr_filled < 5 {
                    continue;
                }
                if this.hdr_buf[0] != TLS_RECORD_APPLICATION_DATA {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected TLS record type: {}", this.hdr_buf[0]),
                    )));
                }
                let length = u16::from_be_bytes([this.hdr_buf[3], this.hdr_buf[4]]) as usize;
                if length > MAX_TLS_RECORD + 256 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS record too large",
                    )));
                }
                this.read_buf.clear();
                this.read_buf.resize(length, 0);
                this.read_pos = length;
                this.body_filled = 0;
            }

            if this.body_filled < this.read_buf.len() {
                let mut body_rb = ReadBuf::new(&mut this.read_buf[this.body_filled..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut body_rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = body_rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof in TLS record body",
                            )));
                        }
                        this.body_filled += n;
                    }
                }
                if this.body_filled < this.read_buf.len() {
                    continue;
                }
                if let Some(cipher) = &mut this.cipher {
                    cipher
                        .decrypt(&mut this.read_buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                }
                this.read_pos = 0;
                this.hdr_filled = 0;
                this.body_filled = 0;
            }
        }
    }
}

fn encode_bridge_tls_plain(hdr: &[u8; 8], data: &[u8], pad_len: usize, out: &mut Vec<u8>) {
    let total = 8 + data.len() + pad_len;
    let n_records = total.div_ceil(MAX_TLS_RECORD);
    out.reserve(total + n_records * 5);
    let mut hdr_pos = 0usize;
    let mut data_pos = 0usize;
    let mut pad_rem = pad_len;
    let mut remaining = total;
    while remaining > 0 {
        let chunk = remaining.min(MAX_TLS_RECORD);
        out.push(TLS_RECORD_APPLICATION_DATA);
        out.extend_from_slice(&TLS_VERSION_12);
        out.extend_from_slice(&(chunk as u16).to_be_bytes());
        let mut chunk_rem = chunk;
        if hdr_pos < 8 {
            let n = (8 - hdr_pos).min(chunk_rem);
            out.extend_from_slice(&hdr[hdr_pos..hdr_pos + n]);
            hdr_pos += n;
            chunk_rem -= n;
        }
        if data_pos < data.len() && chunk_rem > 0 {
            let n = (data.len() - data_pos).min(chunk_rem);
            out.extend_from_slice(&data[data_pos..data_pos + n]);
            data_pos += n;
            chunk_rem -= n;
        }
        if pad_rem > 0 && chunk_rem > 0 {
            let n = pad_rem.min(chunk_rem);
            out.resize(out.len() + n, 0);
            pad_rem -= n;
        }
        remaining -= chunk;
    }
}

fn encode_bridge_tls_encrypted(
    hdr: &[u8; 8],
    data: &[u8],
    pad_len: usize,
    cipher: &mut RecordCipher,
    out: &mut Vec<u8>,
) {
    let max_plaintext = MAX_TLS_RECORD - 16;
    let total = 8 + data.len() + pad_len;
    let n_records = total.div_ceil(max_plaintext);
    out.reserve(total + n_records * (5 + 16));
    let mut hdr_pos = 0usize;
    let mut data_pos = 0usize;
    let mut pad_rem = pad_len;
    let mut remaining = total;
    while remaining > 0 {
        let chunk = remaining.min(max_plaintext);
        out.push(TLS_RECORD_APPLICATION_DATA);
        out.extend_from_slice(&TLS_VERSION_12);
        out.extend_from_slice(&((chunk + 16) as u16).to_be_bytes());
        let start = out.len();
        let mut chunk_rem = chunk;
        if hdr_pos < 8 {
            let n = (8 - hdr_pos).min(chunk_rem);
            out.extend_from_slice(&hdr[hdr_pos..hdr_pos + n]);
            hdr_pos += n;
            chunk_rem -= n;
        }
        if data_pos < data.len() && chunk_rem > 0 {
            let n = (data.len() - data_pos).min(chunk_rem);
            out.extend_from_slice(&data[data_pos..data_pos + n]);
            data_pos += n;
            chunk_rem -= n;
        }
        if pad_rem > 0 && chunk_rem > 0 {
            let n = pad_rem.min(chunk_rem);
            out.resize(out.len() + n, 0);
            pad_rem -= n;
        }
        let tag = cipher.encrypt(&mut out[start..]);
        out.extend_from_slice(&tag);
        remaining -= chunk;
    }
}

fn encode_bridge_tls_plain_multi(
    hdr: &[u8; 8],
    slices: &[&[u8]],
    pad_len: usize,
    out: &mut Vec<u8>,
) {
    let data_total: usize = slices.iter().map(|s| s.len()).sum();
    let total = 8 + data_total + pad_len;
    let n_records = total.div_ceil(MAX_TLS_RECORD);
    out.reserve(total + n_records * 5);
    let mut hdr_pos = 0usize;
    let mut si = 0usize;
    let mut sp = 0usize;
    let mut pad_rem = pad_len;
    let mut remaining = total;
    while remaining > 0 {
        let chunk = remaining.min(MAX_TLS_RECORD);
        out.push(TLS_RECORD_APPLICATION_DATA);
        out.extend_from_slice(&TLS_VERSION_12);
        out.extend_from_slice(&(chunk as u16).to_be_bytes());
        let mut chunk_rem = chunk;
        if hdr_pos < 8 {
            let n = (8 - hdr_pos).min(chunk_rem);
            out.extend_from_slice(&hdr[hdr_pos..hdr_pos + n]);
            hdr_pos += n;
            chunk_rem -= n;
        }
        while si < slices.len() && chunk_rem > 0 {
            let avail = slices[si].len() - sp;
            let n = avail.min(chunk_rem);
            out.extend_from_slice(&slices[si][sp..sp + n]);
            chunk_rem -= n;
            sp += n;
            if sp >= slices[si].len() {
                si += 1;
                sp = 0;
            }
        }
        if pad_rem > 0 && chunk_rem > 0 {
            let n = pad_rem.min(chunk_rem);
            out.resize(out.len() + n, 0);
            pad_rem -= n;
        }
        remaining -= chunk;
    }
}

fn encode_bridge_tls_encrypted_multi(
    hdr: &[u8; 8],
    slices: &[&[u8]],
    pad_len: usize,
    cipher: &mut RecordCipher,
    out: &mut Vec<u8>,
) {
    let max_plaintext = MAX_TLS_RECORD - 16;
    let data_total: usize = slices.iter().map(|s| s.len()).sum();
    let total = 8 + data_total + pad_len;
    let n_records = total.div_ceil(max_plaintext);
    out.reserve(total + n_records * (5 + 16));
    let mut hdr_pos = 0usize;
    let mut si = 0usize;
    let mut sp = 0usize;
    let mut pad_rem = pad_len;
    let mut remaining = total;
    while remaining > 0 {
        let chunk = remaining.min(max_plaintext);
        out.push(TLS_RECORD_APPLICATION_DATA);
        out.extend_from_slice(&TLS_VERSION_12);
        out.extend_from_slice(&((chunk + 16) as u16).to_be_bytes());
        let start = out.len();
        let mut chunk_rem = chunk;
        if hdr_pos < 8 {
            let n = (8 - hdr_pos).min(chunk_rem);
            out.extend_from_slice(&hdr[hdr_pos..hdr_pos + n]);
            hdr_pos += n;
            chunk_rem -= n;
        }
        while si < slices.len() && chunk_rem > 0 {
            let avail = slices[si].len() - sp;
            let n = avail.min(chunk_rem);
            out.extend_from_slice(&slices[si][sp..sp + n]);
            chunk_rem -= n;
            sp += n;
            if sp >= slices[si].len() {
                si += 1;
                sp = 0;
            }
        }
        if pad_rem > 0 && chunk_rem > 0 {
            let n = pad_rem.min(chunk_rem);
            out.resize(out.len() + n, 0);
            pad_rem -= n;
        }
        let tag = cipher.encrypt(&mut out[start..]);
        out.extend_from_slice(&tag);
        remaining -= chunk;
    }
}

async fn tls_read_record<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    read_buf: &mut Vec<u8>,
    read_pos: &mut usize,
) -> std::io::Result<()> {
    read_buf.clear();
    *read_pos = 0;

    let mut hdr = [0u8; 5];
    reader.read_exact(&mut hdr).await?;

    if hdr[0] != TLS_RECORD_APPLICATION_DATA {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected TLS record type: {}", hdr[0]),
        ));
    }

    let length = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if length > MAX_TLS_RECORD + 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record too large",
        ));
    }

    read_buf.resize(length, 0);
    reader.read_exact(read_buf).await?;
    Ok(())
}

async fn tls_write_all<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    let mut remaining = data;
    let n_records = data.len().div_ceil(MAX_TLS_RECORD);
    let mut buf = Vec::with_capacity(data.len() + n_records * 5);

    while !remaining.is_empty() {
        let chunk_len = remaining.len().min(MAX_TLS_RECORD);
        buf.push(TLS_RECORD_APPLICATION_DATA);
        buf.extend_from_slice(&TLS_VERSION_12);
        buf.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        buf.extend_from_slice(&remaining[..chunk_len]);
        remaining = &remaining[chunk_len..];
    }

    writer.write_all(&buf).await
}

async fn tls_write_all_encrypted<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    cipher: &mut RecordCipher,
) -> std::io::Result<()> {
    let max_plaintext = MAX_TLS_RECORD - 16;
    let mut remaining = data;
    let n_records = data.len().div_ceil(max_plaintext);
    let mut buf = Vec::with_capacity(data.len() + n_records * (5 + 16));

    while !remaining.is_empty() {
        let chunk_len = remaining.len().min(max_plaintext);
        buf.push(TLS_RECORD_APPLICATION_DATA);
        buf.extend_from_slice(&TLS_VERSION_12);
        buf.extend_from_slice(&((chunk_len + 16) as u16).to_be_bytes());
        let start = buf.len();
        buf.extend_from_slice(&remaining[..chunk_len]);
        let tag = cipher.encrypt(&mut buf[start..]);
        buf.extend_from_slice(&tag);
        remaining = &remaining[chunk_len..];
    }

    writer.write_all(&buf).await
}

pub async fn client_tls_templated(
    mut stream: TcpStream,
    secret: &[u8],
    template: &crate::fingerprint::FingerprintTemplate,
) -> Result<FakeTlsStream> {
    let record = template
        .build(secret)
        .map_err(|e| anyhow!("build ClientHello from template: {}", e))?;
    let tls_random = record[11..43].to_vec();

    stream
        .write_all(&record)
        .await
        .map_err(|e| anyhow!("write ClientHello: {}", e))?;

    read_server_handshake(&mut stream, secret, &tls_random)
        .await
        .map_err(|e| anyhow!("read server handshake: {}", e))?;

    let (write_cipher, read_cipher) =
        crate::crypto::derive_session_keys(secret, &tls_random, true)?;
    Ok(FakeTlsStream::encrypted(stream, write_cipher, read_cipher))
}

const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn server_tls(
    mut stream: TcpStream,
    secret: &[u8],
    domain: &str,
    guard: &ReplayGuard,
    forward_limit: &Arc<Semaphore>,
) -> Result<FakeTlsStream> {
    let mut hdr = [0u8; 5];
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, stream.read_exact(&mut hdr)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(anyhow!("read TLS header: {}", e)),
        Err(_) => return Err(anyhow!("read TLS header: timeout")),
    }

    if hdr[0] != TLS_RECORD_HANDSHAKE {
        tokio::spawn(forward_to_real_server(
            stream,
            hdr.to_vec(),
            domain.to_string(),
            forward_limit.clone(),
        ));
        return Err(ProbeForwarded.into());
    }

    let length = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if length > MAX_TLS_RECORD + 256 {
        tokio::spawn(forward_to_real_server(
            stream,
            hdr.to_vec(),
            domain.to_string(),
            forward_limit.clone(),
        ));
        return Err(ProbeForwarded.into());
    }

    let mut body = vec![0u8; length];
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, stream.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => return Err(ProbeForwarded.into()),
    }

    let mut client_hello = Vec::with_capacity(5 + length);
    client_hello.extend_from_slice(&hdr);
    client_hello.extend_from_slice(&body);

    if !verify_auth_token(&body, secret) {
        tokio::spawn(forward_to_real_server(
            stream,
            client_hello,
            domain.to_string(),
            forward_limit.clone(),
        ));
        return Err(ProbeForwarded.into());
    }

    if !guard.check(&body[6..38]) {
        tokio::spawn(forward_to_real_server(
            stream,
            client_hello,
            domain.to_string(),
            forward_limit.clone(),
        ));
        return Err(ProbeForwarded.into());
    }

    let tls_random = body[6..38].to_vec();

    relay_real_handshake(&mut stream, domain, &client_hello, secret, &tls_random)
        .await
        .map_err(|e| anyhow!("relay handshake: {}", e))?;

    let (write_cipher, read_cipher) =
        crate::crypto::derive_session_keys(secret, &tls_random, false)?;
    Ok(FakeTlsStream::encrypted(stream, write_cipher, read_cipher))
}

fn verify_auth_token(body: &[u8], secret: &[u8]) -> bool {
    if body.len() < 71 || body[0] != TLS_HANDSHAKE_CLIENT_HELLO || body[38] != 32 {
        return false;
    }
    let tls_random = &body[6..38];
    let received_token = &body[39..71];
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(tls_random);
    mac.verify_slice(received_token).is_ok()
}

fn handshake_terminator(secret: &[u8], tls_random: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(b"handshake-done");
    mac.update(tls_random);
    mac.finalize().into_bytes().to_vec()
}

fn padded_terminator(secret: &[u8], tls_random: &[u8]) -> Vec<u8> {
    let hmac = handshake_terminator(secret, tls_random);
    let pad_len = fastrand::usize(100..750);
    let mut padded = Vec::with_capacity(hmac.len() + pad_len);
    padded.extend_from_slice(&hmac);
    let mut padding = vec![0u8; pad_len];
    rand::rng().fill(&mut padding[..]);
    padded.extend_from_slice(&padding);
    padded
}

pub(crate) fn derive_psk_identity(secret: &[u8]) -> [u8; 32] {
    let hour = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 3600;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(b"psk-identity");
    mac.update(&hour.to_le_bytes());
    mac.finalize().into_bytes().into()
}

pub(crate) fn derive_ticket_age(secret: &[u8]) -> [u8; 4] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let minutes_in_hour = ((now % 3600) / 60) as u32;
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(b"ticket-age-obfuscator");
    let obfuscator = u32::from_le_bytes(mac.finalize().into_bytes()[..4].try_into().unwrap());
    (minutes_in_hour.wrapping_mul(60000).wrapping_add(obfuscator)).to_be_bytes()
}

fn make_tls_record(content_type: u8, data: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(content_type);
    record.extend_from_slice(&TLS_VERSION_12);
    record.extend_from_slice(&(data.len() as u16).to_be_bytes());
    record.extend_from_slice(data);
    record
}

async fn relay_real_handshake(
    client_conn: &mut TcpStream,
    domain: &str,
    client_hello: &[u8],
    secret: &[u8],
    tls_random: &[u8],
) -> Result<()> {
    let addr = format!("{}:443", domain);
    let mut real_conn = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("dial real server: timeout"))?
        .map_err(|e| anyhow!("dial real server: {}", e))?;

    real_conn
        .write_all(client_hello)
        .await
        .map_err(|e| anyhow!("write to real server: {}", e))?;

    let mut got_records = false;
    let mut seen_app_data = false;

    loop {
        let timeout = if seen_app_data {
            match real_conn.try_read(&mut [0u8; 0]) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                _ => Duration::from_secs(1),
            }
        } else {
            Duration::from_secs(5)
        };

        let result = tokio::time::timeout(timeout, async {
            let mut hdr = [0u8; 5];
            real_conn.read_exact(&mut hdr).await?;
            let length = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if length > MAX_TLS_RECORD + 256 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "record too large",
                ));
            }
            let mut body = vec![0u8; length];
            real_conn.read_exact(&mut body).await?;
            let mut record = Vec::with_capacity(5 + length);
            record.extend_from_slice(&hdr);
            record.extend_from_slice(&body);
            Ok(record)
        })
        .await;

        match result {
            Ok(Ok(record)) => {
                if record[0] == TLS_RECORD_APPLICATION_DATA {
                    seen_app_data = true;
                }
                client_conn
                    .write_all(&record)
                    .await
                    .map_err(|e| anyhow!("write relay record: {}", e))?;
                got_records = true;
            }
            _ => break,
        }
    }

    if !got_records {
        return Err(anyhow!("no data from real server"));
    }

    let _ = real_conn.shutdown().await;

    let terminator = padded_terminator(secret, tls_random);
    let record = make_tls_record(TLS_RECORD_APPLICATION_DATA, &terminator);
    client_conn
        .write_all(&record)
        .await
        .map_err(|e| anyhow!("write terminator: {}", e))?;

    Ok(())
}

async fn read_server_handshake(
    conn: &mut TcpStream,
    secret: &[u8],
    tls_random: &[u8],
) -> Result<()> {
    let expected = handshake_terminator(secret, tls_random);

    for _ in 0..64 {
        let mut hdr = [0u8; 5];
        conn.read_exact(&mut hdr).await?;

        let length = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if length > MAX_TLS_RECORD + 256 {
            return Err(anyhow!("TLS record too large: {}", length));
        }

        let mut body = vec![0u8; length];
        conn.read_exact(&mut body).await?;

        if hdr[0] == TLS_RECORD_APPLICATION_DATA && body.len() >= 32 && body[..32] == expected[..] {
            return Ok(());
        }
    }

    Err(anyhow!("handshake terminator not found"))
}

async fn forward_to_real_server(
    mut client: TcpStream,
    buffered: Vec<u8>,
    domain: String,
    limit: Arc<Semaphore>,
) {
    let _permit = match limit.try_acquire() {
        Ok(p) => p,
        Err(_) => return,
    };

    let addr = format!("{}:443", domain);
    let real = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await;

    let mut real = match real {
        Ok(Ok(c)) => c,
        _ => return,
    };

    if real.write_all(&buffered).await.is_err() {
        return;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut real).await;
}
