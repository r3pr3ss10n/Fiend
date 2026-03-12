use std::collections::HashMap;
use std::io::{self, IoSlice};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

use super::frame::*;
use super::stream::{MuxStream, Signal, StreamInner};

const DEFAULT_ACCEPT_BACKLOG: usize = 1024;
const SEND_QUEUE_SIZE: usize = 1024;

#[derive(Debug, Clone)]
pub struct Config {
    pub version: u8,
    pub keep_alive_disabled: bool,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
    pub max_frame_size: usize,
    pub max_receive_buffer: usize,
    pub max_stream_buffer: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            keep_alive_disabled: false,
            keep_alive_interval: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(30),
            max_frame_size: 32768,
            max_receive_buffer: 4_194_304,
            max_stream_buffer: 65536,
        }
    }
}

impl Config {
    pub fn verify(&self) -> Result<()> {
        if self.version != 1 && self.version != 2 {
            return Err(anyhow!("unsupported protocol version"));
        }
        if !self.keep_alive_disabled {
            if self.keep_alive_interval.is_zero() {
                return Err(anyhow!("keep-alive interval must be positive"));
            }
            if self.keep_alive_timeout < self.keep_alive_interval {
                return Err(anyhow!(
                    "keep-alive timeout must be larger than keep-alive interval"
                ));
            }
        }
        if self.max_frame_size == 0 || self.max_frame_size > 65535 {
            return Err(anyhow!("max frame size must be between 1 and 65535"));
        }
        if self.max_receive_buffer == 0 || self.max_receive_buffer > i32::MAX as usize {
            return Err(anyhow!("max receive buffer out of range"));
        }
        if self.max_stream_buffer == 0 || self.max_stream_buffer > self.max_receive_buffer {
            return Err(anyhow!(
                "max stream buffer must be positive and <= max receive buffer"
            ));
        }
        Ok(())
    }
}

struct WriteRequest {
    frame: Bytes,
}

pub(crate) struct SessionInner {
    pub config: Config,

    streams: std::sync::Mutex<HashMap<u32, Arc<StreamInner>>>,
    next_stream_id: std::sync::Mutex<u32>,
    go_away: AtomicBool,

    bucket: AtomicI32,
    bucket_notify: Notify,

    pub die: Signal,
    closed: AtomicBool,

    pub read_error: OnceLock<String>,
    pub read_error_signal: Signal,
    pub write_error: OnceLock<String>,
    pub write_error_signal: Signal,
    pub proto_error: OnceLock<String>,
    pub proto_error_signal: Signal,

    is_active: AtomicBool,
    write_tx: mpsc::Sender<WriteRequest>,
}

impl SessionInner {
    pub fn return_tokens(&self, n: i32) {
        if self.bucket.fetch_add(n, Ordering::AcqRel) + n > 0 {
            self.bucket_notify.notify_one();
        }
    }

    pub fn stream_closed(&self, sid: u32) {
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(stream) = streams.remove(&sid) {
            let n = stream.recycle_tokens();
            if n > 0 && self.bucket.fetch_add(n as i32, Ordering::AcqRel) + n as i32 > 0 {
                self.bucket_notify.notify_one();
            }
        }
    }

    pub async fn write_frame(
        &self,
        ver: u8,
        cmd: u8,
        sid: u32,
        data: &[u8],
        deadline: Option<tokio::time::Instant>,
    ) -> Result<usize> {
        let len = data.len();
        let mut frame = Vec::with_capacity(HEADER_SIZE + data.len());
        frame.resize(HEADER_SIZE, 0u8);
        encode_header(&mut frame, ver, cmd, sid, data.len() as u16);
        frame.extend_from_slice(data);
        let req = WriteRequest {
            frame: Bytes::from(frame),
        };

        let deadline_sleep = |d: Option<tokio::time::Instant>| async move {
            match d {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            result = self.write_tx.send(req) => {
                result.map_err(|_| anyhow!("broken pipe"))?;
                Ok(len)
            }
            _ = self.die.wait() => Err(anyhow!("broken pipe")),
            _ = self.write_error_signal.wait() => {
                Err(anyhow!("{}", self.write_error.get().map(String::as_str).unwrap_or("unknown error")))
            }
            _ = deadline_sleep(deadline) => Err(anyhow!("timeout")),
        }
    }

    fn notify_read_error(&self, err: String) {
        let _ = self.read_error.set(err);
        self.read_error_signal.fire();
    }

    fn notify_write_error(&self, err: String) {
        let _ = self.write_error.set(err);
        self.write_error_signal.fire();
    }

    fn notify_proto_error(&self, err: String) {
        let _ = self.proto_error.set(err);
        self.proto_error_signal.fire();
    }
}

#[derive(Clone)]
pub struct Session {
    shared: Arc<SessionInner>,
    accept_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<MuxStream>>>,
}

impl Session {
    pub async fn open_stream(&self) -> Result<MuxStream> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(anyhow!("broken pipe"));
        }

        let sid = {
            let mut next = self
                .shared
                .next_stream_id
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.shared.go_away.load(Ordering::Acquire) {
                return Err(anyhow!("stream id overflow"));
            }
            let candidate = next.wrapping_add(2);
            if candidate < *next {
                self.shared.go_away.store(true, Ordering::Release);
                return Err(anyhow!("stream id overflow"));
            }
            *next = candidate;
            candidate
        };

        let stream = StreamInner::new(sid, self.shared.config.max_frame_size, self.shared.clone());

        let deadline = Some(tokio::time::Instant::now() + Duration::from_secs(30));
        self.shared
            .write_frame(self.shared.config.version, CMD_SYN, sid, &[], deadline)
            .await?;

        {
            let mut streams = self
                .shared
                .streams
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.shared.read_error_signal.is_fired() {
                return Err(anyhow!(
                    "{}",
                    self.shared
                        .read_error
                        .get()
                        .map(String::as_str)
                        .unwrap_or("unknown error")
                ));
            }
            if self.shared.write_error_signal.is_fired() {
                return Err(anyhow!(
                    "{}",
                    self.shared
                        .write_error
                        .get()
                        .map(String::as_str)
                        .unwrap_or("unknown error")
                ));
            }
            if self.shared.die.is_fired() {
                return Err(anyhow!("broken pipe"));
            }
            streams.insert(sid, stream.clone());
        }

        Ok(MuxStream::new(stream))
    }

    pub async fn closed(&self) {
        let die = self.shared.die.wait();
        let read_err = self.shared.read_error_signal.wait();
        let write_err = self.shared.write_error_signal.wait();
        let proto_err = self.shared.proto_error_signal.wait();
        tokio::pin!(die, read_err, write_err, proto_err);
        tokio::select! {
            _ = die => {
                tracing::warn!("session die: keepalive timeout");
            }
            _ = read_err => {
                tracing::warn!(
                    "session die: read error: {}",
                    self.shared.read_error.get().map(String::as_str).unwrap_or("unknown")
                );
            }
            _ = write_err => {
                tracing::warn!(
                    "session die: write error: {}",
                    self.shared.write_error.get().map(String::as_str).unwrap_or("unknown")
                );
            }
            _ = proto_err => {
                tracing::warn!(
                    "session die: proto error: {}",
                    self.shared.proto_error.get().map(String::as_str).unwrap_or("unknown")
                );
            }
        }
    }

    pub async fn accept_stream(&self) -> Result<MuxStream> {
        let mut rx = self.accept_rx.lock().await;
        let read_err = self.shared.read_error_signal.wait();
        let proto_err = self.shared.proto_error_signal.wait();
        let die = self.shared.die.wait();

        tokio::pin!(read_err, proto_err, die);

        tokio::select! {
            stream = rx.recv() => {
                stream.ok_or_else(|| anyhow!("broken pipe"))
            }
            _ = read_err => {
                Err(anyhow!("{}", self.shared.read_error.get().map(String::as_str).unwrap_or("unknown error")))
            }
            _ = proto_err => {
                Err(anyhow!("{}", self.shared.proto_error.get().map(String::as_str).unwrap_or("unknown error")))
            }
            _ = die => Err(anyhow!("broken pipe")),
        }
    }
}

pub fn client<R, W>(reader: R, writer: W, config: Config) -> Result<Session>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    config.verify()?;
    Ok(new_session(config, reader, writer, true))
}

pub fn server<R, W>(reader: R, writer: W, config: Config) -> Result<Session>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    config.verify()?;
    Ok(new_session(config, reader, writer, false))
}

fn new_session<R, W>(config: Config, reader: R, writer: W, is_client: bool) -> Session
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (write_tx, write_rx) = mpsc::channel(SEND_QUEUE_SIZE);
    let (accept_tx, accept_rx) = mpsc::channel(DEFAULT_ACCEPT_BACKLOG);

    let shared = Arc::new(SessionInner {
        config: config.clone(),
        streams: std::sync::Mutex::new(HashMap::new()),
        next_stream_id: std::sync::Mutex::new(if is_client { 1 } else { 0 }),
        go_away: AtomicBool::new(false),
        bucket: AtomicI32::new(config.max_receive_buffer as i32),
        bucket_notify: Notify::new(),
        die: Signal::new(),
        closed: AtomicBool::new(false),
        read_error: OnceLock::new(),
        read_error_signal: Signal::new(),
        write_error: OnceLock::new(),
        write_error_signal: Signal::new(),
        proto_error: OnceLock::new(),
        proto_error_signal: Signal::new(),
        is_active: AtomicBool::new(false),
        write_tx,
    });

    {
        let shared = shared.clone();
        tokio::spawn(async move {
            recv_loop(reader, shared, accept_tx).await;
        });
    }

    {
        let shared = shared.clone();
        tokio::spawn(async move {
            send_loop(writer, write_rx, shared).await;
        });
    }

    if !config.keep_alive_disabled {
        let shared = shared.clone();
        tokio::spawn(async move {
            keepalive(shared).await;
        });
    }

    Session {
        shared,
        accept_rx: Arc::new(tokio::sync::Mutex::new(accept_rx)),
    }
}

async fn recv_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    shared: Arc<SessionInner>,
    accept_tx: mpsc::Sender<MuxStream>,
) {
    let mut hdr = [0u8; HEADER_SIZE];
    let mut upd_buf = [0u8; SZ_CMD_UPD];

    loop {
        while shared.bucket.load(Ordering::Acquire) < -(shared.config.max_stream_buffer as i32)
            && !shared.die.is_fired()
        {
            let notified = shared.bucket_notify.notified();
            let die = shared.die.wait();
            tokio::pin!(notified, die);
            tokio::select! {
                _ = notified => {}
                _ = die => return,
            }
        }

        if shared.die.is_fired() {
            return;
        }

        if let Err(e) = reader.read_exact(&mut hdr).await {
            shared.notify_read_error(e.to_string());
            return;
        }

        shared.is_active.store(true, Ordering::Release);

        let (ver, cmd, length, sid) = decode_header(&hdr);

        if ver != shared.config.version {
            shared.notify_proto_error("invalid protocol".into());
            return;
        }

        match cmd {
            CMD_NOP => {
                if length != 0 {
                    shared.notify_proto_error("invalid protocol".into());
                    return;
                }
            }

            CMD_SYN => {
                if length != 0 {
                    shared.notify_proto_error("invalid protocol".into());
                    return;
                }

                let accepted = {
                    let mut streams = shared.streams.lock().unwrap_or_else(|e| e.into_inner());
                    if let std::collections::hash_map::Entry::Vacant(e) = streams.entry(sid) {
                        let stream =
                            StreamInner::new(sid, shared.config.max_frame_size, shared.clone());
                        e.insert(stream.clone());
                        Some(stream)
                    } else {
                        None
                    }
                };

                if let Some(stream) = accepted {
                    let mux_stream = MuxStream::new(stream);
                    tokio::select! {
                        _ = accept_tx.send(mux_stream) => {}
                        _ = shared.die.wait() => return,
                    }
                }
            }

            CMD_FIN => {
                if length != 0 {
                    shared.notify_proto_error("invalid protocol".into());
                    return;
                }

                let stream = {
                    let streams = shared.streams.lock().unwrap_or_else(|e| e.into_inner());
                    streams.get(&sid).cloned()
                };

                if let Some(s) = stream {
                    s.fin_event.fire();
                    s.wakeup_reader();
                }
            }

            CMD_PSH => {
                if length == 0 {
                    continue;
                }

                let mut payload = vec![0u8; length as usize];
                if let Err(e) = reader.read_exact(&mut payload).await {
                    shared.notify_read_error(e.to_string());
                    return;
                }

                let written = payload.len();

                let mut streams = shared.streams.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(stream) = streams.get_mut(&sid) {
                    stream.push_bytes(payload);
                    shared.bucket.fetch_sub(written as i32, Ordering::AcqRel);
                    stream.wakeup_reader();
                }
            }

            CMD_UPD => {
                if shared.config.version != 2 {
                    shared.notify_proto_error("invalid protocol".into());
                    return;
                }
                if length as usize != SZ_CMD_UPD {
                    shared.notify_proto_error("invalid protocol".into());
                    return;
                }

                if let Err(e) = reader.read_exact(&mut upd_buf).await {
                    shared.notify_read_error(e.to_string());
                    return;
                }

                let (consumed, window) = decode_upd(&upd_buf);

                let stream = {
                    let streams = shared.streams.lock().unwrap_or_else(|e| e.into_inner());
                    streams.get(&sid).cloned()
                };

                if let Some(s) = stream {
                    s.update(consumed, window);
                }
            }

            _ => {
                shared.notify_proto_error("invalid protocol".into());
                return;
            }
        }
    }
}

async fn send_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut write_rx: mpsc::Receiver<WriteRequest>,
    shared: Arc<SessionInner>,
) {
    let mut frames: Vec<Bytes> = Vec::with_capacity(64);

    loop {
        frames.clear();

        let req = tokio::select! {
            req = write_rx.recv() => match req {
                Some(r) => r,
                None => return,
            },
            _ = shared.die.wait() => return,
        };

        frames.push(req.frame);

        loop {
            match write_rx.try_recv() {
                Ok(r) => frames.push(r.frame),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }

        if let Err(e) = write_all_vectored(&mut writer, &frames).await {
            shared.notify_write_error(e.to_string());
            return;
        }
    }
}

async fn write_all_vectored<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frames: &[Bytes],
) -> io::Result<()> {
    let mut frame_idx = 0;
    let mut frame_off = 0;
    while frame_idx < frames.len() {
        let ioslices: Vec<IoSlice<'_>> = frames[frame_idx..]
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if i == 0 {
                    IoSlice::new(&f[frame_off..])
                } else {
                    IoSlice::new(f)
                }
            })
            .collect();
        let n = writer.write_vectored(&ioslices).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
        }
        let mut rem = n;
        while rem > 0 && frame_idx < frames.len() {
            let avail = frames[frame_idx].len() - frame_off;
            if rem >= avail {
                rem -= avail;
                frame_idx += 1;
                frame_off = 0;
            } else {
                frame_off += rem;
                rem = 0;
            }
        }
    }
    Ok(())
}

async fn keepalive(shared: Arc<SessionInner>) {
    use rand::RngExt;

    let mut timeout_interval = tokio::time::interval(shared.config.keep_alive_timeout);
    timeout_interval.tick().await;

    let base_ms = shared.config.keep_alive_interval.as_millis() as u64;
    let jitter_range = base_ms * 3 / 10;
    let min_ms = base_ms - jitter_range;
    let max_ms = base_ms + jitter_range;

    let mut ping_sleep = Box::pin(tokio::time::sleep(Duration::from_millis(
        rand::rng().random_range(min_ms..=max_ms),
    )));

    loop {
        tokio::select! {
            _ = &mut ping_sleep => {
                let deadline = Some(
                    tokio::time::Instant::now() + shared.config.keep_alive_interval,
                );
                let _ = shared.write_frame(
                    shared.config.version,
                    CMD_NOP,
                    0,
                    &[],
                    deadline,
                ).await;
                shared.bucket_notify.notify_one();
                ping_sleep = Box::pin(tokio::time::sleep(Duration::from_millis(
                    rand::rng().random_range(min_ms..=max_ms),
                )));
            }
            _ = timeout_interval.tick() => {
                let was_active = shared.is_active.compare_exchange(
                    true, false, Ordering::AcqRel, Ordering::Acquire,
                );
                if was_active.is_err() && shared.bucket.load(Ordering::Acquire) > 0 {
                    shared.die.fire();
                    shared.closed.store(true, Ordering::Release);
                    return;
                }
            }
            _ = shared.die.wait() => return,
        }
    }
}
