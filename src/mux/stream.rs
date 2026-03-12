use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Notify;

use super::frame::*;
use super::session::SessionInner;

pub struct Signal {
    fired: AtomicBool,
    notify: Notify,
}

impl Signal {
    pub fn new() -> Self {
        Self {
            fired: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub fn fire(&self) -> bool {
        if self
            .fired
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.notify.notify_waiters();
            true
        } else {
            false
        }
    }

    pub fn is_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }

    pub async fn wait(&self) {
        loop {
            if self.is_fired() {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_fired() {
                return;
            }
            notified.await;
        }
    }
}

struct StreamBuffer {
    chunks: VecDeque<Vec<u8>>,
    front_offset: usize,
    num_read: u32,
    incr: u32,
}

impl StreamBuffer {
    fn new() -> Self {
        Self {
            chunks: VecDeque::with_capacity(8),
            front_offset: 0,
            num_read: 0,
            incr: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    fn push(&mut self, data: Vec<u8>) {
        self.chunks.push_back(data);
    }

    fn consume(&mut self, buf: &mut [u8]) -> usize {
        let mut total = 0;
        while total < buf.len() && !self.chunks.is_empty() {
            let front = &self.chunks[0][self.front_offset..];
            let n = (buf.len() - total).min(front.len());
            buf[total..total + n].copy_from_slice(&front[..n]);
            total += n;
            self.front_offset += n;
            if self.front_offset >= self.chunks[0].len() {
                self.chunks.pop_front();
                self.front_offset = 0;
            }
        }
        total
    }

    fn drain_bytes(&mut self) -> usize {
        let mut total = 0;
        for chunk in &self.chunks {
            total += chunk.len();
        }
        total -= self.front_offset;
        self.chunks.clear();
        self.front_offset = 0;
        total
    }
}

pub(crate) struct StreamInner {
    pub id: u32,
    pub sess: Arc<SessionInner>,
    pub frame_size: usize,

    buffer: std::sync::Mutex<StreamBuffer>,

    pub reader_wakeup: Notify,
    writer_wakeup: Notify,

    pub die: Signal,
    pub fin_event: Signal,
    pub write_closed: Signal,
    fin_sent: AtomicBool,

    pub num_written: AtomicU32,
    pub peer_consumed: AtomicU32,
    pub peer_window: AtomicU32,
    pub update_notify: Notify,
    window_update_threshold: u32,
}

impl StreamInner {
    pub fn new(id: u32, frame_size: usize, sess: Arc<SessionInner>) -> Arc<Self> {
        let threshold = sess.config.max_stream_buffer as u32 / 2;
        Arc::new(Self {
            id,
            frame_size,
            buffer: std::sync::Mutex::new(StreamBuffer::new()),
            reader_wakeup: Notify::new(),
            writer_wakeup: Notify::new(),
            die: Signal::new(),
            fin_event: Signal::new(),
            write_closed: Signal::new(),
            fin_sent: AtomicBool::new(false),
            num_written: AtomicU32::new(0),
            peer_consumed: AtomicU32::new(0),
            peer_window: AtomicU32::new(INITIAL_PEER_WINDOW),
            update_notify: Notify::new(),
            window_update_threshold: threshold,
            sess,
        })
    }

    pub fn push_bytes(&self, data: Vec<u8>) {
        self.buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(data);
    }

    pub fn recycle_tokens(&self) -> usize {
        self.buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain_bytes()
    }

    pub fn wakeup_reader(&self) {
        self.reader_wakeup.notify_one();
    }

    pub fn update(&self, consumed: u32, window: u32) {
        self.peer_consumed.store(consumed, Ordering::Release);
        self.peer_window.store(window, Ordering::Release);
        self.update_notify.notify_one();
    }

    fn try_send_fin(&self) -> bool {
        self.fin_sent
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

pub struct MuxStream {
    pub(crate) inner: Arc<StreamInner>,
}

impl MuxStream {
    pub(crate) fn new(inner: Arc<StreamInner>) -> Self {
        Self { inner }
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.inner.sess.config.version == 2 {
            self.read_v2(buf).await
        } else {
            self.read_v1(buf).await
        }
    }

    async fn read_v1(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let n = self
                .inner
                .buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .consume(buf);
            if n > 0 {
                self.inner.sess.return_tokens(n as i32);
                return Ok(n);
            }

            if self.inner.die.is_fired() {
                return Ok(0);
            }

            self.wait_read().await?;
        }
    }

    async fn read_v2(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let (n, notify_consumed) = {
                let mut sb = self.inner.buffer.lock().unwrap_or_else(|e| e.into_inner());
                let n = sb.consume(buf);
                let mut notify = 0u32;
                if n > 0 {
                    sb.num_read += n as u32;
                    sb.incr += n as u32;
                    if sb.incr >= self.inner.window_update_threshold || sb.num_read == n as u32 {
                        notify = sb.num_read;
                        sb.incr = 0;
                    }
                }
                (n, notify)
            };

            if n > 0 {
                self.inner.sess.return_tokens(n as i32);
                if notify_consumed > 0 {
                    self.send_window_update(notify_consumed).await?;
                }
                return Ok(n);
            }

            if self.inner.die.is_fired() {
                return Ok(0);
            }

            self.wait_read().await?;
        }
    }

    async fn wait_read(&self) -> Result<()> {
        let reader = self.inner.reader_wakeup.notified();
        let fin = self.inner.fin_event.wait();
        let die = self.inner.die.wait();
        let read_err = self.inner.sess.read_error_signal.wait();
        let proto_err = self.inner.sess.proto_error_signal.wait();

        tokio::pin!(reader, fin, die, read_err, proto_err);

        tokio::select! {
            _ = reader => Ok(()),
            _ = fin => {
                let sb = self.inner.buffer.lock().unwrap_or_else(|e| e.into_inner());
                if !sb.is_empty() {
                    Ok(())
                } else {
                    Err(anyhow!("EOF"))
                }
            }
            _ = read_err => {
                Err(anyhow!("{}", self.inner.sess.read_error.get().map(String::as_str).unwrap_or("unknown error")))
            }
            _ = proto_err => {
                Err(anyhow!("{}", self.inner.sess.proto_error.get().map(String::as_str).unwrap_or("unknown error")))
            }
            _ = die => Err(anyhow!("broken pipe")),
        }
    }

    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.inner.write_closed.is_fired() || self.inner.die.is_fired() {
            return Err(anyhow!("broken pipe"));
        }

        if self.inner.sess.config.version == 2 {
            self.write_v2(data).await
        } else {
            self.write_v1(data).await
        }
    }

    async fn write_v1(&self, data: &[u8]) -> Result<usize> {
        let mut sent = 0;
        let mut remaining = data;

        while !remaining.is_empty() {
            let size = remaining.len().min(self.inner.frame_size);
            let chunk = &remaining[..size];

            let n = self
                .inner
                .sess
                .write_frame(
                    self.inner.sess.config.version,
                    CMD_PSH,
                    self.inner.id,
                    chunk,
                    None,
                )
                .await?;

            self.inner
                .num_written
                .fetch_add(size as u32, Ordering::AcqRel);
            sent += n;
            remaining = &remaining[size..];
        }

        Ok(sent)
    }

    async fn write_v2(&self, mut data: &[u8]) -> Result<usize> {
        let mut sent = 0;

        loop {
            let num_written = self.inner.num_written.load(Ordering::Acquire);
            let peer_consumed = self.inner.peer_consumed.load(Ordering::Acquire);
            let inflight = num_written.wrapping_sub(peer_consumed) as i32;
            if inflight < 0 {
                return Err(anyhow!("peer consumed more than sent"));
            }

            let peer_win = self.inner.peer_window.load(Ordering::Acquire);
            let win = (peer_win as i32) - inflight;

            if win > 0 {
                let n = data.len().min(win as usize);
                let mut chunk = &data[..n];

                while !chunk.is_empty() {
                    let size = chunk.len().min(self.inner.frame_size);
                    let frame_data = &chunk[..size];

                    let nw = self
                        .inner
                        .sess
                        .write_frame(
                            self.inner.sess.config.version,
                            CMD_PSH,
                            self.inner.id,
                            frame_data,
                            None,
                        )
                        .await?;

                    self.inner
                        .num_written
                        .fetch_add(size as u32, Ordering::AcqRel);
                    sent += nw;
                    chunk = &chunk[size..];
                }

                data = &data[n..];
            }

            if data.is_empty() {
                return Ok(sent);
            }

            let writer = self.inner.writer_wakeup.notified();
            let update = self.inner.update_notify.notified();
            let wc = self.inner.write_closed.wait();
            let die = self.inner.die.wait();
            let write_err = self.inner.sess.write_error_signal.wait();
            let fc_timeout = tokio::time::sleep(Duration::from_secs(30));

            tokio::pin!(writer, update, wc, die, write_err, fc_timeout);

            tokio::select! {
                _ = writer => continue,
                _ = update => continue,
                _ = wc => return Err(anyhow!("broken pipe")),
                _ = die => return Err(anyhow!("broken pipe")),
                _ = write_err => {
                    return Err(anyhow!("{}", self.inner.sess.write_error.get().map(String::as_str).unwrap_or("unknown error")));
                }
                _ = fc_timeout => return Err(anyhow!("timeout")),
            }
        }
    }

    async fn send_window_update(&self, consumed: u32) -> Result<()> {
        let mut upd = [0u8; SZ_CMD_UPD];
        encode_upd(
            &mut upd,
            consumed,
            self.inner.sess.config.max_stream_buffer as u32,
        );
        self.inner
            .sess
            .write_frame(
                self.inner.sess.config.version,
                CMD_UPD,
                self.inner.id,
                &upd,
                None,
            )
            .await?;
        Ok(())
    }

    pub async fn shutdown_write(&self) -> Result<()> {
        self.inner.write_closed.fire();
        if self.inner.try_send_fin() {
            let deadline = Some(tokio::time::Instant::now() + Duration::from_secs(30));
            let _ = self
                .inner
                .sess
                .write_frame(
                    self.inner.sess.config.version,
                    CMD_FIN,
                    self.inner.id,
                    &[],
                    deadline,
                )
                .await;
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.inner.die.fire();
        self.inner.write_closed.fire();

        if self.inner.try_send_fin() {
            let deadline = Some(tokio::time::Instant::now() + Duration::from_secs(30));
            let _ = self
                .inner
                .sess
                .write_frame(
                    self.inner.sess.config.version,
                    CMD_FIN,
                    self.inner.id,
                    &[],
                    deadline,
                )
                .await;
        }

        self.inner.sess.stream_closed(self.inner.id);
        Ok(())
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.inner.die.fire();
        self.inner.write_closed.fire();
        if self.inner.try_send_fin() {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                let deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                let _ = inner
                    .sess
                    .write_frame(inner.sess.config.version, CMD_FIN, inner.id, &[], deadline)
                    .await;
                inner.sess.stream_closed(inner.id);
            });
        } else {
            self.inner.sess.stream_closed(self.inner.id);
        }
    }
}
