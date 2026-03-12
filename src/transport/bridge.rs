use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::disguise::tls::{FakeTlsReadHalf, FakeTlsStream, FakeTlsWriteHalf};

const BRIDGE_FRAME_BUF: usize = 256 * 1024;

fn padded_size(real_len: usize) -> usize {
    match real_len {
        0..=64 => fastrand::usize(200..300),
        65..=256 => fastrand::usize(400..600),
        257..=1024 => fastrand::usize(1800..2200),
        1025..=4096 => fastrand::usize(4000..4200),
        _ => real_len,
    }
}

pub struct FakeTlsBridge {
    read_half: FakeTlsReadHalf,
    write_half: FakeTlsWriteHalf,
    br_hdr: [u8; 8],
    br_hdr_filled: usize,
    br_real_rem: usize,
    br_skip_rem: usize,
    bw_input_len: usize,
}

pub fn bridge(tls: FakeTlsStream) -> FakeTlsBridge {
    let (read_half, write_half) = tls.into_split();
    FakeTlsBridge {
        read_half,
        write_half,
        br_hdr: [0u8; 8],
        br_hdr_filled: 0,
        br_real_rem: 0,
        br_skip_rem: 0,
        bw_input_len: 0,
    }
}

impl AsyncRead for FakeTlsBridge {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.br_real_rem > 0 {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                let to_read = buf.remaining().min(this.br_real_rem);
                let old_filled = buf.filled().len();
                let n = {
                    let slice = buf.initialize_unfilled_to(to_read);
                    let mut sub = ReadBuf::new(slice);
                    match Pin::new(&mut this.read_half).poll_read(cx, &mut sub) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => sub.filled().len(),
                    }
                };
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                buf.set_filled(old_filled + n);
                this.br_real_rem -= n;
                return Poll::Ready(Ok(()));
            }

            if this.br_skip_rem > 0 {
                if this.read_half.read_pos < this.read_half.read_buf.len() {
                    let avail = this.read_half.read_buf.len() - this.read_half.read_pos;
                    let skip = this.br_skip_rem.min(avail);
                    this.read_half.read_pos += skip;
                    this.br_skip_rem -= skip;
                    continue;
                }
                let mut empty: [u8; 0] = [];
                let mut zero_rb = ReadBuf::new(&mut empty);
                match Pin::new(&mut this.read_half).poll_read(cx, &mut zero_rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if this.read_half.read_pos >= this.read_half.read_buf.len() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "eof in bridge frame padding",
                            )));
                        }
                    }
                }
                continue;
            }

            if this.br_hdr_filled < 8 {
                let mut hdr_rb = ReadBuf::new(&mut this.br_hdr[this.br_hdr_filled..]);
                match Pin::new(&mut this.read_half).poll_read(cx, &mut hdr_rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = hdr_rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.br_hdr_filled += n;
                    }
                }
                if this.br_hdr_filled < 8 {
                    continue;
                }
            }

            let frame_len = u32::from_be_bytes([
                this.br_hdr[0],
                this.br_hdr[1],
                this.br_hdr[2],
                this.br_hdr[3],
            ]) as usize;
            let real_len = u32::from_be_bytes([
                this.br_hdr[4],
                this.br_hdr[5],
                this.br_hdr[6],
                this.br_hdr[7],
            ]) as usize;

            if real_len > frame_len {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid bridge frame: real_len > frame_len",
                )));
            }

            this.br_hdr_filled = 0;
            this.br_real_rem = real_len;
            this.br_skip_rem = frame_len - real_len;
        }
    }
}

impl AsyncWrite for FakeTlsBridge {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        loop {
            if this.write_half.write_pos < this.write_half.write_buf.len() {
                let n = {
                    let data = &this.write_half.write_buf[this.write_half.write_pos..];
                    match Pin::new(&mut this.write_half.inner).poll_write(cx, data) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero",
                            )));
                        }
                        Poll::Ready(Ok(n)) => n,
                    }
                };
                this.write_half.write_pos += n;
                if this.write_half.write_pos < this.write_half.write_buf.len() {
                    continue;
                }
                let consumed = this.bw_input_len;
                this.write_half.write_pos = 0;
                this.write_half.write_buf.clear();
                return Poll::Ready(Ok(consumed));
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            let real_len = buf.len().min(BRIDGE_FRAME_BUF);
            let frame_len = padded_size(real_len);
            let pad_len = frame_len - real_len;
            let mut hdr = [0u8; 8];
            hdr[..4].copy_from_slice(&(frame_len as u32).to_be_bytes());
            hdr[4..].copy_from_slice(&(real_len as u32).to_be_bytes());
            this.write_half
                .encode_bridge_frame(&hdr, &buf[..real_len], pad_len);
            this.bw_input_len = real_len;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write_half.inner).poll_flush(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        loop {
            if this.write_half.write_pos < this.write_half.write_buf.len() {
                let n = {
                    let data = &this.write_half.write_buf[this.write_half.write_pos..];
                    match Pin::new(&mut this.write_half.inner).poll_write(cx, data) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero",
                            )));
                        }
                        Poll::Ready(Ok(n)) => n,
                    }
                };
                this.write_half.write_pos += n;
                if this.write_half.write_pos < this.write_half.write_buf.len() {
                    continue;
                }
                let consumed = this.bw_input_len;
                this.write_half.write_pos = 0;
                this.write_half.write_buf.clear();
                return Poll::Ready(Ok(consumed));
            }

            let mut total_input = 0usize;
            let mut slices: Vec<&[u8]> = Vec::with_capacity(bufs.len());
            for buf in bufs.iter().filter(|b| !b.is_empty()) {
                let take = buf.len().min(BRIDGE_FRAME_BUF - total_input);
                if take == 0 {
                    break;
                }
                slices.push(&buf[..take]);
                total_input += take;
            }

            if total_input == 0 {
                return Poll::Ready(Ok(0));
            }

            let frame_len = padded_size(total_input);
            let pad_len = frame_len - total_input;
            let mut hdr = [0u8; 8];
            hdr[..4].copy_from_slice(&(frame_len as u32).to_be_bytes());
            hdr[4..].copy_from_slice(&(total_input as u32).to_be_bytes());
            this.write_half
                .encode_bridge_frame_multi(&hdr, &slices, pad_len);
            this.bw_input_len = total_input;
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write_half.inner).poll_shutdown(cx)
    }
}
