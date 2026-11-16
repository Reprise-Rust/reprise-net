//! General-purpose file transfer over QUIC streams, with resume.
//!
//! A file transfer moves raw bytes between two peers over a single QUIC stream,
//! in fixed-size chunks with a per-chunk timeout (so a stalled transfer aborts
//! quickly rather than blocking). The direction is determined by which peer
//! opens the stream and which drives the bytes; there is no client/server role.
//!
//! ## Resume
//!
//! The *receiver* (the peer persisting bytes) is the one that knows how much it
//! already has, so it is the receiver that tells the sender where to continue
//! from. The resume offset is therefore a protocol-level concern carried by the
//! caller (e.g. an `offset` field on the request), not by this module: the
//! sender passes the offset to [`send_file`] to seek its source, and the
//! receiver's sink is already positioned at its persisted offset when
//! [`recv_file`] runs.
//!
//! The caller supplies a small [`Send`] / [`Recv`] pair that owns the actual
//! byte source/sink (typically a file), so this module stays independent of any
//! particular storage backend.

use quinn::{RecvStream, SendStream};
use std::time::Duration;

use crate::error::{Error, Result};

/// The size of a single transfer chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// The per-chunk read/write timeout.
pub const CHUNK_TIMEOUT: Duration = Duration::from_millis(500);

/// A byte source on the sending side (typically a file opened for reading).
pub trait Send {
    /// Seeks to `offset` from the start, so the transfer can resume.
    fn seek(&mut self, offset: u64) -> std::io::Result<()>;
    /// Reads up to `buf.len()` bytes, returning the number read (0 = EOF).
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// The total length of the source in bytes, if known.
    fn total_len(&self) -> Option<u64>;
}

/// A byte sink on the receiving side (typically a file opened for writing).
pub trait Recv {
    /// Writes `bytes` at the current position.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// The number of bytes already persisted, to resume from.
    fn offset(&self) -> u64;
}

/// Streams bytes from `source` to `stream`, starting at `offset` (for resume).
///
/// Returns the number of bytes sent. The stream is finished on success.
pub async fn send_file(
    mut stream: SendStream,
    source: &mut impl Send,
    offset: u64,
) -> Result<u64> {
    source.seek(offset)?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut sent: u64 = 0;
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        tokio::time::timeout(CHUNK_TIMEOUT, stream.write_all(&buf[..n]))
            .await
            .map_err(|_| Error::TimedOut("write chunk"))??;
        sent += n as u64;
    }
    stream.finish()?;
    Ok(sent)
}

/// Receives bytes from `stream` into `sink`, which is already positioned at its
/// persisted offset (for resume).
///
/// Returns the number of bytes received.
pub async fn recv_file(stream: &mut RecvStream, sink: &mut impl Recv) -> Result<u64> {
    let mut received: u64 = 0;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let read = tokio::time::timeout(CHUNK_TIMEOUT, stream.read(&mut buf))
            .await
            .map_err(|_| Error::TimedOut("read chunk"))??;
        match read {
            Some(0) | None => break,
            Some(n) => {
                sink.write(&buf[..n])?;
                received += n as u64;
            }
        }
    }
    Ok(received)
}