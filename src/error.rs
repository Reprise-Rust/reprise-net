//! The crate-wide error type.

use thiserror::Error;

/// Errors produced by `reprise-net`.
#[derive(Debug, Error)]
pub enum Error {
    /// The peer's message layout does not match ours (protocol mismatch).
    #[error(transparent)]
    Packet(#[from] crate::packet::PacketError),

    /// A QUIC connection operation failed (open/accept/close).
    #[error("quic connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// A QUIC connect failed.
    #[error("quic connect: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// A QUIC read failed.
    #[error("quic read: {0}")]
    Read(#[from] quinn::ReadError),

    /// A QUIC read ended early.
    #[error("quic read exact: {0}")]
    ReadExact(#[from] quinn::ReadExactError),

    /// A QUIC read-to-end failed.
    #[error("quic read to end: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),

    /// A QUIC write failed.
    #[error("quic write: {0}")]
    Write(#[from] quinn::WriteError),

    /// A QUIC stream close failed.
    #[error("quic stream closed: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),

    /// An I/O operation failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A framed message exceeded the maximum allowed size.
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),

    /// A frame carried an unrecognized stream-kind discriminant.
    #[error("unknown stream kind: {0:#x}")]
    UnknownStreamKind(u32),

    /// A certificate could not be generated or parsed.
    #[error("certificate: {0}")]
    Certificate(String),

    /// An ed25519 key was invalid.
    #[error("key: {0}")]
    Key(String),

    /// A transfer timed out.
    #[error("timed out: {0}")]
    TimedOut(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;