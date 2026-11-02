//! `reprise-net` — role-agnostic QUIC transport for request/response, file
//! streaming, and change tracking.
//!
//! This crate provides the common networking machinery shared by client-server
//! and peer-to-peer applications:
//!
//! - **Protocol signature checking** ([`packet`]) — a typed envelope that
//!   detects wire-layout mismatches before decoding.
//! - **Peer authentication** ([`quic`], [`endpoint`]) — ed25519 identities via
//!   self-signed certificates, with no client/server distinction.
//! - **Request/response** ([`rpc`]) — framed transactions over bidirectional
//!   streams.
//! - **File streaming** ([`file`]) — chunked byte transfer with resume.
//! - **Change tracking** ([`version`]) — a client-side cache of per-resource
//!   versions with a staleness-free fetch helper.
//!
//! There is no notion of "client" or "server" here: any peer can dial any other
//! peer, and any peer can listen.

// Lets `#[derive(Layout)]`-generated code refer to `::reprise_net::...` even
// from within this crate.
extern crate self as reprise_net;

pub mod endpoint;
pub mod error;
pub mod file;
pub mod framing;
pub mod packet;
pub mod quic;
pub mod rpc;
pub mod transport;
pub mod type_hash;
pub mod version;

pub use endpoint::Peer;
pub use error::{Error, Result};
pub use framing::StreamKind;
pub use packet::{Message, Packet, PacketError};
pub use reprise_net_derive::Layout;
pub use rpc::{Transaction, send_transaction};
pub use type_hash::{Layout, TypeHash};

/// The bincode configuration used for every message on the wire.
pub fn config() -> bincode::config::Configuration {
    bincode::config::standard()
}