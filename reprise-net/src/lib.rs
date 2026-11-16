//! `reprise-net` — role-agnostic QUIC transport for request/response, file
//! streaming, and change tracking.
//!
//! This crate provides the common networking machinery shared by client-server
//! and peer-to-peer applications:
//!
//! - **Protocol signature checking** ([`packet`]) — a typed envelope carrying a
//!   command discriminant and a layout fingerprint, so a peer rejects a
//!   mismatched command or wire layout before decoding.
//! - **Command identity** ([`Command`], [`command_set`]) — every wire message has
//!   a stable string id (independent of its Rust name) and a u32 discriminant;
//!   [`command_set`] groups commands into a matchable dispatch enum.
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
pub use packet::{Command, Message, Packet, PacketError};
pub use reprise_net_derive::{Command, Layout, command_set};
pub use rpc::{Transaction, send_transaction};
pub use type_hash::{Layout, TypeHash, discriminant};

/// The bincode configuration used for every message on the wire.
pub fn config() -> bincode::config::Configuration {
    bincode::config::standard()
}