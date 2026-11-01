//! QUIC transport parameters shared by every peer.
//!
//! All peers must agree on idle timeout and keep-alive so that a connection is
//! not torn down by one peer while the other still considers it alive. Kept here
//! so peers never drift apart.

use std::sync::Arc;
use std::time::Duration;

use quinn::TransportConfig;

/// How long a connection may sit idle before QUIC closes it.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often keep-alive packets are sent while a connection is idle.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Builds the shared QUIC transport config.
pub fn transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(MAX_IDLE_TIMEOUT.try_into().unwrap()));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport
}

/// Convenience wrapper returning the shared config as `Arc<TransportConfig>`,
/// the form quinn's `ClientConfig`/`ServerConfig` expect.
pub fn shared_transport_config() -> Arc<TransportConfig> {
    Arc::new(transport_config())
}