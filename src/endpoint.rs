//! Role-agnostic QUIC endpoint construction.
//!
//! A [`Peer`] packages an ed25519 identity with the TLS/QUIC configuration so a
//! single endpoint can both dial out to, and accept connections from, other
//! peers. There is no client/server distinction here: any peer can dial any
//! other peer, and any peer can listen.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig};

use crate::error::{Error, Result};
use crate::quic::{AcceptAnyClient, cert_from_key, peer_verifier};
use crate::transport::shared_transport_config;

/// A peer identity: an ed25519 signing key plus the derived self-signed
/// certificate used during the QUIC handshake.
pub struct Peer {
    signing_key: SigningKey,
    cert: quinn::rustls::pki_types::CertificateDer<'static>,
    key: quinn::rustls::pki_types::PrivateKeyDer<'static>,
}

impl Peer {
    /// Builds a peer from an ed25519 signing key.
    pub fn new(signing_key: SigningKey) -> Result<Self> {
        let (cert, key) = cert_from_key(&signing_key)?;
        Ok(Self {
            signing_key,
            cert,
            key,
        })
    }

    /// The peer's ed25519 public key (its identity on the wire).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Builds a client (dialing) config that authenticates the server against
    /// `expected_server_pubkey`.
    pub fn client_config(&self, expected_server_pubkey: [u8; 32]) -> Result<ClientConfig> {
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&expected_server_pubkey)
            .map_err(|e| Error::Key(e.to_string()))?;
        let verifier = peer_verifier(verifying);

        let rustls_config = quinn::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(|e| Error::Certificate(e.to_string()))?;

        let quic_config = QuicClientConfig::try_from(rustls_config)
            .map_err(|e| Error::Certificate(e.to_string()))?;
        let mut config = ClientConfig::new(Arc::new(quic_config));
        config.transport_config(shared_transport_config());
        Ok(config)
    }

    /// Builds a server (listening) config that accepts any client certificate
    /// and defers the trust decision to the caller (via the peer's public key).
    pub fn server_config(&self) -> Result<ServerConfig> {
        let rustls_config = quinn::rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(AcceptAnyClient))
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
            .map_err(|e| Error::Certificate(e.to_string()))?;

        let quic_config = QuicServerConfig::try_from(rustls_config)
            .map_err(|e| Error::Certificate(e.to_string()))?;
        let mut config = ServerConfig::with_crypto(Arc::new(quic_config));
        config.transport_config(shared_transport_config());
        Ok(config)
    }

    /// Creates a dialing endpoint bound to an ephemeral local socket, with the
    /// default client config set to authenticate `expected_server_pubkey`.
    pub fn dialing_endpoint(&self, expected_server_pubkey: [u8; 32]) -> Result<Endpoint> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.client_config(expected_server_pubkey)?);
        Ok(endpoint)
    }

    /// Creates a listening endpoint bound to `addr`, accepting any client.
    pub fn listening_endpoint(&self, addr: std::net::SocketAddr) -> Result<Endpoint> {
        let socket = std::net::UdpSocket::bind(addr)?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(self.server_config()?),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(endpoint)
    }
}