//! QUIC peer authentication helpers.
//!
//! Each peer has an ed25519 identity. The QUIC handshake is authenticated by a
//! self-signed certificate whose public key *is* the peer's ed25519 verifying
//! key, and the other side verifies that the certificate's public key matches
//! the expected peer key.

use std::sync::Arc;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use quinn::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use quinn::rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rcgen::{CertificateParams, PKCS_ED25519};

use crate::error::Error;

/// Generates a self-signed certificate/private-key pair from an ed25519 signing
/// key. The certificate's subject public key equals the ed25519 verifying key,
/// which is how peers authenticate each other.
pub fn cert_from_key(
    signing_key: &SigningKey,
) -> crate::error::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let pkcs8_bytes = signing_key
        .to_pkcs8_der()
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let private_key = PrivateKeyDer::Pkcs8(pkcs8_bytes.as_bytes().to_vec().into());

    let keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &pkcs8_bytes.as_bytes().into(),
        &PKCS_ED25519,
    )
    .map_err(|e| Error::Certificate(e.to_string()))?;
    let params = CertificateParams::new(vec!["reprise".to_string()])
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let cert = params
        .self_signed(&keypair)
        .map_err(|e| Error::Certificate(e.to_string()))?;

    Ok((cert.der().clone(), private_key))
}

/// A rustls verifier that accepts a peer only if its certificate's public key
/// matches `expected_pubkey`. Used on both sides of the connection.
#[derive(Debug)]
pub struct PeerPublicKeyVerifier {
    expected_pubkey: VerifyingKey,
}

impl PeerPublicKeyVerifier {
    pub fn new(expected_pubkey: VerifyingKey) -> Self {
        Self { expected_pubkey }
    }
}

fn cert_matches(cert: &CertificateDer<'_>, expected: &VerifyingKey) -> bool {
    let Ok((_, x509)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
        return false;
    };
    let peer_pubkey_bytes = x509.tbs_certificate.subject_pki.subject_public_key.data;
    peer_pubkey_bytes.as_ref() == expected.as_bytes()
}

fn ring() -> &'static WebPkiSupportedAlgorithms {
    use std::sync::OnceLock;
    static PROVIDER: OnceLock<rustls::crypto::CryptoProvider> = OnceLock::new();
    &PROVIDER
        .get_or_init(rustls::crypto::ring::default_provider)
        .signature_verification_algorithms
}

/// Installs the *ring* crypto provider as the process default.
///
/// Both `aws-lc-rs` and `ring` can end up enabled through a dependency graph
/// (quinn + sqlx), which prevents rustls from auto-selecting a provider. We pin
/// `ring` explicitly so every TLS/QUIC handshake uses a single provider.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl ServerCertVerifier for PeerPublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !cert_matches(end_entity, &self.expected_pubkey) {
            return Err(rustls::Error::General("Peer public key mismatch!".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, ring())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, ring())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring().supported_schemes()
    }
}

impl ClientCertVerifier for PeerPublicKeyVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !cert_matches(end_entity, &self.expected_pubkey) {
            return Err(rustls::Error::General("Peer public key mismatch!".into()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, ring())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, ring())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring().supported_schemes()
    }
}

/// Wraps a verifier in an `Arc`, the form rustls expects.
pub fn peer_verifier(expected_pubkey: VerifyingKey) -> Arc<PeerPublicKeyVerifier> {
    Arc::new(PeerPublicKeyVerifier::new(expected_pubkey))
}

/// A client-cert verifier that accepts any certificate, so a listener can
/// request client authentication and then inspect the presented public key
/// itself (checking it against a trusted set that changes at runtime).
///
/// The listener performs the actual trust decision after the handshake, by
/// extracting the peer's public key from the connection.
#[derive(Debug)]
pub struct AcceptAnyClient;

impl ClientCertVerifier for AcceptAnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, ring())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, ring())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring().supported_schemes()
    }
}

/// Extracts the ed25519 public key from a peer's certificate chain, as returned
/// by `quinn::Connection::peer_identity()`.
pub fn pubkey_from_peer_identity(identity: &dyn std::any::Any) -> Option<[u8; 32]> {
    let certs = identity.downcast_ref::<Vec<CertificateDer<'static>>>()?;
    let cert = certs.first()?;
    let (_, x509) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let bytes = x509.tbs_certificate.subject_pki.subject_public_key.data;
    let arr: [u8; 32] = bytes.as_ref().try_into().ok()?;
    Some(arr)
}