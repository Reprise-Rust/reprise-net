//! The upper packet envelope wrapping a bincode-encoded message.
//!
//! A [`Packet`] is a [`TypeHash`] followed by the bincode-encoded body. The hash
//! lets the receiver reject a payload whose layout differs from the one it was
//! compiled against *before* attempting to decode it. The [`crate::framing`]
//! layer adds the stream-kind byte and length prefix around the serialized
//! packet.

use bincode::{Decode, Encode};
use thiserror::Error;

use crate::type_hash::TypeHash;
use crate::Layout;

/// A wire message that can be encoded with bincode and identified by a stable
/// type fingerprint.
///
/// The fingerprint comes from the [`Layout`] impl, which is normally generated
/// with `#[derive(Layout)]`.
pub trait Message: Encode + Decode<()> + Layout {}

/// A transaction response is a `Result`; make it a first-class [`Message`] so
/// `Transaction::Response` can be `Result<T, ApiError>`.
impl<T: Message, E: Message> Message for Result<T, E> {}

/// A framed message: the sender's type fingerprint plus the encoded body.
#[derive(Debug, Clone, Encode, Decode)]
pub struct Packet {
    pub type_hash: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("protocol mismatch: peer type hash {peer:#x} != local {local:#x}")]
    TypeMismatch { peer: u64, local: u64 },
    #[error("frame too short")]
    FrameTooShort,
    #[error("bincode encode failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("bincode decode failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

impl Packet {
    /// Wraps an already-encoded message body together with its type hash.
    pub fn new(type_hash: TypeHash, payload: Vec<u8>) -> Self {
        Self {
            type_hash: type_hash.0,
            payload,
        }
    }

    /// Encodes a message into a packet.
    pub fn encode<M: Message>(msg: &M) -> Result<Self, PacketError> {
        let payload = bincode::encode_to_vec(msg, crate::config())?;
        Ok(Self::new(M::TYPE_HASH, payload))
    }

    /// Serializes the whole packet (envelope + body) into bytes for the wire.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PacketError> {
        Ok(bincode::encode_to_vec(self, crate::config())?)
    }

    /// Parses a packet from raw wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PacketError> {
        let (packet, _): (Packet, usize) =
            bincode::decode_from_slice(bytes, crate::config())?;
        Ok(packet)
    }

    /// Verifies the envelope's type hash matches `M`, then decodes the body.
    pub fn decode<M: Message>(&self) -> Result<M, PacketError> {
        if self.type_hash != M::TYPE_HASH.0 {
            return Err(PacketError::TypeMismatch {
                peer: self.type_hash,
                local: M::TYPE_HASH.0,
            });
        }
        let (msg, _): (M, usize) =
            bincode::decode_from_slice(&self.payload, crate::config())?;
        Ok(msg)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Encode, Decode, Layout)]
    struct Ping {
        value: u64,
    }

    impl Message for Ping {}

    #[test]
    fn packet_roundtrip() {
        let req = Ping { value: 42 };
        let packet = Packet::encode(&req).unwrap();
        let bytes = packet.to_bytes().unwrap();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        let decoded: Ping = parsed.decode().unwrap();
        assert_eq!(decoded.value, 42);
    }

    #[test]
    fn type_mismatch_detected() {
        let req = Ping { value: 1 };
        let mut packet = Packet::encode(&req).unwrap();
        packet.type_hash ^= 0xdead_beef;
        assert!(matches!(
            packet.decode::<Ping>(),
            Err(PacketError::TypeMismatch { .. })
        ));
    }
}