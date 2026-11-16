//! The upper packet envelope wrapping a bincode-encoded message.
//!
//! A [`Packet`] is a [`TypeHash`] followed by the bincode-encoded body. The hash
//! lets the receiver reject a payload whose layout differs from the one it was
//! compiled against *before* attempting to decode it. The [`crate::framing`]
//! layer adds the stream-kind byte and length prefix around the serialized
//! packet.

use bincode::{Decode, Encode};
use thiserror::Error;

use crate::type_hash::{TypeHash, discriminant};
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

/// A [`Message`] that carries a stable command identity on the wire.
///
/// The `ID` is a stable string independent of the Rust type name, so a command
/// can be renamed without changing its wire identity. The [`DISCRIMINANT`] is
/// the u32 tag written into a [`Packet`]; it is derived from `ID` at compile
/// time. Normally generated with `#[derive(Command)]`.
///
/// [`DISCRIMINANT`]: Command::DISCRIMINANT
pub trait Command: Message {
    /// The stable, human-readable command id (e.g. `"CreateProduct"`).
    const ID: &'static str;
    /// The u32 wire tag derived from [`ID`](Command::ID).
    const DISCRIMINANT: u32 = discriminant(Self::ID);
}

/// A transaction response is a `Result`; make it a [`Command`] so it can be
/// wrapped in a [`Packet`]. Its discriminant is derived from the two arms'
/// discriminants, so a `Result<T, E>` is distinguishable on the wire without a
/// hand-written id.
impl<T: Command, E: Command> Command for Result<T, E> {
    const ID: &'static str = "Result";
    const DISCRIMINANT: u32 = {
        let a = T::DISCRIMINANT.to_le_bytes();
        let b = E::DISCRIMINANT.to_le_bytes();
        crate::type_hash::xxh32(&[a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]], 0x5265_7375)
    };
}

/// A framed message: the command discriminant, the sender's type fingerprint,
/// and the encoded body.
///
/// The discriminant names *which* command this is; the type hash verifies that
/// the command's layout matches the receiver's. Both are checked before the
/// body is decoded, so a mismatched command or layout is rejected cleanly.
#[derive(Debug, Clone, Encode, Decode)]
pub struct Packet {
    pub discriminant: u32,
    pub type_hash: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("protocol mismatch: peer type hash {peer:#x} != local {local:#x}")]
    TypeMismatch { peer: u64, local: u64 },
    #[error("command mismatch: peer discriminant {peer:#x} != local {local:#x}")]
    CommandMismatch { peer: u32, local: u32 },
    #[error("unknown command discriminant {0:#x}")]
    UnknownCommand(u32),
    #[error("frame too short")]
    FrameTooShort,
    #[error("bincode encode failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("bincode decode failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

impl Packet {
    /// Wraps an already-encoded message body together with its discriminant and
    /// type hash.
    pub fn new(discriminant: u32, type_hash: TypeHash, payload: Vec<u8>) -> Self {
        Self {
            discriminant,
            type_hash: type_hash.0,
            payload,
        }
    }

    /// Encodes a command into a packet, filling its discriminant and type hash.
    pub fn encode<M: Command>(msg: &M) -> Result<Self, PacketError> {
        let payload = bincode::encode_to_vec(msg, crate::config())?;
        Ok(Self::new(M::DISCRIMINANT, M::TYPE_HASH, payload))
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

    /// Verifies the envelope's discriminant and type hash match `M`, then
    /// decodes the body.
    pub fn decode<M: Command>(&self) -> Result<M, PacketError> {
        if self.discriminant != M::DISCRIMINANT {
            return Err(PacketError::CommandMismatch {
                peer: self.discriminant,
                local: M::DISCRIMINANT,
            });
        }
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
    impl Command for Ping {
        const ID: &'static str = "Ping";
    }

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

    #[test]
    fn command_mismatch_detected() {
        let req = Ping { value: 1 };
        let mut packet = Packet::encode(&req).unwrap();
        packet.discriminant ^= 0xdead_beef;
        assert!(matches!(
            packet.decode::<Ping>(),
            Err(PacketError::CommandMismatch { .. })
        ));
    }
}