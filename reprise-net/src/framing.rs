//! Length-prefixed framing for a QUIC stream.
//!
//! A frame is a big-endian `u32` stream kind, a big-endian `u32` byte length,
//! and that many body bytes. The kind tells the peer what the stream is for, so
//! it knows which packet sequence to expect (see [`StreamKind`]). The length
//! prefix is independent of any serialization format; the [`crate::packet`]
//! layer wraps a bincode-encoded message in this framing.

use crate::type_hash::discriminant;

/// The number of bytes in the length prefix.
pub const LEN_PREFIX: usize = 4;

/// The number of bytes in the stream-kind prefix.
pub const KIND_PREFIX: usize = 4;

/// The stream-kind discriminant written as the first four bytes of every frame.
///
/// It names the stream's purpose, so the peer reads it and knows the exact
/// packet sequence to expect for the rest of the stream. Raw file bytes are not
/// framed and are delimited by QUIC FIN instead.
///
/// The wire value of each variant is `xxh32(ID)`, derived at compile time from a
/// stable string id — the same scheme [`crate::Command`] uses. Because the value
/// depends only on the id, adding or removing a variant from the middle of the
/// enum never shifts the wire identity of the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Bidirectional: one request frame, then one response frame.
    Transaction,
    /// Bidirectional: header frame, then raw bytes (FIN), then a result frame.
    Upload,
    /// Bidirectional: header frame, then a meta/error frame, then raw bytes (FIN).
    Download,
    /// Unidirectional (server→client): notification frames until FIN.
    Notification,
}

impl StreamKind {
    /// The stable string id whose hash is the wire discriminant.
    pub const fn id(self) -> &'static str {
        match self {
            StreamKind::Transaction => "StreamKind::Transaction",
            StreamKind::Upload => "StreamKind::Upload",
            StreamKind::Download => "StreamKind::Download",
            StreamKind::Notification => "StreamKind::Notification",
        }
    }

    /// The u32 wire discriminant derived from [`id`](StreamKind::id).
    pub const fn discriminant(self) -> u32 {
        discriminant(self.id())
    }

    /// Resolves a wire discriminant back to a stream kind.
    pub fn from_discriminant(discriminant: u32) -> Option<Self> {
        match discriminant {
            d if d == StreamKind::Transaction.discriminant() => Some(StreamKind::Transaction),
            d if d == StreamKind::Upload.discriminant() => Some(StreamKind::Upload),
            d if d == StreamKind::Download.discriminant() => Some(StreamKind::Download),
            d if d == StreamKind::Notification.discriminant() => Some(StreamKind::Notification),
            _ => None,
        }
    }
}

// Compile-time check that all stream-kind discriminants are pairwise distinct.
const _: () = {
    const KINDS: [StreamKind; 4] = [
        StreamKind::Transaction,
        StreamKind::Upload,
        StreamKind::Download,
        StreamKind::Notification,
    ];
    let mut i = 0;
    while i < KINDS.len() {
        let mut j = i + 1;
        while j < KINDS.len() {
            assert!(
                KINDS[i].discriminant() != KINDS[j].discriminant(),
                "stream kind discriminant collision"
            );
            j += 1;
        }
        i += 1;
    }
};

/// Prepends a stream-kind discriminant and a big-endian `u32` length prefix to
/// `body`.
pub fn prepend_kind_length(kind: StreamKind, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KIND_PREFIX + LEN_PREFIX + body.len());
    out.extend_from_slice(&kind.discriminant().to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Strips a stream-kind discriminant and big-endian `u32` length prefix,
/// returning the kind and the body slice.
///
/// Returns `None` if the frame is shorter than the prefixes, the declared body,
/// or if the kind is unrecognized.
pub fn strip_kind_length(frame: &[u8]) -> Option<(StreamKind, &[u8])> {
    if frame.len() < KIND_PREFIX + LEN_PREFIX {
        return None;
    }
    let kind = StreamKind::from_discriminant(u32::from_be_bytes(
        frame[..KIND_PREFIX].try_into().unwrap(),
    ))?;
    let len = u32::from_be_bytes(
        frame[KIND_PREFIX..KIND_PREFIX + LEN_PREFIX]
            .try_into()
            .unwrap(),
    ) as usize;
    let body = &frame[KIND_PREFIX + LEN_PREFIX..];
    if body.len() < len {
        return None;
    }
    Some((kind, &body[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_length_roundtrip() {
        let body = b"hello";
        let framed = prepend_kind_length(StreamKind::Transaction, body);
        assert_eq!(
            strip_kind_length(&framed),
            Some((StreamKind::Transaction, &body[..]))
        );
    }

    #[test]
    fn distinguishes_kinds() {
        let a = prepend_kind_length(StreamKind::Upload, b"x");
        let b = prepend_kind_length(StreamKind::Download, b"x");
        assert_ne!(strip_kind_length(&a), strip_kind_length(&b));
    }

    #[test]
    fn discriminant_roundtrips() {
        for kind in [
            StreamKind::Transaction,
            StreamKind::Upload,
            StreamKind::Download,
            StreamKind::Notification,
        ] {
            assert_eq!(StreamKind::from_discriminant(kind.discriminant()), Some(kind));
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut frame = vec![0xde, 0xad, 0xbe, 0xef];
        frame.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(strip_kind_length(&frame), None);
    }

    #[test]
    fn rejects_short_frame() {
        assert_eq!(strip_kind_length(b""), None);
        assert_eq!(strip_kind_length(b"\x00"), None);
        assert_eq!(strip_kind_length(b"\x00\x00\x00\x00"), None);
        assert_eq!(strip_kind_length(b"\x00\x00\x00\x00\x00\x00\x00"), None);
    }

    #[test]
    fn rejects_truncated_body() {
        let mut frame = StreamKind::Transaction.discriminant().to_be_bytes().to_vec();
        frame.extend_from_slice(&10u32.to_be_bytes());
        frame.extend_from_slice(b"ab");
        assert_eq!(strip_kind_length(&frame), None);
    }
}
