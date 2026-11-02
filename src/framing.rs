//! Length-prefixed framing for a QUIC stream.
//!
//! A frame is a 1-byte stream kind, a big-endian `u32` byte length, and that
//! many body bytes. The kind byte tells the peer what the stream is for, so it
//! knows which packet sequence to expect (see [`StreamKind`]). The length prefix
//! is independent of any serialization format; the [`crate::packet`] layer wraps
//! a bincode-encoded message in this framing.

/// The number of bytes in the length prefix.
pub const LEN_PREFIX: usize = 4;

/// The number of bytes in the stream-kind prefix.
pub const KIND_PREFIX: usize = 1;

/// The stream-kind discriminant written as the first byte of every frame.
///
/// It names the stream's purpose, so the peer reads it and knows the exact
/// packet sequence to expect for the rest of the stream. Raw file bytes are not
/// framed and are delimited by QUIC FIN instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamKind {
    /// Bidirectional: one request frame, then one response frame.
    Transaction = 0,
    /// Bidirectional: header frame, then raw bytes (FIN), then a result frame.
    Upload = 1,
    /// Bidirectional: header frame, then a meta/error frame, then raw bytes (FIN).
    Download = 2,
    /// Unidirectional (server→client): notification frames until FIN.
    Notification = 3,
}

impl StreamKind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(StreamKind::Transaction),
            1 => Some(StreamKind::Upload),
            2 => Some(StreamKind::Download),
            3 => Some(StreamKind::Notification),
            _ => None,
        }
    }
}

/// Prepends a stream-kind byte and a big-endian `u32` length prefix to `body`.
pub fn prepend_kind_length(kind: StreamKind, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KIND_PREFIX + LEN_PREFIX + body.len());
    out.push(kind as u8);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Strips a stream-kind byte and big-endian `u32` length prefix, returning the
/// kind and the body slice.
///
/// Returns `None` if the frame is shorter than the prefixes or the declared body.
pub fn strip_kind_length(frame: &[u8]) -> Option<(StreamKind, &[u8])> {
    if frame.len() < KIND_PREFIX + LEN_PREFIX {
        return None;
    }
    let kind = StreamKind::from_byte(frame[0])?;
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
    fn rejects_unknown_kind() {
        assert_eq!(strip_kind_length(&[99, 0, 0, 0, 0]), None);
    }

    #[test]
    fn rejects_short_frame() {
        assert_eq!(strip_kind_length(b""), None);
        assert_eq!(strip_kind_length(b"\x00"), None);
        assert_eq!(strip_kind_length(b"\x00\x00\x00\x00"), None);
    }

    #[test]
    fn rejects_truncated_body() {
        let mut frame = vec![StreamKind::Transaction as u8];
        frame.extend_from_slice(&10u32.to_be_bytes());
        frame.extend_from_slice(b"ab");
        assert_eq!(strip_kind_length(&frame), None);
    }
}