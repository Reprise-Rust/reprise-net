//! Length-prefixed framing for a QUIC stream.
//!
//! A frame is a big-endian `u32` byte length followed by that many bytes. This
//! is independent of any serialization format; the [`crate::packet`] layer wraps
//! a bincode-encoded message in this framing.

/// The number of bytes in the length prefix.
pub const LEN_PREFIX: usize = 4;

/// Prepends a big-endian `u32` length prefix to `body`.
pub fn prepend_length(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Strips a big-endian `u32` length prefix, returning the body slice.
///
/// Returns `None` if the frame is shorter than the prefix or the declared body.
pub fn strip_length(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < LEN_PREFIX {
        return None;
    }
    let len = u32::from_be_bytes(frame[..LEN_PREFIX].try_into().unwrap()) as usize;
    let body = &frame[LEN_PREFIX..];
    if body.len() < len {
        return None;
    }
    Some(&body[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let body = b"hello";
        let framed = prepend_length(body);
        assert_eq!(strip_length(&framed), Some(&body[..]));
    }

    #[test]
    fn rejects_short_frame() {
        assert_eq!(strip_length(b""), None);
        assert_eq!(strip_length(b"\x00"), None);
        assert_eq!(strip_length(b"\x00\x00\x00"), None);
    }

    #[test]
    fn rejects_truncated_body() {
        // Declares 10 bytes but only carries 2.
        let mut frame = vec![0u8; 4];
        frame[..4].copy_from_slice(&10u32.to_be_bytes());
        frame.extend_from_slice(b"ab");
        assert_eq!(strip_length(&frame), None);
    }
}