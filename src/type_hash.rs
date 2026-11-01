//! Stable fingerprints of message layouts.
//!
//! We use bincode rather than a self-describing format, so there is no schema to
//! hash at runtime. Instead every wire type declares a canonical *layout string*
//! describing its bincode representation, and the fingerprint is the FNV-1a hash
//! of that string. Two builds that agree on the layout string produce the same
//! fingerprint; any wire-visible change must be reflected in the layout string,
//! which changes the fingerprint.

/// A 64-bit fingerprint identifying the wire layout of a message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeHash(pub u64);

impl TypeHash {
    /// Computes the fingerprint of a canonical layout string.
    pub const fn of(layout: &str) -> Self {
        Self(fnv1a(layout.as_bytes()))
    }
}

const fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(TypeHash::of("Request::Ping"), TypeHash::of("Request::Ping"));
    }

    #[test]
    fn distinct_layouts_differ() {
        assert_ne!(TypeHash::of("Request::Ping"), TypeHash::of("Request::Echo"));
    }
}