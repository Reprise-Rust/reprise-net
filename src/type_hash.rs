//! Stable fingerprints of message layouts.
//!
//! We use bincode rather than a self-describing format, so there is no schema to
//! hash at runtime. Instead every wire type derives a fingerprint describing its
//! bincode representation (see [`Layout`]).
//!
//! A type's fingerprint is a fold of its own name and the fingerprints of its
//! field types, so composite types recurse automatically: a change to any nested
//! type propagates to every type that contains it. Everything is computed in
//! `const` context, so the fingerprint is baked into the binary.

/// A stable fingerprint of a type's bincode representation.
///
/// Implementations compose: a struct's fingerprint folds in the
/// [`TYPE_HASH`](Layout::TYPE_HASH) of each field type, so nested and generic
/// types are covered transitively. The value is a compile-time constant.
pub trait Layout {
    /// The fingerprint of this type's wire layout.
    const TYPE_HASH: TypeHash;
}

/// A 64-bit fingerprint identifying the wire layout of a message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeHash(pub u64);

impl TypeHash {
    /// Computes the fingerprint of a canonical layout string.
    pub const fn of(layout: &str) -> Self {
        Self(fnv1a(layout.as_bytes()))
    }

    /// Folds another fingerprint into this one, producing a new fingerprint.
    ///
    /// Used to compose a type's fingerprint from the fingerprints of its fields.
    pub const fn combine(self, other: TypeHash) -> Self {
        Self(fnv1a_bytes(&self.0.to_le_bytes(), other.0))
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

/// Continues an FNV-1a hash over `bytes`, then folds in `tail`.
const fn fnv1a_bytes(bytes: &[u8], tail: u64) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash ^= tail;
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    hash
}

macro_rules! layout_primitive {
    ($($ty:ty => $name:literal),* $(,)?) => {
        $(
            impl Layout for $ty {
                const TYPE_HASH: TypeHash = TypeHash::of($name);
            }
        )*
    };
}

layout_primitive! {
    bool => "bool",
    u8 => "u8",
    u16 => "u16",
    u32 => "u32",
    u64 => "u64",
    u128 => "u128",
    i8 => "i8",
    i16 => "i16",
    i32 => "i32",
    i64 => "i64",
    i128 => "i128",
    f32 => "f32",
    f64 => "f64",
    char => "char",
    String => "String",
    str => "str",
}

impl<T: Layout> Layout for Option<T> {
    const TYPE_HASH: TypeHash = TypeHash::of("Option").combine(T::TYPE_HASH);
}

impl<T: Layout> Layout for Vec<T> {
    const TYPE_HASH: TypeHash = TypeHash::of("Vec").combine(T::TYPE_HASH);
}

impl<T: Layout + ?Sized> Layout for Box<T> {
    const TYPE_HASH: TypeHash = TypeHash::of("Box").combine(T::TYPE_HASH);
}

impl<T: Layout, const N: usize> Layout for [T; N] {
    const TYPE_HASH: TypeHash = TypeHash::of("Array").combine(T::TYPE_HASH);
}

impl<A: Layout, B: Layout> Layout for (A, B) {
    const TYPE_HASH: TypeHash = TypeHash::of("Tuple2")
        .combine(A::TYPE_HASH)
        .combine(B::TYPE_HASH);
}

impl<T: Layout, E: Layout> Layout for Result<T, E> {
    const TYPE_HASH: TypeHash = TypeHash::of("Result")
        .combine(T::TYPE_HASH)
        .combine(E::TYPE_HASH);
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
