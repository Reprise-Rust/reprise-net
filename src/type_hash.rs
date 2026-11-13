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
        Self(xxh64(layout.as_bytes(), XXH64_SEED))
    }

    /// Folds another fingerprint into this one, producing a new fingerprint.
    ///
    /// Used to compose a type's fingerprint from the fingerprints of its fields.
    pub const fn combine(self, other: TypeHash) -> Self {
        Self(xxh64(&self.0.to_le_bytes(), other.0))
    }
}

/// Computes the u32 command discriminant of a stable command id.
///
/// This is the wire tag written into a [`crate::packet::Packet`]; it is
/// independent of the Rust type name, so a command can be renamed without
/// changing its wire identity.
pub const fn discriminant(id: &str) -> u32 {
    xxh32(id.as_bytes(), XXH32_SEED)
}

const XXH32_SEED: u32 = 0x9747_b28c;
const XXH64_SEED: u64 = 0x9e37_79b1_85eb_ca87;

const XXH32_PRIME1: u32 = 0x9e37_79b1;
const XXH32_PRIME2: u32 = 0x85eb_ca77;
const XXH32_PRIME3: u32 = 0xc2b2_ae3d;
const XXH32_PRIME4: u32 = 0x27d4_eb2f;
const XXH32_PRIME5: u32 = 0x1656_67b1;

const XXH64_PRIME1: u64 = 0x9e37_79b1_85eb_ca87;
const XXH64_PRIME2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const XXH64_PRIME3: u64 = 0x1656_67b1_9e37_79f9;
const XXH64_PRIME4: u64 = 0x85eb_ca77_c2b2_ae63;
const XXH64_PRIME5: u64 = 0x27d4_eb2f_1656_67c5;

const fn xxh32_round(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(XXH32_PRIME2))
        .rotate_left(13)
        .wrapping_mul(XXH32_PRIME1)
}

/// The 32-bit xxHash algorithm (seed-based), usable in `const` context.
///
/// Chosen over FNV-1a for its much stronger avalanche behaviour, which keeps
/// command discriminants well-distributed.
pub const fn xxh32(bytes: &[u8], seed: u32) -> u32 {
    let len = bytes.len();
    let mut i = 0;
    let mut h: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(XXH32_PRIME1).wrapping_add(XXH32_PRIME2);
        let mut v2 = seed.wrapping_add(XXH32_PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(XXH32_PRIME1);
        while i + 16 <= len {
            v1 = xxh32_round(v1, read_u32_le(bytes, i));
            v2 = xxh32_round(v2, read_u32_le(bytes, i + 4));
            v3 = xxh32_round(v3, read_u32_le(bytes, i + 8));
            v4 = xxh32_round(v4, read_u32_le(bytes, i + 12));
            i += 16;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(XXH32_PRIME5);
    }

    h = h.wrapping_add(len as u32);

    while i + 4 <= len {
        h = h
            .wrapping_add(read_u32_le(bytes, i).wrapping_mul(XXH32_PRIME3))
            .rotate_left(17)
            .wrapping_mul(XXH32_PRIME4);
        i += 4;
    }

    while i < len {
        h = h
            .wrapping_add((bytes[i] as u32).wrapping_mul(XXH32_PRIME5))
            .rotate_left(11)
            .wrapping_mul(XXH32_PRIME1);
        i += 1;
    }

    h ^= h >> 15;
    h = h.wrapping_mul(XXH32_PRIME2);
    h ^= h >> 13;
    h = h.wrapping_mul(XXH32_PRIME3);
    h ^= h >> 16;
    h
}

const fn xxh64_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(XXH64_PRIME2))
        .rotate_left(31)
        .wrapping_mul(XXH64_PRIME1)
}

const fn xxh64_merge(acc: u64, val: u64) -> u64 {
    let acc = acc ^ xxh64_round(0, val);
    acc.wrapping_mul(XXH64_PRIME1).wrapping_add(XXH64_PRIME4)
}

/// The 64-bit xxHash algorithm (seed-based), usable in `const` context.
pub const fn xxh64(bytes: &[u8], seed: u64) -> u64 {
    let len = bytes.len();
    let mut i = 0;
    let mut h: u64;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(XXH64_PRIME1).wrapping_add(XXH64_PRIME2);
        let mut v2 = seed.wrapping_add(XXH64_PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(XXH64_PRIME1);
        while i + 32 <= len {
            v1 = xxh64_round(v1, read_u64_le(bytes, i));
            v2 = xxh64_round(v2, read_u64_le(bytes, i + 8));
            v3 = xxh64_round(v3, read_u64_le(bytes, i + 16));
            v4 = xxh64_round(v4, read_u64_le(bytes, i + 24));
            i += 32;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = xxh64_merge(h, v1);
        h = xxh64_merge(h, v2);
        h = xxh64_merge(h, v3);
        h = xxh64_merge(h, v4);
    } else {
        h = seed.wrapping_add(XXH64_PRIME5);
    }

    h = h.wrapping_add(len as u64);

    while i + 8 <= len {
        h ^= xxh64_round(0, read_u64_le(bytes, i));
        h = h.rotate_left(27).wrapping_mul(XXH64_PRIME1).wrapping_add(XXH64_PRIME4);
        i += 8;
    }

    if i + 4 <= len {
        h ^= (read_u32_le(bytes, i) as u64).wrapping_mul(XXH64_PRIME1);
        h = h.rotate_left(23).wrapping_mul(XXH64_PRIME2).wrapping_add(XXH64_PRIME3);
        i += 4;
    }

    while i < len {
        h ^= (bytes[i] as u64).wrapping_mul(XXH64_PRIME5);
        h = h.rotate_left(11).wrapping_mul(XXH64_PRIME1);
        i += 1;
    }

    h ^= h >> 33;
    h = h.wrapping_mul(XXH64_PRIME2);
    h ^= h >> 29;
    h = h.wrapping_mul(XXH64_PRIME3);
    h ^= h >> 32;
    h
}

const fn read_u32_le(bytes: &[u8], at: usize) -> u32 {
    (bytes[at] as u32)
        | ((bytes[at + 1] as u32) << 8)
        | ((bytes[at + 2] as u32) << 16)
        | ((bytes[at + 3] as u32) << 24)
}

const fn read_u64_le(bytes: &[u8], at: usize) -> u64 {
    (read_u32_le(bytes, at) as u64) | ((read_u32_le(bytes, at + 4) as u64) << 32)
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

    #[test]
    fn xxh32_reference_vectors() {
        // Reference values from the xxHash specification for seed 0.
        assert_eq!(xxh32(b"", 0), 0x02cc_5d05);
        assert_eq!(xxh32(b"a", 0), 0x550d_7456);
        assert_eq!(xxh32(b"abc", 0), 0x32d1_53ff);
        assert_eq!(xxh32(b"hello", 0), 0xfb00_77f9);
        assert_eq!(xxh32(b"Nobody inspects the spammish repetition", 0), 0xe229_3b2f);
    }

    #[test]
    fn xxh64_reference_vectors() {
        // Reference values from the xxHash specification for seed 0.
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
        assert_eq!(xxh64(b"a", 0), 0xd24e_c4f1_a98c_6e5b);
        assert_eq!(xxh64(b"abc", 0), 0x44bc_2cf5_ad77_0999);
        assert_eq!(xxh64(b"hello", 0), 0x26c7_827d_889f_6da3);
    }

    #[test]
    fn discriminant_is_stable_and_distinct() {
        assert_eq!(discriminant("Ping"), discriminant("Ping"));
        assert_ne!(discriminant("Ping"), discriminant("Pong"));
    }
}
