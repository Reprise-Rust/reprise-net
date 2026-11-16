//! Client-side change tracking: a cache of per-resource versions.
//!
//! The server assigns each changeable resource (a table, a per-person table, a
//! file, …) a monotonically increasing version. A client keeps the last version
//! it has observed for each resource and, after a disconnect, diffs its stored
//! map against the server's current map to learn which resources to refetch.
//!
//! This is transport-agnostic: a "resource" is an opaque [`VersionKey`], and the
//! version is a plain `u64`. The caller maps its domain concepts (tables,
//! person-scoped tables) onto keys.

use std::collections::HashMap;

/// An opaque key identifying a changeable resource.
///
/// The caller defines the key space. For example a table name, or a
/// `(table, person)` pair for per-person tables.
pub type VersionKey = u64;

/// A client's view of the server's per-resource versions.
///
/// Stores the last version the client has observed for each resource. On
/// reconnect, [`diff`](Self::diff) against a freshly fetched map tells the
/// client exactly which resources changed while it was away.
#[derive(Debug, Clone, Default)]
pub struct VersionMap {
    versions: HashMap<VersionKey, u64>,
}

/// How a resource's version changed between two maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Present in both, but the version advanced — refetch it.
    Advanced { key: VersionKey },
    /// Present only in the newer map — a new resource, refetch it.
    New { key: VersionKey },
    /// Present only in the older map — the resource was removed, drop it.
    Removed { key: VersionKey },
}

impl VersionMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the version observed for `key`.
    pub fn observe(&mut self, key: VersionKey, version: u64) {
        self.versions.insert(key, version);
    }

    /// The last observed version for `key`, if any.
    pub fn get(&self, key: VersionKey) -> Option<u64> {
        self.versions.get(&key).copied()
    }

    /// Compares `self` (the older map) against `newer`, returning the changes
    /// needed to bring `self` up to date.
    pub fn diff(&self, newer: &VersionMap) -> Vec<Change> {
        let mut changes = Vec::new();

        for (&key, &new_version) in &newer.versions {
            match self.versions.get(&key) {
                Some(&old_version) if old_version != new_version => {
                    changes.push(Change::Advanced { key });
                }
                Some(_) => {}
                None => changes.push(Change::New { key }),
            }
        }

        for &key in self.versions.keys() {
            if !newer.versions.contains_key(&key) {
                changes.push(Change::Removed { key });
            }
        }

        changes
    }

    /// Replaces this map's contents with `newer`, returning the changes applied.
    pub fn apply(&mut self, newer: &VersionMap) -> Vec<Change> {
        let changes = self.diff(newer);
        self.versions.clone_from(&newer.versions);
        changes
    }
}

/// Runs a fetch while guaranteeing the result is not stale.
///
/// The caller supplies `read_versions` (returns the current version map) and
/// `fetch` (performs the query and returns its result). The fetch is retried if
/// a version advanced between the before-check and the after-check, since the
/// result may then not reflect the latest state.
///
/// `max_retries` bounds the retry loop so a continuously changing resource
/// cannot spin forever; on exhaustion the last (possibly stale) result is
/// returned.
pub async fn fetch_consistent<T, E, FRead, FFetch>(
    mut read_versions: FRead,
    mut fetch: FFetch,
    max_retries: usize,
) -> Result<T, E>
where
    FRead: FnMut() -> VersionMap,
    FFetch: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>>>>,
{
    for _ in 0..=max_retries {
        let before = read_versions();
        let result = fetch().await?;
        let after = read_versions();
        if before.diff(&after).is_empty() {
            return Ok(result);
        }
    }
    // A write landed during every attempt; return the last result anyway.
    fetch().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_detects_advance_new_unchanged() {
        let mut old = VersionMap::new();
        old.observe(1, 10);
        old.observe(2, 20);

        let mut new = VersionMap::new();
        new.observe(1, 11); // advanced
        new.observe(2, 20); // unchanged
        new.observe(3, 5); // new

        let changes = old.diff(&new);
        assert!(changes.contains(&Change::Advanced { key: 1 }));
        assert!(changes.contains(&Change::New { key: 3 }));
        assert_eq!(changes.len(), 2); // key 2 unchanged, not reported
    }

    #[test]
    fn diff_detects_removed() {
        let mut old = VersionMap::new();
        old.observe(1, 10);

        let new = VersionMap::new();
        let changes = old.diff(&new);
        assert!(changes.contains(&Change::Removed { key: 1 }));
    }
}