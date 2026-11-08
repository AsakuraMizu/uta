//! What to capture: the rules resolved against the running system.

pub mod resolve;
pub mod watch;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    os::unix::fs::MetadataExt,
    path::Path,
};

use ipnet::IpNet;

use crate::config::rules::IfacePattern;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub include: Side,
    pub exclude: Side,
}

/// Selectors of one sign, with user names already mapped to IDs and cgroup
/// patterns to the cgroups that currently match them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Side {
    pub local: bool,
    pub uids: BTreeSet<u32>,
    /// Cgroups keyed by level. A level that has patterns but no matching
    /// cgroup keeps an empty entry, so that its set exists for cgroups created
    /// later.
    pub cgroups: BTreeMap<usize, BTreeSet<Cgroup>>,
    pub iifs: Vec<IfacePattern>,
    pub nets: Vec<IpNet>,
    pub ports: BTreeSet<u16>,
    pub oifs: Vec<IfacePattern>,
}

impl Side {
    /// Adds the sources `other` selects: its local, uid, cgroup and incoming
    /// interface selectors.
    pub fn extend_sources(&mut self, other: &Self) {
        self.local |= other.local;
        self.uids.extend(&other.uids);
        for (level, cgroups) in &other.cgroups {
            self.cgroups
                .entry(*level)
                .or_default()
                .extend(cgroups.iter().cloned());
        }
        self.iifs.extend(other.iifs.iter().cloned());
    }
}

/// A cgroup by its path relative to the cgroup root, without `"` or control
/// characters, and its ID. nft stores the ID, so a cgroup created again at the
/// same path is a different element.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cgroup {
    pub path: String,
    pub id: u64,
}

impl Cgroup {
    /// The cgroup at `path` now; cgroupfs inode numbers are cgroup IDs.
    pub fn at(root: &Path, path: String) -> io::Result<Self> {
        let id = fs::metadata(root.join(&path))?.ino();
        Ok(Self { path, id })
    }
}
