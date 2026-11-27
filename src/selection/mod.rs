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

use crate::config::rules::{IfacePattern, Mac, Origin, Proto, Span};

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The resolved rules, sorted and without duplicates, so that equal
/// selections capture the same traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub include: Vec<Match>,
    pub exclude: Vec<Match>,
    /// Destinations the exclusions do not apply to: the FakeIP ranges of the
    /// sing-box configuration, whose addresses only sing-box can reach.
    pub fakeip: Vec<IpNet>,
}

impl Selection {
    pub fn normalize(&mut self) {
        for matches in [&mut self.include, &mut self.exclude] {
            matches.sort();
            matches.dedup();
        }
        self.fakeip.sort();
        self.fakeip.dedup();
    }
}

/// A rule with user and group names mapped to IDs and cgroup patterns to the
/// cgroups that currently match them. Every test must hold.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Match {
    pub origin: Option<Origin>,
    pub tests: Vec<Test>,
}

impl Match {
    /// Sockets of processes in `cgroup` or below it.
    pub fn cgroup(cgroup: &Cgroup) -> Self {
        let level = cgroup.path.split('/').count();
        Self {
            origin: Some(Origin::Local),
            tests: vec![Test {
                negated: false,
                value: Value::Cgroup(BTreeMap::from([(level, BTreeSet::from([cgroup.clone()]))])),
            }],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Test {
    pub negated: bool,
    pub value: Value,
}

/// What a test matches. Ranges and networks are merged where they overlap.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    Local,
    Uid(Vec<Span<u32>>),
    Gid(Vec<Span<u32>>),
    /// Cgroups keyed by level. Every level of the patterns has an entry, empty
    /// if nothing matches now, so that the table has a set for cgroups created
    /// later.
    Cgroup(BTreeMap<usize, BTreeSet<Cgroup>>),
    Iif(Vec<IfacePattern>),
    Src(Vec<IpNet>),
    Mac(Vec<Mac>),
    Proto(Vec<Proto>),
    Dst(Vec<IpNet>),
    Port(Vec<Span<u16>>),
    Sport(Vec<Span<u16>>),
    Oif(Vec<IfacePattern>),
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
