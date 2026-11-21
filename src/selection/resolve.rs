//! Resolves rules against the running system: user and group names to IDs and
//! cgroup patterns to the cgroups that exist.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use nix::unistd::{Group, User};

use super::{Cgroup, Match, Selection, Test, Value};
use crate::config::rules::{CgroupPattern, Id, Rule, Selector, Span};

/// Rules resolved, with a note for each on what it resolved to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    /// One for each rule, in the order of the rules.
    pub matches: Vec<Match>,
    pub notes: Vec<Option<String>>,
    /// The directories whose children decide what the cgroup patterns match.
    pub dirs: BTreeSet<PathBuf>,
}

impl Resolved {
    /// Adds the resolved `rules` to `selection`.
    pub fn add_to(&self, rules: &[Rule], selection: &mut Selection) {
        for (rule, resolved) in rules.iter().zip(&self.matches) {
            let side = if rule.exclude {
                &mut selection.exclude
            } else {
                &mut selection.include
            };
            side.push(resolved.clone());
        }
    }
}

pub fn resolve(rules: &[Rule], cgroup_root: &Path) -> Result<Resolved> {
    let mut resolved = Resolved::default();
    for rule in rules {
        let mut tests = Vec::new();
        for condition in &rule.conditions {
            let value = value(&condition.selector, cgroup_root, &mut resolved.dirs)
                .with_context(|| format!("rule `{rule}`"))?;
            tests.push(Test {
                negated: condition.negated,
                value,
            });
        }
        let resolved_rule = Match {
            origin: rule.origin(),
            tests,
        };
        resolved.notes.push(note(rule, &resolved_rule));
        resolved.matches.push(resolved_rule);
    }
    Ok(resolved)
}

/// Matches the cgroup patterns of `rules` again, after cgroups were created or
/// removed. On failure `resolved` is left as it was.
pub fn refresh_cgroups(rules: &[Rule], resolved: &mut Resolved, cgroup_root: &Path) -> Result<()> {
    let mut fresh = resolved.clone();
    fresh.dirs.clear();
    for ((rule, resolved_rule), note) in rules.iter().zip(&mut fresh.matches).zip(&mut fresh.notes)
    {
        let mut changed = false;
        for (condition, test) in rule.conditions.iter().zip(&mut resolved_rule.tests) {
            if let Selector::Cgroup(patterns) = &condition.selector {
                test.value = Value::Cgroup(cgroups(patterns, cgroup_root, &mut fresh.dirs)?);
                changed = true;
            }
        }
        if changed {
            *note = self::note(rule, resolved_rule);
        }
    }
    *resolved = fresh;
    Ok(())
}

fn value(selector: &Selector, root: &Path, dirs: &mut BTreeSet<PathBuf>) -> Result<Value> {
    Ok(match selector {
        Selector::Local => Value::Local,
        Selector::Uid(ids) => Value::Uid(ids_of(ids, |name| {
            let Some(user) = User::from_name(name).context("failed to look up the user")? else {
                bail!("user {name} does not exist");
            };
            Ok(user.uid.as_raw())
        })?),
        Selector::Gid(ids) => Value::Gid(ids_of(ids, |name| {
            let Some(group) = Group::from_name(name).context("failed to look up the group")? else {
                bail!("group {name} does not exist");
            };
            Ok(group.gid.as_raw())
        })?),
        Selector::Cgroup(patterns) => Value::Cgroup(cgroups(patterns, root, dirs)?),
        Selector::Iif(patterns) => Value::Iif(patterns.clone()),
        Selector::Src(nets) => Value::Src(IpNet::aggregate(nets)),
        Selector::Mac(macs) => Value::Mac(macs.clone()),
        Selector::Proto(protos) => Value::Proto(protos.clone()),
        Selector::Dst(nets) => Value::Dst(IpNet::aggregate(nets)),
        Selector::Port(ports) => Value::Port(merge(ports.clone())),
        Selector::Oif(patterns) => Value::Oif(patterns.clone()),
    })
}

fn ids_of(ids: &[Id], lookup: impl Fn(&str) -> Result<u32>) -> Result<Vec<Span<u32>>> {
    let spans = ids
        .iter()
        .map(|id| match id {
            Id::Numbers(span) => Ok(*span),
            Id::Name(name) => lookup(name).map(|id| Span {
                first: id,
                last: id,
            }),
        })
        .collect::<Result<_>>()?;
    Ok(merge(spans))
}

/// `spans` sorted, with overlapping and adjacent ones joined.
fn merge<T: Ord + Copy + Into<u64>>(mut spans: Vec<Span<T>>) -> Vec<Span<T>> {
    spans.sort();
    let mut merged: Vec<Span<T>> = Vec::new();
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.first.into() <= last.last.into() + 1 => {
                last.last = last.last.max(span.last);
            }
            _ => merged.push(span),
        }
    }
    merged
}

/// What the rule resolved to, where the rules file does not say it.
fn note(rule: &Rule, resolved: &Match) -> Option<String> {
    let mut parts = Vec::new();
    for (condition, test) in rule.conditions.iter().zip(&resolved.tests) {
        let named = |ids: &[Id]| ids.iter().any(|id| matches!(id, Id::Name(_)));
        let list = |spans: &[Span<u32>]| {
            spans
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        match (&condition.selector, &test.value) {
            (Selector::Uid(ids), Value::Uid(spans)) if named(ids) => {
                parts.push(format!("uid {}", list(spans)));
            }
            (Selector::Gid(ids), Value::Gid(spans)) if named(ids) => {
                parts.push(format!("gid {}", list(spans)));
            }
            (Selector::Cgroup(_), Value::Cgroup(levels)) => {
                parts.push(match levels.values().map(BTreeSet::len).sum::<usize>() {
                    1 => "1 cgroup".to_owned(),
                    n => format!("{n} cgroups"),
                });
            }
            _ => {}
        }
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// The cgroups that match `patterns`, keyed by level, with an entry for every
/// level of the patterns.
fn cgroups(
    patterns: &[CgroupPattern],
    root: &Path,
    dirs: &mut BTreeSet<PathBuf>,
) -> Result<BTreeMap<usize, BTreeSet<Cgroup>>> {
    let mut levels: BTreeMap<usize, BTreeSet<Cgroup>> = BTreeMap::new();
    for pattern in patterns {
        let found = expand(pattern, root, dirs)?;
        levels.entry(pattern.level()).or_default().extend(found);
    }
    Ok(levels)
}

/// The existing cgroups that match `pattern`. The directories read on the way
/// are added to `dirs`.
fn expand(
    pattern: &CgroupPattern,
    root: &Path,
    dirs: &mut BTreeSet<PathBuf>,
) -> Result<Vec<Cgroup>> {
    let mut paths = vec![String::new()];
    for depth in 0..pattern.level() {
        let mut next = Vec::new();
        for parent in &paths {
            let dir = root.join(parent);
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                // The cgroup went away while the tree was read.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("failed to read {}", dir.display()));
                }
            };
            dirs.insert(dir);
            for entry in entries {
                let gone = |error: &io::Error| error.kind() == io::ErrorKind::NotFound;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) if gone(&error) => break,
                    Err(error) => return Err(error.into()),
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !pattern.matches_segment(depth, name) {
                    continue;
                }
                match entry.file_type() {
                    Ok(kind) if kind.is_dir() => {}
                    Ok(_) => continue,
                    Err(error) if gone(&error) => continue,
                    Err(error) => return Err(error.into()),
                }
                next.push(if parent.is_empty() {
                    name.to_owned()
                } else {
                    format!("{parent}/{name}")
                });
            }
        }
        paths = next;
    }
    // A cgroup removed since its parent was read no longer matters.
    Ok(paths
        .into_iter()
        .filter_map(|path| Cgroup::at(root, path).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::rules::parse;

    fn paths(resolved: &Resolved, rule: usize, level: usize) -> Vec<&str> {
        match &resolved.matches[rule].tests[0].value {
            Value::Cgroup(levels) => levels[&level]
                .iter()
                .map(|cgroup| cgroup.path.as_str())
                .collect(),
            value => panic!("not a cgroup test: {value:?}"),
        }
    }

    #[test]
    fn expands_cgroup_globs_and_follows_the_tree() {
        let root = std::env::temp_dir().join(format!("uta-resolve-{}", std::process::id()));
        for dir in [
            "system.slice/docker.service",
            "system.slice/cron.service",
            "system.slice/cron.service/child",
            "user.slice/user-1000.slice",
        ] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("system.slice/not-a-cgroup.service"), "").unwrap();

        let rules =
            parse("cgroup:/system.slice/*.service,/nothing/here/yet\n!cgroup:/user.slice/*\n")
                .unwrap();
        let mut resolved = resolve(&rules, &root).unwrap();
        assert_eq!(
            paths(&resolved, 0, 2),
            ["system.slice/cron.service", "system.slice/docker.service"]
        );
        // A level with patterns but no cgroup yet stays, for cgroups created
        // later.
        assert!(paths(&resolved, 0, 3).is_empty());
        assert_eq!(paths(&resolved, 1, 2), ["user.slice/user-1000.slice"]);
        assert_eq!(
            resolved.notes,
            [Some("2 cgroups".to_owned()), Some("1 cgroup".to_owned())]
        );

        fs::remove_dir_all(root.join("system.slice/docker.service")).unwrap();
        refresh_cgroups(&rules, &mut resolved, &root).unwrap();
        assert_eq!(paths(&resolved, 0, 2), ["system.slice/cron.service"]);
        assert_eq!(resolved.notes[0].as_deref(), Some("1 cgroup"));

        // A unit that restarts gets a new cgroup at the same path, which the
        // kernel table must pick up.
        let before = resolved.matches.clone();
        fs::remove_dir_all(root.join("system.slice/cron.service")).unwrap();
        fs::create_dir_all(root.join("system.slice/cron.service")).unwrap();
        refresh_cgroups(&rules, &mut resolved, &root).unwrap();
        assert_eq!(paths(&resolved, 0, 2), ["system.slice/cron.service"]);
        assert_ne!(resolved.matches, before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn overlapping_values_merge() {
        let rules = parse("uid:1000-1999,1500-2500,2501,0\n!dst:10.0.0.0/8,10.1.0.0/16,fd00::/8\n")
            .unwrap();
        let resolved = resolve(&rules, Path::new("/nonexistent")).unwrap();
        assert_eq!(
            resolved.matches[0].tests[0].value,
            Value::Uid(vec![
                Span { first: 0, last: 0 },
                Span {
                    first: 1000,
                    last: 2501
                }
            ])
        );
        assert_eq!(
            resolved.matches[1].tests[0].value,
            Value::Dst(vec![
                "10.0.0.0/8".parse().unwrap(),
                "fd00::/8".parse().unwrap()
            ])
        );
    }
}
