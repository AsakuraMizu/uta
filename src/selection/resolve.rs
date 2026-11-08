//! Resolves rules against the running system: user names to IDs and cgroup
//! patterns to the cgroups that exist.

use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use nix::unistd::User as Passwd;

use super::{Cgroup, Selection, Side};
use crate::config::rules::{CgroupPattern, Rule, Selector, User};

/// A selection, with a note for each rule on what it resolved to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub selection: Selection,
    pub notes: Vec<Option<String>>,
    /// The directories whose children decide what the cgroup patterns match.
    pub dirs: BTreeSet<PathBuf>,
}

pub fn resolve(rules: &[Rule], cgroup_root: &Path) -> Result<Resolved> {
    let mut resolved = Resolved::default();
    for rule in rules {
        let side = side(&mut resolved.selection, rule);
        let note = match &rule.selector {
            Selector::Cgroup(pattern) => {
                Some(add_cgroups(side, pattern, cgroup_root, &mut resolved.dirs)?)
            }
            selector => add(side, selector).with_context(|| format!("rule `{rule}`"))?,
        };
        resolved.notes.push(note);
    }
    Ok(resolved)
}

/// Matches the cgroup patterns of `rules` again, after cgroups were created or
/// removed. On failure `resolved` is left as it was.
pub fn refresh_cgroups(rules: &[Rule], resolved: &mut Resolved, cgroup_root: &Path) -> Result<()> {
    let mut fresh = resolved.clone();
    fresh.selection.include.cgroups.clear();
    fresh.selection.exclude.cgroups.clear();
    fresh.dirs.clear();
    for (rule, note) in rules.iter().zip(&mut fresh.notes) {
        if let Selector::Cgroup(pattern) = &rule.selector {
            let side = side(&mut fresh.selection, rule);
            *note = Some(add_cgroups(side, pattern, cgroup_root, &mut fresh.dirs)?);
        }
    }
    *resolved = fresh;
    Ok(())
}

fn side<'a>(selection: &'a mut Selection, rule: &Rule) -> &'a mut Side {
    if rule.exclude {
        &mut selection.exclude
    } else {
        &mut selection.include
    }
}

fn add(side: &mut Side, selector: &Selector) -> Result<Option<String>> {
    Ok(match selector {
        Selector::Local => {
            side.local = true;
            None
        }
        Selector::Uid(User::Id(id)) => {
            side.uids.insert(*id);
            None
        }
        Selector::Uid(User::Name(name)) => {
            let Some(user) = Passwd::from_name(name).context("failed to look up the user")? else {
                bail!("user {name} does not exist");
            };
            side.uids.insert(user.uid.as_raw());
            Some(format!("uid {}", user.uid))
        }
        Selector::Iif(pattern) => {
            side.iifs.push(pattern.clone());
            None
        }
        Selector::Oif(pattern) => {
            side.oifs.push(pattern.clone());
            None
        }
        Selector::Dst(net) => {
            side.nets.push(*net);
            None
        }
        Selector::Port(port) => {
            side.ports.insert(*port);
            None
        }
        Selector::Cgroup(_) => unreachable!("cgroups resolve through add_cgroups"),
    })
}

fn add_cgroups(
    side: &mut Side,
    pattern: &CgroupPattern,
    root: &Path,
    dirs: &mut BTreeSet<PathBuf>,
) -> Result<String> {
    let paths = expand(pattern, root, dirs)?;
    let note = match paths.len() {
        1 => "1 cgroup".to_owned(),
        n => format!("{n} cgroups"),
    };
    side.cgroups
        .entry(pattern.level())
        .or_default()
        .extend(paths);
    Ok(note)
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

    fn paths(side: &Side, level: usize) -> Vec<&str> {
        side.cgroups[&level]
            .iter()
            .map(|cgroup| cgroup.path.as_str())
            .collect()
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
            crate::config::rules::parse("cgroup:/system.slice/*.service\n!cgroup:/user.slice/*\n")
                .unwrap();
        let mut resolved = resolve(&rules, &root).unwrap();
        assert_eq!(
            paths(&resolved.selection.include, 2),
            ["system.slice/cron.service", "system.slice/docker.service"]
        );
        assert_eq!(
            paths(&resolved.selection.exclude, 2),
            ["user.slice/user-1000.slice"]
        );
        assert_eq!(
            resolved.notes,
            [Some("2 cgroups".to_owned()), Some("1 cgroup".to_owned())]
        );

        fs::remove_dir_all(root.join("system.slice/docker.service")).unwrap();
        refresh_cgroups(&rules, &mut resolved, &root).unwrap();
        assert_eq!(
            paths(&resolved.selection.include, 2),
            ["system.slice/cron.service"]
        );
        assert_eq!(resolved.notes[0].as_deref(), Some("1 cgroup"));

        // A unit that restarts gets a new cgroup at the same path, which the
        // kernel table must pick up.
        let before = resolved.selection.clone();
        fs::remove_dir_all(root.join("system.slice/cron.service")).unwrap();
        fs::create_dir_all(root.join("system.slice/cron.service")).unwrap();
        refresh_cgroups(&rules, &mut resolved, &root).unwrap();
        assert_eq!(
            paths(&resolved.selection.include, 2),
            ["system.slice/cron.service"]
        );
        assert_ne!(resolved.selection, before);
        fs::remove_dir_all(root).unwrap();
    }
}
