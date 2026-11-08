//! Following the cgroup tree for cgroup rules and `uta run` scopes.

use std::{fs, path::Path, rc::Rc, time::Duration};

use anyhow::{Context, Result, bail};
use compio::time::sleep;

use super::{Daemon, Run, State};
use crate::{
    config::rules::Rule,
    selection::{CGROUP_ROOT, Cgroup, resolve},
};

/// How long to collect cgroup changes before acting on them, so that a burst of
/// changes costs one table update.
const SETTLE: Duration = Duration::from_millis(100);

impl Daemon {
    /// Whether a cgroup the daemon captures holds the client `pid`, so that a
    /// new scope for it would capture nothing more.
    pub(super) fn covers(&self, pid: i32) -> Result<bool> {
        let path = client_cgroup(pid)?;
        let within = |cgroup: &Cgroup| {
            path.strip_prefix(&cgroup.path)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        };
        let selection = self.selection();
        let state = self.state.borrow();
        Ok(state.runs.iter().any(|run| within(&run.cgroup))
            || selection.include.cgroups.values().flatten().any(within))
    }

    /// Captures the cgroup of the client `pid`, and what the source rules
    /// `with` select, until the cgroup holds no process.
    pub(super) async fn add_run(&self, pid: i32, with: Vec<Rule>) -> Result<()> {
        let path = client_cgroup(pid)?;
        let root = Path::new(CGROUP_ROOT);
        let resolved = resolve::resolve(&with, root)?;
        self.watcher.add_run(root, &path)?;
        let cgroup = Cgroup::at(root, path.clone())?;
        self.state.borrow_mut().runs.push(Run {
            cgroup,
            with,
            resolved,
        });
        self.update_watches();
        if let Err(error) = self.sync().await {
            self.end_run(&path);
            return Err(error);
        }
        eprintln!("capturing /{path}");
        Ok(())
    }

    pub(super) fn end_run(&self, path: &str) {
        self.watcher.remove_run(path);
        self.state
            .borrow_mut()
            .runs
            .retain(|run| run.cgroup.path != path);
        self.update_watches();
    }

    /// Follows cgroups appearing and going away for as long as the daemon runs.
    pub(super) async fn track(self: Rc<Self>) {
        let root = Path::new(CGROUP_ROOT);
        loop {
            let mut changes = match self.watcher.changes(root).await {
                Ok(changes) => changes,
                Err(error) => {
                    self.fail(format!("failed to watch the cgroup tree: {error}"));
                    return;
                }
            };
            sleep(SETTLE).await;
            if let Err(error) = self.watcher.drain(root, &mut changes) {
                self.fail(format!("failed to watch the cgroup tree: {error}"));
                return;
            }
            for path in &changes.ended {
                eprintln!("/{path} has no process left");
                self.end_run(path);
            }
            if changes.tree {
                self.refresh();
            }
            if let Err(error) = self.sync().await {
                eprintln!("failed to update the captured cgroups: {error:#}");
            }
        }
    }

    /// Matches the cgroup patterns of the rules in effect and of `uta run`
    /// sources against the current tree.
    pub(super) fn refresh(&self) {
        let root = Path::new(CGROUP_ROOT);
        let mut state = self.state.borrow_mut();
        let State {
            applied,
            trial,
            runs,
            ..
        } = &mut *state;
        let rules = std::iter::once((&applied.rules, &mut applied.resolved))
            .chain(
                trial
                    .as_mut()
                    .map(|trial| (&trial.rules, &mut trial.resolved)),
            )
            .chain(runs.iter_mut().map(|run| (&run.with, &mut run.resolved)));
        for (rules, resolved) in rules {
            if let Err(error) = resolve::refresh_cgroups(rules, resolved, root) {
                eprintln!("failed to read the cgroup tree: {error:#}");
            }
        }
        drop(state);
        self.update_watches();
    }
}

/// The cgroup of process `pid`, relative to the cgroup root.
fn client_cgroup(pid: i32) -> Result<String> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .context("failed to read the client's cgroup")?;
    match cgroup.lines().find_map(|line| line.strip_prefix("0::/")) {
        Some(path) => Ok(path.to_owned()),
        None => bail!("the client is not in a cgroup v2 hierarchy"),
    }
}
