//! Applying a change: the transaction behind `uta add`, `uta del`, and `uta
//! apply`.

use std::{
    fs,
    path::Path,
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use compio::time::sleep;
use futures_util::{FutureExt, SinkExt, StreamExt, pin_mut, select};
use nix::sys::signal::Signal;

use super::{Applied, Connection, Daemon, Operation, check, read_rules, stop, wait_ready};
use crate::{
    config::rules::{self, Rule},
    rpc::{Request, Response},
    selection::{CGROUP_ROOT, resolve},
    singbox::{self, Files, Process},
};

impl Daemon {
    pub(super) async fn apply(
        self: &Rc<Self>,
        connection: &mut Connection,
        rules: Option<String>,
        confirm_secs: u64,
    ) -> Result<()> {
        let Some(_operation) = self.begin("apply") else {
            let operation = self
                .state
                .borrow()
                .operation
                .as_ref()
                .map(Operation::describe);
            connection
                .send(Response::Busy(operation.unwrap_or_default()))
                .await?;
            return Ok(());
        };

        // A client that goes away while the change is prepared cancels it.
        let (new, singbox_changed) = {
            let prepare = self.prepare(rules).fuse();
            let closed = connection.next().fuse();
            pin_mut!(prepare, closed);
            select! {
                prepared = prepare => prepared?,
                _ = closed => return Ok(()),
            }
        };
        let old = self.state.borrow().applied.clone();
        let capture_changed = new.resolved.selection != old.resolved.selection;

        if !singbox_changed && !capture_changed {
            self.state.borrow_mut().applied = new;
            self.update_watches();
            connection.send(Response::Unchanged).await?;
            return Ok(());
        }
        if singbox_changed {
            self.reload().await?;
        }
        if !capture_changed {
            self.state.borrow_mut().applied = new;
            self.update_watches();
            connection.send(Response::Applied).await?;
            return Ok(());
        }

        self.state.borrow_mut().trial = Some(new.clone());
        self.update_watches();
        if let Err(error) = self.sync().await {
            self.restore(singbox_changed).await?;
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_secs(confirm_secs);
        if let Some(operation) = &mut self.state.borrow_mut().operation {
            operation.deadline = Some(deadline);
        }
        let pending = Response::Pending {
            changes: describe(&old, &new),
            secs: confirm_secs,
        };
        let confirmed = if connection.send(pending).await.is_ok() {
            let request = connection.next().fuse();
            let expired = sleep(Duration::from_secs(confirm_secs)).fuse();
            pin_mut!(request, expired);
            select! {
                request = request => match request {
                    Some(Ok(Request::Confirm)) => Ok(()),
                    Some(Ok(Request::Rollback)) => Err("rolled back on request".to_owned()),
                    None => Err("the client went away".to_owned()),
                    _ => Err("unexpected request".to_owned()),
                },
                () = expired => Err(format!("not confirmed within {confirm_secs}s")),
            }
        } else {
            Err("the client went away".to_owned())
        };

        match confirmed {
            Ok(()) => {
                eprintln!("applied rules confirmed");
                {
                    let mut state = self.state.borrow_mut();
                    state.applied = state.trial.take().unwrap_or(new);
                }
                self.update_watches();
                connection.send(Response::Confirmed).await?;
            }
            Err(reason) => {
                eprintln!("applied rules rolled back: {reason}");
                self.restore(singbox_changed).await?;
                let _ = connection.send(Response::RolledBack(reason)).await;
            }
        }
        Ok(())
    }

    /// Puts back the rules and the sing-box configuration in effect before the
    /// apply. The daemon cannot describe what runs after a failure here, so a
    /// failure is fatal.
    async fn restore(self: &Rc<Self>, singbox_changed: bool) -> Result<()> {
        self.state.borrow_mut().trial = None;
        self.update_watches();
        let synced = self.sync().await;
        let reverted = if singbox_changed {
            self.revert().await
        } else {
            Ok(())
        };
        let result = match (synced, reverted) {
            (Ok(()), Ok(())) => return Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => error,
            (Err(synced), Err(reverted)) => anyhow!("{synced:#}; {reverted:#}"),
        };
        let error = result.context("failed to roll back");
        self.fail(format!("{error:#}"));
        Err(error)
    }

    /// Resolves the rules and, if the sing-box configuration changed, writes
    /// and checks it in the staging directory.
    async fn prepare(&self, rules: Option<String>) -> Result<(Applied, bool)> {
        let text = match rules {
            Some(text) => text,
            None => read_rules(&self.rules_path)?,
        };
        let rules = rules::parse(&text)?;
        let resolved = resolve::resolve(&rules, Path::new(CGROUP_ROOT))?;
        let files = Files::collect(&self.config)?;
        let singbox_changed = !files.matches(&self.paths.current)?;
        if singbox_changed {
            files.write(&self.paths.staging)?;
            check(&self.config, &self.paths.staging, &self.paths.merged).await?;
        }
        Ok((
            Applied {
                text,
                rules,
                resolved,
            },
            singbox_changed,
        ))
    }

    fn begin(&self, kind: &'static str) -> Option<OperationGuard<'_>> {
        let mut state = self.state.borrow_mut();
        if state.operation.is_some() {
            return None;
        }
        state.operation = Some(Operation {
            kind,
            deadline: None,
        });
        Some(OperationGuard(self))
    }

    /// Makes sing-box run the staging configuration. On failure, sing-box runs
    /// the previous configuration again.
    async fn reload(self: &Rc<Self>) -> Result<()> {
        singbox::remove_dir(&self.paths.previous)?;
        fs::rename(&self.paths.current, &self.paths.previous)?;
        fs::rename(&self.paths.staging, &self.paths.current)?;
        let Err(error) = self.hup().await else {
            return Ok(());
        };
        fs::rename(&self.paths.current, &self.paths.staging)?;
        fs::rename(&self.paths.previous, &self.paths.current)?;
        self.restart().await?;
        Err(error
            .context("sing-box failed with the new configuration; it runs the previous one again"))
    }

    /// Makes sing-box run the configuration a reload replaced.
    async fn revert(self: &Rc<Self>) -> Result<()> {
        singbox::remove_dir(&self.paths.staging)?;
        fs::rename(&self.paths.current, &self.paths.staging)?;
        fs::rename(&self.paths.previous, &self.paths.current)?;
        if self.hup().await.is_err() {
            self.restart().await?;
        }
        Ok(())
    }

    /// Sends SIGHUP and waits for sing-box to report startup with the
    /// configuration on disk.
    async fn hup(&self) -> Result<()> {
        let process = self.process();
        let count = process.ready_count();
        self.state.borrow_mut().replacing = true;
        let result = match process.signal(Signal::SIGHUP) {
            Ok(()) => wait_ready(&process, count).await,
            Err(error) => Err(error.into()),
        };
        self.state.borrow_mut().replacing = false;
        result
    }

    /// Starts a new sing-box on the current configuration and captures the
    /// applied rules again. A failure is fatal to the daemon.
    async fn restart(self: &Rc<Self>) -> Result<()> {
        self.state.borrow_mut().replacing = true;
        let result = async {
            self.kernel.lock().await.remove().await?;
            stop(&self.process()).await;
            // Shutdown stops the process it finds in the state; one started
            // after that would outlive the daemon.
            if self.stopping.get() {
                bail!("the daemon is stopping");
            }
            let process = Rc::new(Process::spawn(
                &self.config.singbox.binary,
                &self.paths.current,
                &self.config.singbox.work_dir,
            )?);
            self.state.borrow_mut().process = Rc::clone(&process);
            self.watch(&process);
            wait_ready(&process, 0).await?;
            self.sync().await
        }
        .await;
        self.state.borrow_mut().replacing = false;
        if let Err(error) = &result {
            self.fail(format!("failed to restart sing-box: {error:#}"));
        }
        result
    }
}

struct OperationGuard<'a>(&'a Daemon);

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        self.0.state.borrow_mut().operation = None;
    }
}

impl Operation {
    pub(super) fn describe(&self) -> String {
        match self.deadline {
            Some(deadline) => format!(
                "{} waiting for confirmation, {}s left",
                self.kind,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            ),
            None => format!("{} in progress", self.kind),
        }
    }
}

/// Lines describing how the captured traffic changes.
fn describe(old: &Applied, new: &Applied) -> Vec<String> {
    let line = |sign, rule: &Rule, note: &Option<String>| match note {
        Some(note) => format!("{sign} {rule} ({note})"),
        None => format!("{sign} {rule}"),
    };
    let mut changes = Vec::new();
    for (rule, note) in old.rules.iter().zip(&old.resolved.notes) {
        if !new.rules.contains(rule) {
            changes.push(line("-", rule, note));
        }
    }
    for (rule, note) in new.rules.iter().zip(&new.resolved.notes) {
        match old.rules.iter().position(|old_rule| old_rule == rule) {
            None => changes.push(line("+", rule, note)),
            Some(index) if old.resolved.notes[index] != *note => {
                changes.push(line("~", rule, note))
            }
            Some(_) => {}
        }
    }
    if changes.is_empty() {
        changes.push("~ the rules now match other cgroups".to_owned());
    }
    changes
}
