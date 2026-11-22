//! Applying a change: the transaction behind `uta add`, `uta del`, and `uta
//! apply`.

use std::{
    fs,
    path::Path,
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use compio::time::sleep;
use futures_channel::oneshot;
use futures_util::{FutureExt, SinkExt, StreamExt, future, pin_mut, select};
use nix::sys::signal::Signal;

use super::{
    Applied, Connection, Daemon, Decision, Operation, Pending, check, read_rules, stop, wait_ready,
};
use crate::{
    config::rules::{self, Rule},
    rpc::{Request, Response},
    selection::{CGROUP_ROOT, resolve},
    singbox::{self, Files, Level, Process},
};

impl Daemon {
    pub(super) async fn apply(
        self: &Rc<Self>,
        connection: &mut Connection,
        rules: Option<String>,
        confirm_secs: u64,
        pending: bool,
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
            let prepare = self.prepare(rules.clone()).fuse();
            let closed = connection.next().fuse();
            pin_mut!(prepare, closed);
            select! {
                prepared = prepare => prepared?,
                _ = closed => return Ok(()),
            }
        };
        let old = self.state.borrow().applied.clone();
        let capture_changed = new.selection() != old.selection();

        if singbox_changed.is_none() && !capture_changed {
            self.state.borrow_mut().applied = new;
            self.update_watches();
            connection.send(Response::Unchanged).await?;
            return Ok(());
        }
        if let Some(filter) = singbox_changed {
            self.reload(filter).await?;
        }
        let singbox_changed = singbox_changed.is_some();

        self.state.borrow_mut().trial = Some(new.clone());
        self.update_watches();
        if let Err(error) = self.sync().await {
            self.restore(singbox_changed).await?;
            return Err(error);
        }
        let deadline = Instant::now() + Duration::from_secs(confirm_secs);
        let (decide, decision) = oneshot::channel();
        {
            let mut state = self.state.borrow_mut();
            if let Some(operation) = &mut state.operation {
                operation.deadline = Some(deadline);
            }
            state.pending = Some(Pending { rules, decide });
        }
        let waiting = Response::Pending {
            changes: describe(&old, &new, capture_changed, singbox_changed),
            secs: confirm_secs,
        };
        let (decided, reply) = if connection.send(waiting).await.is_ok() {
            // The client answers on this connection, unless it left the
            // change pending; another client may answer in either case.
            let request = async {
                if pending {
                    future::pending().await
                } else {
                    connection.next().await
                }
            }
            .fuse();
            let decision = decision.fuse();
            let expired = sleep(Duration::from_secs(confirm_secs)).fuse();
            pin_mut!(request, decision, expired);
            select! {
                request = request => (match request {
                    Some(Ok(Request::Confirm)) => Ok(()),
                    Some(Ok(Request::Rollback)) => Err("rolled back on request".to_owned()),
                    None => Err("the client went away".to_owned()),
                    _ => Err("unexpected request".to_owned()),
                }, None),
                decision = decision => match decision {
                    Ok(Decision { keep: true, reply }) => (Ok(()), Some(reply)),
                    Ok(Decision { keep: false, reply }) => {
                        (Err("rolled back on request".to_owned()), Some(reply))
                    }
                    Err(oneshot::Canceled) => (Err("the decision was lost".to_owned()), None),
                },
                () = expired => (Err(format!("not confirmed within {confirm_secs}s")), None),
            }
        } else {
            (Err("the client went away".to_owned()), None)
        };
        self.state.borrow_mut().pending = None;

        match &decided {
            Ok(()) => {
                eprintln!("applied change confirmed");
                {
                    let mut state = self.state.borrow_mut();
                    state.applied = state.trial.take().unwrap_or(new);
                }
                self.update_watches();
            }
            Err(reason) => {
                eprintln!("applied change rolled back: {reason}");
                self.restore(singbox_changed).await?;
            }
        }
        let outcome = || match &decided {
            Ok(()) => Response::Confirmed,
            Err(reason) => Response::RolledBack(reason.clone()),
        };
        if let Some(reply) = reply {
            let _ = reply.send(outcome());
        }
        // The client may have gone away, or left the decision to another.
        let _ = connection.send(outcome()).await;
        Ok(())
    }

    /// Serves `uta confirm`: hands out the rules to write, then confirms or
    /// rolls back as the client asks.
    pub(super) async fn confirm(self: &Rc<Self>, connection: &mut Connection) -> Result<()> {
        let rules = match &self.state.borrow().pending {
            Some(pending) => pending.rules.clone(),
            None => bail!("no change is waiting for confirmation"),
        };
        connection.send(Response::Confirming(rules)).await?;
        match connection.next().await {
            Some(Ok(Request::Confirm)) => self.decide(connection, true).await,
            Some(Ok(Request::Rollback)) => self.decide(connection, false).await,
            // The change keeps waiting.
            None => Ok(()),
            _ => bail!("unexpected request"),
        }
    }

    /// Confirms or rolls back the change waiting for confirmation and reports
    /// the outcome.
    pub(super) async fn decide(
        self: &Rc<Self>,
        connection: &mut Connection,
        keep: bool,
    ) -> Result<()> {
        let pending = self.state.borrow_mut().pending.take();
        let Some(pending) = pending else {
            bail!("no change is waiting for confirmation");
        };
        let (reply, outcome) = oneshot::channel();
        let _ = pending.decide.send(Decision { keep, reply });
        let outcome = outcome
            .await
            .context("the change ended before it was decided")?;
        connection.send(outcome).await?;
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
    /// and checks it in the staging directory and returns its log filter.
    async fn prepare(&self, rules: Option<String>) -> Result<(Applied, Option<Option<Level>>)> {
        let text = match rules {
            Some(text) => text,
            None => read_rules(&self.rules_path)?,
        };
        let rules = rules::parse(&text)?;
        let resolved = resolve::resolve(&rules, Path::new(CGROUP_ROOT))?;
        let files = Files::collect(&self.config)?;
        let singbox_changed = if files.matches(&self.paths.current)? {
            None
        } else {
            files.write(&self.paths.staging)?;
            Some(check(&self.config, &self.paths.staging, &self.paths.merged).await?)
        };
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

    /// Makes sing-box run the staging configuration, whose log filter is
    /// `filter`. On failure, sing-box runs the previous configuration again.
    async fn reload(self: &Rc<Self>, filter: Option<Level>) -> Result<()> {
        singbox::remove_dir(&self.paths.previous)?;
        fs::rename(&self.paths.current, &self.paths.previous)?;
        fs::rename(&self.paths.staging, &self.paths.current)?;
        self.swap_log_filter(filter);
        let Err(error) = self.hup().await else {
            return Ok(());
        };
        fs::rename(&self.paths.current, &self.paths.staging)?;
        fs::rename(&self.paths.previous, &self.paths.current)?;
        let filter = self.state.borrow().previous_log_filter;
        self.swap_log_filter(filter);
        self.restart().await?;
        Err(error
            .context("sing-box failed with the new configuration; it runs the previous one again"))
    }

    /// Makes sing-box run the configuration a reload replaced.
    async fn revert(self: &Rc<Self>) -> Result<()> {
        singbox::remove_dir(&self.paths.staging)?;
        fs::rename(&self.paths.current, &self.paths.staging)?;
        fs::rename(&self.paths.previous, &self.paths.current)?;
        let filter = self.state.borrow().previous_log_filter;
        self.swap_log_filter(filter);
        if self.hup().await.is_err() {
            self.restart().await?;
        }
        Ok(())
    }

    /// Makes `filter` the log filter of the configuration sing-box runs, and
    /// the one it replaces the previous.
    fn swap_log_filter(&self, filter: Option<Level>) {
        let mut state = self.state.borrow_mut();
        state.previous_log_filter = std::mem::replace(&mut state.log_filter, filter);
        state.process.filter_log(filter);
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
            process.filter_log(self.state.borrow().log_filter);
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
                "{} waiting for confirmation, {}s left; run `uta confirm` or `uta rollback`",
                self.kind,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            ),
            None => format!("{} in progress", self.kind),
        }
    }
}

/// Lines describing the change.
fn describe(
    old: &Applied,
    new: &Applied,
    capture_changed: bool,
    singbox_changed: bool,
) -> Vec<String> {
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
    if changes.is_empty() && capture_changed {
        changes.push("~ the rules now match other cgroups".to_owned());
    }
    if singbox_changed {
        changes.push("~ the sing-box configuration".to_owned());
    }
    changes
}
