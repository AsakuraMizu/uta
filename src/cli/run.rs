//! `uta run`.

use std::{ffi::OsString, os::unix::process::CommandExt, path::Path, process::Command};

use anyhow::{Result, bail};
use futures_util::SinkExt;

use super::{connect, receive, unexpected};
use crate::{
    config::rules::Rule,
    rpc::{Request, Response},
};

/// Runs `command` with its traffic captured, along with what the source rules
/// `with` select. Returns only on failure.
pub async fn run(
    socket: &Path,
    with: &[Rule],
    in_scope: bool,
    command: Vec<OsString>,
) -> Result<bool> {
    if in_scope {
        let with = with.iter().map(ToString::to_string).collect();
        request(socket, Request::Run { with }).await?;
        return exec(command);
    }
    // Inside an enclosing `uta run`, the command is already captured. Sources
    // to add need a scope of their own, which ends with the command.
    if with.is_empty() && request(socket, Request::Covered).await? {
        return exec(command);
    }
    // systemd gives the scope a cgroup of its own and moves this process into
    // it; the process then asks the daemon to capture that cgroup.
    let mut scope = Command::new("systemd-run");
    if !nix::unistd::geteuid().is_root() {
        scope.arg("--user");
    }
    scope
        .args(["--scope", "--quiet", "--collect"])
        .arg(format!("--unit=uta-run-{}", std::process::id()))
        .arg("--")
        .arg(std::env::current_exe()?)
        .arg("--socket")
        .arg(socket)
        .args(["run", "--in-scope"])
        .args(with.iter().map(|rule| format!("--with={rule}")))
        .arg("--")
        .args(&command);
    Err(anyhow::Error::new(scope.exec()).context("failed to run systemd-run"))
}

/// Sends a `Covered` or `Run` request and returns whether the client's cgroup
/// is captured.
async fn request(socket: &Path, request: Request) -> Result<bool> {
    let (mut connection, _) = connect(socket).await?;
    connection.send(request).await?;
    match receive(&mut connection).await? {
        Response::Covered(covered) => Ok(covered),
        Response::Captured => Ok(true),
        Response::Error(message) => bail!("{message}"),
        response => unexpected(response),
    }
}

/// Replaces this process with `command`, or `$SHELL` if it is empty.
fn exec(command: Vec<OsString>) -> Result<bool> {
    let mut command = command.into_iter();
    let program = command
        .next()
        .or_else(|| std::env::var_os("SHELL"))
        .unwrap_or_else(|| "/bin/sh".into());
    let error = Command::new(&program).args(command).exec();
    Err(anyhow::Error::new(error).context(format!("failed to run {}", program.to_string_lossy())))
}
