//! `uta add`, `uta del`, and `uta apply`.

use std::{
    fs,
    io::{self, IsTerminal, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use compio::{
    bytes::Bytes,
    io::framed::{Framed, codec::bytes::BytesCodec, frame::CharDelimited},
};
use futures_util::{FutureExt, SinkExt, StreamExt, pin_mut, select};

use super::{Connection, connect, receive, unexpected};
use crate::{
    config::rules::{self, Rule},
    rpc::{Request, Response},
};

pub enum Change {
    /// Apply the rules file as it is.
    File,
    Add(Vec<Rule>),
    Del(Vec<Rule>),
}

/// How to confirm a change.
pub struct Confirmation {
    /// Ask on the terminal; otherwise keep the change.
    pub ask: bool,
    /// Leave the change waiting for `uta confirm` or `uta rollback`.
    pub pending: bool,
    pub secs: u64,
}

/// Applies a change and, if it changes anything, has it confirmed. Returns
/// whether the change took effect.
pub async fn apply(socket: &Path, change: Change, confirmation: Confirmation) -> Result<bool> {
    if confirmation.ask && !confirmation.pending && !io::stdin().is_terminal() {
        bail!(
            "confirming the change needs a terminal; pass --pending to confirm it with `uta \
             confirm`, or --yes to keep it without asking"
        );
    }
    let (mut connection, rules_path) = connect(socket).await?;
    let edited = match change {
        Change::File => None,
        Change::Add(rules) => match add(&rules_path, &rules)? {
            Some(text) => Some(text),
            None => {
                println!("{} already has these rules.", rules_path.display());
                return Ok(true);
            }
        },
        Change::Del(rules) => Some(del(&rules_path, &rules)?),
    };

    connection
        .send(Request::Apply {
            rules: edited.clone(),
            confirm_secs: confirmation.secs,
            pending: confirmation.pending,
        })
        .await?;
    match receive(&mut connection).await? {
        Response::Unchanged => println!("Nothing to apply."),
        Response::Pending { changes, secs } => {
            for change in changes {
                println!("{change}");
            }
            if confirmation.pending {
                println!(
                    "Run `uta confirm` within {secs}s to keep this change, or `uta rollback` to \
                     undo it."
                );
                return Ok(true);
            }
            if confirmation.ask
                && let Some(kept) = ask(&mut connection, secs).await?
            {
                return Ok(kept);
            }
            return commit(&mut connection, &rules_path, edited.as_deref()).await;
        }
        Response::Busy(operation) => bail!("the daemon is busy: {operation}"),
        Response::Error(message) => bail!("{message}"),
        response => return unexpected(response),
    }
    if let Some(text) = edited {
        write_rules(&rules_path, &text)?;
    }
    Ok(true)
}

/// `uta confirm`: keeps the change waiting for confirmation.
pub async fn confirm(socket: &Path) -> Result<bool> {
    let (mut connection, rules_path) = connect(socket).await?;
    connection.send(Request::Confirm).await?;
    let rules = match receive(&mut connection).await? {
        Response::Confirming(rules) => rules,
        Response::Error(message) => bail!("{message}"),
        response => return unexpected(response),
    };
    commit(&mut connection, &rules_path, rules.as_deref()).await
}

/// `uta rollback`: rolls back the change waiting for confirmation.
pub async fn rollback(socket: &Path) -> Result<bool> {
    let (mut connection, _) = connect(socket).await?;
    connection.send(Request::Rollback).await?;
    match receive(&mut connection).await? {
        Response::RolledBack(_) => {
            println!("Rolled back.");
            Ok(true)
        }
        Response::Error(message) => bail!("{message}"),
        response => unexpected(response),
    }
}

/// Asks whether to keep the change. Returns `None` if the user keeps it, for
/// the caller to commit; otherwise whether the change was kept, as the user
/// rolled it back or another client decided it.
async fn ask(connection: &mut Connection, secs: u64) -> Result<Option<bool>> {
    print!("Keep this change? [y/N] (rolls back in {secs}s) ");
    io::stdout().flush()?;
    let mut stdin = Framed::new::<Bytes, Bytes>(BytesCodec::new(), CharDelimited::<'\n'>::new())
        .with_reader(compio::fs::stdin());
    let answer = stdin.next().fuse();
    let response = connection.next().fuse();
    pin_mut!(answer, response);
    let keep = select! {
        answer = answer => matches!(
            answer,
            Some(Ok(line)) if matches!(String::from_utf8_lossy(&line).trim(), "y" | "Y" | "yes")
        ),
        response = response => {
            println!();
            return outcome(response.transpose()?).map(Some);
        }
    };
    if keep {
        return Ok(None);
    }
    connection.send(Request::Rollback).await?;
    outcome(Some(receive(connection).await?)).map(Some)
}

/// Confirms the change. An edited rules file is written before the daemon
/// commits the change, so that a failed write rolls it back, and restored if
/// the daemon rolls back anyway.
async fn commit(
    connection: &mut Connection,
    rules_path: &Path,
    edited: Option<&str>,
) -> Result<bool> {
    let original = match edited {
        Some(text) => {
            let original = read_rules(rules_path)?;
            if let Err(error) = write_rules(rules_path, text) {
                connection.send(Request::Rollback).await?;
                let _ = receive(connection).await;
                return Err(error.context("rolled back"));
            }
            Some(original)
        }
        None => None,
    };
    let response = async {
        connection.send(Request::Confirm).await?;
        receive(connection).await
    }
    .await;
    if let Ok(Response::Confirmed) = response {
        println!("Confirmed.");
        return Ok(true);
    }
    if let Some(original) = original {
        write_rules(rules_path, &original)?;
    }
    outcome(Some(response?))
}

/// Reports how the daemon decided the change: whether it was kept.
fn outcome(response: Option<Response>) -> Result<bool> {
    match response {
        Some(Response::Confirmed) => {
            println!("Confirmed.");
            Ok(true)
        }
        Some(Response::RolledBack(reason)) => {
            println!("Rolled back: {reason}.");
            Ok(false)
        }
        Some(Response::Error(message)) => bail!("{message}"),
        Some(response) => unexpected(response),
        None => bail!("the daemon closed the connection"),
    }
}

/// The rules file with `rules` appended, or `None` if it has all of them.
fn add(path: &Path, rules: &[Rule]) -> Result<Option<String>> {
    let mut text = read_rules(path)?;
    let existing = rules::parse(&text).with_context(|| format!("invalid {}", path.display()))?;
    let mut missing: Vec<&Rule> = Vec::new();
    for rule in rules {
        if !existing.contains(rule) && !missing.contains(&rule) {
            missing.push(rule);
        }
    }
    if missing.is_empty() {
        return Ok(None);
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for rule in missing {
        text.push_str(&format!("{rule}\n"));
    }
    Ok(Some(text))
}

/// The rules file without the lines that hold `rules`.
fn del(path: &Path, rules: &[Rule]) -> Result<String> {
    let text = read_rules(path)?;
    let existing = rules::parse(&text).with_context(|| format!("invalid {}", path.display()))?;
    for rule in rules {
        if !existing.contains(rule) {
            bail!("{} has no rule {rule}", path.display());
        }
    }
    let mut kept = String::new();
    for line in text.lines() {
        let content = line
            .split_once('#')
            .map_or(line, |(content, _)| content)
            .trim();
        let removed = !content.is_empty()
            && content
                .parse::<Rule>()
                .is_ok_and(|rule| rules.contains(&rule));
        if !removed {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    Ok(kept)
}

fn read_rules(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

/// Replaces the rules file through a rename, keeping its mode and writing
/// through a symlink.
fn write_rules(path: &Path, text: &str) -> Result<()> {
    let replace = || -> io::Result<()> {
        let target = fs::canonicalize(path)?;
        let mut temporary = target.clone().into_os_string();
        temporary.push(".uta-new");
        let temporary = PathBuf::from(temporary);
        let mode = fs::metadata(&target)?.permissions().mode();
        fs::write(&temporary, text)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, &target)
    };
    replace().with_context(|| format!("failed to write {}", path.display()))
}
