//! `uta status`.

use std::path::Path;

use anyhow::Result;
use futures_util::SinkExt;

use super::{connect, receive, unexpected};
use crate::rpc::{Request, Response, Status};

pub async fn status(socket: &Path) -> Result<()> {
    let (mut connection, _) = connect(socket).await?;
    connection.send(Request::Status).await?;
    match receive(&mut connection).await? {
        Response::Status(status) => {
            print(&status);
            Ok(())
        }
        response => unexpected(response),
    }
}

fn print(status: &Status) {
    let uptime = status.singbox_uptime_secs;
    println!(
        "sing-box: running, pid {}, up {}h{:02}m{:02}s",
        status.singbox_pid,
        uptime / 3600,
        uptime / 60 % 60,
        uptime % 60
    );
    println!("rules: {}", status.rules_path.display());
    let width = status
        .rules
        .iter()
        .map(|rule| rule.rule.len())
        .max()
        .unwrap_or(0);
    for rule in &status.rules {
        match &rule.resolved {
            Some(resolved) => println!("  {:width$}  {resolved}", rule.rule),
            None => println!("  {}", rule.rule),
        }
    }
    for run in &status.runs {
        if run.with.is_empty() {
            println!("uta run: {}", run.cgroup);
        } else {
            println!("uta run: {}, with {}", run.cgroup, run.with.join(", "));
        }
    }
    if let Some(operation) = &status.operation {
        println!("operation: {operation}");
    }
    if status.rules_changed {
        println!("The rules file changed since it was applied; run `uta apply` to apply it.");
    }
    if status.singbox_changed {
        println!(
            "The sing-box configuration changed since it was applied; run `uta apply` to apply it."
        );
    }
}
