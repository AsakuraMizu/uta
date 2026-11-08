//! The kernel state uta owns: the nftables table and the policy routing.

use std::process::Stdio;

use anyhow::{Context, Result, anyhow, bail};
use compio::{io::AsyncWriteExt, process::Command};
use rtnetlink::Handle;

use crate::{config::Config, selection::Selection};

pub mod netlink;
mod nft;
mod route;

pub struct Kernel {
    handle: Handle,
    routes: bool,
    /// The selection the table captures, if uta installed it.
    installed: Option<Selection>,
}

impl Kernel {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle,
            routes: false,
            installed: None,
        }
    }

    /// Captures the traffic `selection` picks, replacing whatever uta captured
    /// before.
    pub async fn install(&mut self, selection: &Selection, config: &Config) -> Result<()> {
        if self.installed.as_ref() == Some(selection) {
            return Ok(());
        }
        if !self.routes {
            route::install(&self.handle, &config.kernel)
                .await
                .context("failed to install policy routing")?;
            self.routes = true;
        }
        let ruleset = nft::ruleset(selection, &config.kernel.marks, &config.ports);
        nft(ruleset).await?;
        self.installed = Some(selection.clone());
        Ok(())
    }

    /// Removes everything uta installed, including leftovers of an earlier
    /// daemon.
    pub async fn remove(&mut self) -> Result<()> {
        self.installed = None;
        let table = nft(format!(
            "table inet {table}\ndelete table inet {table}\n",
            table = nft::TABLE
        ))
        .await;
        let routes = route::remove(&self.handle)
            .await
            .context("failed to remove policy routing");
        self.routes = false;
        match (table, routes) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(table), Err(routes)) => Err(anyhow!("{table:#}; {routes:#}")),
        }
    }
}

async fn nft(script: String) -> Result<()> {
    let mut command = Command::new("nft");
    command.args(["-f", "-"]);
    let Ok(command) = command.stdin(Stdio::piped());
    let Ok(command) = command.stdout(Stdio::null());
    let Ok(command) = command.stderr(Stdio::piped());
    let mut child = command.spawn().context("failed to run nft")?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(script.into_bytes())
        .await
        .0
        .context("failed to write to nft")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .context("failed to run nft")?;
    if !output.status.success() {
        bail!(
            "nft failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
