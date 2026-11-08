//! sing-box: the configuration directory uta assembles, and the process it
//! runs.

mod process;

use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, bail};
use compio::process::Command;
use serde_json::{Value, json};

pub use self::process::Process;
use crate::config::{Config, Marks, Ports};

pub const TPROXY_INBOUND: &str = "uta-tproxy";
pub const DNS_INBOUND: &str = "uta-dns";
pub const DNS6_INBOUND: &str = "uta-dns6";

/// The info-level line sing-box logs when every component has started
/// (`box.go`).
pub const READY: &str = "sing-box started (";

/// The fragment that sorts before the user's files.
///
/// When sing-box merges files, the first file wins on a conflicting scalar and
/// arrays are concatenated (`cmd/sing-box/cmd_run.go`), so every scalar here
/// overrides the user's setting.
pub fn fragment(ports: &Ports, marks: &Marks) -> Value {
    json!({
        "inbounds": [
            { "type": "tproxy", "tag": TPROXY_INBOUND, "listen": "::", "listen_port": ports.tproxy },
            { "type": "direct", "tag": DNS_INBOUND, "listen": "127.0.0.1", "listen_port": ports.dns },
            { "type": "direct", "tag": DNS6_INBOUND, "listen": "::1", "listen_port": ports.dns },
        ],
        "route": { "default_mark": marks.mask },
        // uta detects startup from the log on sing-box's standard streams.
        "log": { "disabled": false, "output": "" },
    })
}

/// The files of a configuration directory: uta's fragment, then the user's
/// files in the configured order. sing-box reads a directory's files in name
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Files(Vec<File>);

#[derive(Clone, Debug, PartialEq, Eq)]
struct File {
    name: String,
    content: Vec<u8>,
    /// The permission bits of the user's file, which its copy keeps.
    mode: Option<u32>,
}

impl Files {
    pub fn collect(config: &Config) -> Result<Self> {
        let fragment = fragment(&config.ports, &config.kernel.marks);
        let mut files = vec![File {
            name: "000-uta.json".to_owned(),
            content: serde_json::to_vec_pretty(&fragment)?,
            mode: None,
        }];
        for source in user_files(&config.singbox.config)? {
            let stem = source
                .file_stem()
                .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
            let read = || -> io::Result<_> {
                let mode = fs::metadata(&source)?.permissions().mode() & 0o7777;
                Ok((fs::read(&source)?, mode))
            };
            let (content, mode) =
                read().with_context(|| format!("failed to read {}", source.display()))?;
            files.push(File {
                name: format!("{:03}-{stem}.json", files.len()),
                content,
                mode: Some(mode),
            });
        }
        Ok(Self(files))
    }

    /// Replaces `dir` with these files.
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        remove_dir(dir)?;
        fs::create_dir(dir)?;
        for file in &self.0 {
            let path = dir.join(&file.name);
            fs::write(&path, &file.content)?;
            if let Some(mode) = file.mode {
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            }
        }
        Ok(())
    }

    /// Whether `dir` holds exactly these files.
    pub fn matches(&self, dir: &Path) -> io::Result<bool> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        if names.len() != self.0.len() || names.iter().zip(&self.0).any(|(a, b)| *a != b.name) {
            return Ok(false);
        }
        for file in &self.0 {
            let path = dir.join(&file.name);
            if let Some(mode) = file.mode
                && fs::metadata(&path)?.permissions().mode() & 0o7777 != mode
            {
                return Ok(false);
            }
            if fs::read(&path)? != file.content {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Expands configured paths the way `sing-box -c` and `-C` read them: a
/// directory contributes its `.json` files in name order.
fn user_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        let metadata =
            fs::metadata(path).with_context(|| format!("failed to read {}", path.display()))?;
        if !metadata.is_dir() {
            files.push(path.clone());
            continue;
        }
        let mut entries = Vec::new();
        for entry in
            fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry?;
            let name = entry.path();
            if name.extension().is_some_and(|e| e == "json") && !entry.file_type()?.is_dir() {
                entries.push(name);
            }
        }
        entries.sort();
        files.extend(entries);
    }
    Ok(files)
}

pub fn remove_dir(dir: &Path) -> io::Result<()> {
    match fs::remove_dir_all(dir) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Runs `sing-box check` on a configuration directory.
pub async fn check(binary: &Path, work_dir: &Path, dir: &Path) -> Result<()> {
    run(
        Command::new(binary)
            .arg("check")
            .arg("-C")
            .arg(dir)
            .arg("-D")
            .arg(work_dir),
        "check",
    )
    .await
}

/// The configuration sing-box merges from a directory.
pub async fn merge(binary: &Path, work_dir: &Path, dir: &Path, output: &Path) -> Result<Value> {
    run(
        Command::new(binary)
            .arg("merge")
            .arg(output)
            .arg("-C")
            .arg(dir)
            .arg("-D")
            .arg(work_dir),
        "merge",
    )
    .await?;
    let merged = fs::read(output)?;
    fs::remove_file(output)?;
    Ok(serde_json::from_slice(&merged)?)
}

async fn run(command: &mut Command, what: &str) -> Result<()> {
    command
        .stdin(Stdio::null())?
        .stdout(Stdio::null())?
        .stderr(Stdio::piped())?;
    let output = command
        .output()
        .await
        .with_context(|| format!("failed to run sing-box {what}"))?;
    if !output.status.success() {
        bail!(
            "sing-box {what} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Checks that the merged configuration logs at the level of the startup line,
/// which uta waits for.
pub fn check_log(merged: &Value) -> Result<()> {
    if let Some(level) = merged["log"]["level"].as_str()
        && matches!(level, "warn" | "warning" | "error" | "fatal" | "panic")
    {
        bail!("log.level is {level}, but uta needs info or a lower level to detect startup");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_must_reach_uta_at_info_level() {
        assert!(check_log(&json!({})).is_ok());
        assert!(check_log(&json!({ "log": { "level": "debug", "timestamp": true } })).is_ok());
        assert!(check_log(&json!({ "log": { "level": "warn" } })).is_err());
    }
}
