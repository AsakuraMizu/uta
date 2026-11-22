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

/// The info-level line sing-box logs when every component has started
/// (`box.go`).
pub const READY: &str = "sing-box started (";

/// The file of uta's fragment, which sorts before the user's files.
const FRAGMENT: &str = "000-uta.json";

/// The fragment that sorts before the user's files.
///
/// When sing-box merges files, the first file wins on a conflicting scalar and
/// arrays are concatenated (`cmd/sing-box/cmd_run.go`), so every scalar here
/// overrides the user's setting.
pub fn fragment(ports: &Ports, marks: &Marks) -> Value {
    json!({
        "inbounds": [
            { "type": "tproxy", "tag": TPROXY_INBOUND, "listen": "::", "listen_port": ports.tproxy },
            // Queries redirected in prerouting arrive at an address of the incoming interface.
            { "type": "direct", "tag": DNS_INBOUND, "listen": "::", "listen_port": ports.dns },
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
            name: FRAGMENT.to_owned(),
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

    /// Whether `dir` holds exactly these files. The content of uta's fragment
    /// is not compared: it depends on the user's files, through
    /// [`log_at_info`], and otherwise only on `uta.toml`, which does not change
    /// while the daemon runs.
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
            let Some(mode) = file.mode else {
                continue;
            };
            let path = dir.join(&file.name);
            if fs::metadata(&path)?.permissions().mode() & 0o7777 != mode
                || fs::read(&path)? != file.content
            {
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

/// A sing-box log level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Panic,
}

impl Level {
    /// The level of a log line, such as `INFO[0012] ...` or, with timestamps,
    /// `+0800 2026-01-02 03:04:05 INFO ...`.
    pub fn of_line(line: &str) -> Option<Self> {
        line.split_whitespace().take(4).find_map(|word| {
            match word.split_once('[').map_or(word, |(level, _)| level) {
                "TRACE" => Some(Self::Trace),
                "DEBUG" => Some(Self::Debug),
                "INFO" => Some(Self::Info),
                "WARN" => Some(Self::Warn),
                "ERROR" => Some(Self::Error),
                "FATAL" => Some(Self::Fatal),
                "PANIC" => Some(Self::Panic),
                _ => None,
            }
        })
    }
}

/// The level the merged configuration asks for, if it is above info. uta
/// waits for an info line on startup, so such a configuration has to run at
/// info, and uta drops the lines below the level asked for.
pub fn log_filter(merged: &Value) -> Option<Level> {
    match merged["log"]["level"].as_str()? {
        "warn" | "warning" => Some(Level::Warn),
        "error" => Some(Level::Error),
        "fatal" => Some(Level::Fatal),
        "panic" => Some(Level::Panic),
        _ => None,
    }
}

/// Makes the configuration in `dir` log at info, through uta's fragment.
pub fn log_at_info(dir: &Path) -> Result<()> {
    let path = dir.join(FRAGMENT);
    let mut fragment: Value = serde_json::from_slice(&fs::read(&path)?)?;
    fragment["log"]["level"] = "info".into();
    fs::write(&path, serde_json::to_vec_pretty(&fragment)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_of_log_lines() {
        let level = Level::of_line;
        assert_eq!(
            level("INFO[0000] sing-box started (0.00s)"),
            Some(Level::Info)
        );
        assert_eq!(
            level("+0800 2026-01-02 03:04:05 WARN [123 0ms] dns: lookup failed"),
            Some(Level::Warn)
        );
        assert_eq!(level("DEBUG[0003] router: match"), Some(Level::Debug));
        assert_eq!(level("goroutine 1 [running]:"), None);
    }

    #[test]
    fn levels_above_info_are_filtered() {
        assert_eq!(log_filter(&json!({})), None);
        assert_eq!(log_filter(&json!({ "log": { "level": "debug" } })), None);
        assert_eq!(
            log_filter(&json!({ "log": { "level": "warn" } })),
            Some(Level::Warn)
        );
        assert_eq!(
            log_filter(&json!({ "log": { "level": "error" } })),
            Some(Level::Error)
        );
    }
}
