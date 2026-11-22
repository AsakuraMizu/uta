//! The control protocol: one JSON value per line over the daemon's unix socket.
//!
//! Every connection starts with a hello, then carries one request. A connection
//! is one transaction: closing it cancels an apply that has not been confirmed.

use std::{fs, io, os::unix::fs::MetadataExt, path::PathBuf};

use compio::{
    io::framed::{Framed, codec::serde_json::SerdeJsonCodec, frame::CharDelimited},
    net::UnixStream,
};
use serde::{Deserialize, Serialize};

/// Identifies the uta executable. A client and a daemon must run the same one,
/// as the protocol has no version of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Executable {
    dev: u64,
    ino: u64,
}

impl Executable {
    pub fn current() -> io::Result<Self> {
        let metadata = fs::metadata("/proc/self/exe")?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Hello(Executable),
    Status,
    /// Applies the sing-box configuration together with the rules file, or with
    /// `rules`, which the client writes to the rules file when the user keeps
    /// the change.
    Apply {
        rules: Option<String>,
        confirm_secs: u64,
    },
    Confirm,
    Rollback,
    /// Whether the client's cgroup is already captured through a cgroup, such
    /// as the scope of an enclosing `uta run`.
    Covered,
    /// Captures the client's cgroup, and what the source rules `with` select,
    /// until the cgroup holds no process.
    Run {
        with: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Hello {
        rules: PathBuf,
    },
    Status(Status),
    /// The request matches what is running.
    Unchanged,
    /// Only the sing-box configuration changed; it is running now.
    Applied,
    /// The captured traffic changed and is rolled back unless confirmed within
    /// `secs`.
    Pending {
        changes: Vec<String>,
        secs: u64,
    },
    Confirmed,
    RolledBack(String),
    Covered(bool),
    /// The client's cgroup is captured.
    Captured,
    Busy(String),
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub singbox_pid: u32,
    pub singbox_uptime_secs: u64,
    pub rules_path: PathBuf,
    pub rules: Vec<RuleStatus>,
    pub runs: Vec<RunStatus>,
    pub operation: Option<String>,
    /// The rules file differs from the rules last applied.
    pub rules_changed: bool,
    /// The sing-box configuration files differ from the ones last applied.
    pub singbox_changed: bool,
    /// What uta installed in the kernel and is no longer there.
    pub missing: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleStatus {
    pub rule: String,
    /// What the rule matched when it was applied, such as the ID of a user
    /// name.
    pub resolved: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunStatus {
    /// The scope of the `uta run`.
    pub cgroup: String,
    pub with: Vec<String>,
}

pub type Connection<Send, Receive> =
    Framed<UnixStream, UnixStream, SerdeJsonCodec, CharDelimited<'\n'>, Send, Receive>;

pub fn framed<Send, Receive>(stream: UnixStream) -> Connection<Send, Receive> {
    let (reader, writer) = stream.into_split();
    Framed::new::<Send, Receive>(SerdeJsonCodec::new(), CharDelimited::new())
        .with_reader(reader)
        .with_writer(writer)
}
