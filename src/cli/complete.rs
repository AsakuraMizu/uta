//! Shell completion of rules, for `uta add`, `uta del`, and `uta run --with`.

use std::{
    ffi::{CStr, OsStr},
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use clap_complete::CompletionCandidate;
use nix::{
    libc,
    unistd::{Group, User, getgid, getuid},
};

use crate::{
    config::rules,
    rpc::{Executable, Request, Response},
    selection::CGROUP_ROOT,
};

/// The conditions a rule may have, with what they test.
const KINDS: &[(&str, &str)] = &[
    ("local", "every socket of this host"),
    ("uid:", "sockets of users"),
    (
        "gid:",
        "sockets created with a group as the effective group",
    ),
    ("cgroup:/", "processes in cgroups or below them"),
    ("iif:", "forwarded traffic entering through interfaces"),
    ("src:", "forwarded traffic from addresses or networks"),
    ("mac:", "forwarded traffic from link-layer addresses"),
    ("proto:", "tcp or udp"),
    ("dst:", "traffic to addresses or networks"),
    ("port:", "traffic to ports"),
    ("sport:", "traffic from ports"),
    ("oif:", "traffic that routing sends out of interfaces"),
];

/// Completes the condition being typed at the end of a rule.
pub fn rule(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = unquoted(current);
    match typing(&current) {
        Typing::Kind { kept, partial } => KINDS
            .iter()
            .filter(|(kind, _)| kind.starts_with(partial))
            .map(|(kind, help)| {
                CompletionCandidate::new(format!("{kept}{kind}")).help(Some((*help).into()))
            })
            .collect(),
        Typing::Value {
            kept,
            kind,
            partial,
        } => values(kind, partial)
            .into_iter()
            .map(|value| CompletionCandidate::new(format!("{kept}{value}")))
            .collect(),
    }
}

/// Completes the rules in the rules file of the running daemon.
pub fn existing_rule(current: &OsStr) -> Vec<CompletionCandidate> {
    let current = unquoted(current);
    let Some(text) = rules_path().and_then(|path| fs::read_to_string(path).ok()) else {
        return Vec::new();
    };
    let Ok(rules) = rules::parse(&text) else {
        return Vec::new();
    };
    rules
        .iter()
        .map(ToString::to_string)
        .filter(|rule| rule.starts_with(&*current))
        .map(CompletionCandidate::new)
        .collect()
}

/// The word being completed, without the quote that opens it: fish passes the
/// word as typed, and the shell quotes the candidate itself.
fn unquoted(current: &OsStr) -> String {
    let current = current.to_string_lossy();
    current
        .strip_prefix(['\'', '"'])
        .unwrap_or(&current)
        .to_owned()
}

/// The part of a rule being typed.
#[derive(Debug, PartialEq, Eq)]
enum Typing<'a> {
    /// The kind of a condition, after `kept`.
    Kind { kept: &'a str, partial: &'a str },
    /// A value of a condition of `kind`, after `kept`.
    Value {
        kept: &'a str,
        kind: &'a str,
        partial: &'a str,
    },
}

/// Splits `current` at the last condition, and in it at the last value.
fn typing(current: &str) -> Typing<'_> {
    let mut start = current.rfind(' ').map_or(0, |space| space + 1);
    // A `!` that starts the rule excludes what it matches.
    if start == 0 && current.starts_with('!') {
        start = 1;
    }
    let condition = &current[start..];
    let Some((kind, values)) = condition.split_once(':') else {
        return Typing::Kind {
            kept: &current[..start],
            partial: condition,
        };
    };
    let first = usize::from(values.starts_with('!'));
    let value = start + kind.len() + 1 + values.rfind(',').map_or(first, |comma| comma + 1);
    Typing::Value {
        kept: &current[..value],
        kind,
        partial: &current[value..],
    }
}

/// The values of a condition of `kind` that start with `partial`.
fn values(kind: &str, partial: &str) -> Vec<String> {
    let mut values = match kind {
        "uid" => users(),
        "gid" => groups(),
        "iif" | "oif" => entries(Path::new("/sys/class/net")),
        "proto" => vec!["tcp".to_owned(), "udp".to_owned()],
        "cgroup" => cgroups(partial),
        _ => Vec::new(),
    };
    values.retain(|value| value.starts_with(partial));
    values.sort();
    values.dedup();
    values
}

/// The users NSS lists, as `getent passwd` does, and the current user, whom a
/// directory service may not list.
fn users() -> Vec<String> {
    let mut users = Vec::new();
    // SAFETY: completion runs on one thread, and each name is copied before
    // the next call reuses the entry.
    unsafe {
        libc::setpwent();
        loop {
            let entry = libc::getpwent();
            if entry.is_null() {
                break;
            }
            users.push(
                CStr::from_ptr((*entry).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        libc::endpwent();
    }
    if let Ok(Some(user)) = User::from_uid(getuid()) {
        users.push(user.name);
    }
    users
}

/// The groups NSS lists, as `getent group` does, and the current user's
/// group.
fn groups() -> Vec<String> {
    let mut groups = Vec::new();
    // SAFETY: as in `users`.
    unsafe {
        libc::setgrent();
        loop {
            let entry = libc::getgrent();
            if entry.is_null() {
                break;
            }
            groups.push(
                CStr::from_ptr((*entry).gr_name)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        libc::endgrent();
    }
    if let Ok(Some(group)) = Group::from_gid(getgid()) {
        groups.push(group.name);
    }
    groups
}

fn entries(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

/// The cgroups in the directory that `partial`, a path from the cgroup root,
/// is typed in.
fn cgroups(partial: &str) -> Vec<String> {
    let dir = partial.rsplit_once('/').map_or("", |(dir, _)| dir);
    let path = Path::new(CGROUP_ROOT).join(dir.trim_start_matches('/'));
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| format!("{dir}/{}", entry.file_name().to_string_lossy()))
        .collect()
}

/// The rules file of the daemon at the default control socket.
fn rules_path() -> Option<PathBuf> {
    let socket = super::socket_path(std::env::var_os("UTA_SOCKET").map(PathBuf::from));
    let mut stream = UnixStream::connect(socket).ok()?;
    let hello = serde_json::to_string(&Request::Hello(Executable::current().ok()?)).ok()?;
    writeln!(stream, "{hello}").ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    match serde_json::from_str(&line).ok()? {
        Response::Hello { rules } => Some(rules),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_at_the_condition_and_value_being_typed() {
        assert_eq!(
            typing(""),
            Typing::Kind {
                kept: "",
                partial: ""
            }
        );
        assert_eq!(
            typing("!ds"),
            Typing::Kind {
                kept: "!",
                partial: "ds"
            }
        );
        assert_eq!(
            typing("uid:alice po"),
            Typing::Kind {
                kept: "uid:alice ",
                partial: "po"
            }
        );
        assert_eq!(
            typing("uid:al"),
            Typing::Value {
                kept: "uid:",
                kind: "uid",
                partial: "al"
            }
        );
        assert_eq!(
            typing("!dst:10.0.0.0/8 port:!5"),
            Typing::Value {
                kept: "!dst:10.0.0.0/8 port:!",
                kind: "port",
                partial: "5"
            }
        );
        assert_eq!(
            typing("iif:!eth0,br-"),
            Typing::Value {
                kept: "iif:!eth0,",
                kind: "iif",
                partial: "br-"
            }
        );
        assert_eq!(
            typing("cgroup:/system.slice/do"),
            Typing::Value {
                kept: "cgroup:",
                kind: "cgroup",
                partial: "/system.slice/do"
            }
        );
    }
}
