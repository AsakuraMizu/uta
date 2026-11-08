//! The nftables table that selects traffic and hands it to sing-box's tproxy
//! inbound.

use askama::Template;
use ipnet::IpNet;

use crate::{
    config::{Marks, Ports, rules::IfacePattern},
    selection::{Selection, Side},
};

pub const TABLE: &str = "uta";

/// A script for `nft -f` that replaces uta's table in one transaction.
pub fn ruleset(selection: &Selection, marks: &Marks, ports: &Ports) -> String {
    let Selection { include, exclude } = selection;
    let mut sets = Vec::new();
    sets_of(&mut sets, "include", include);
    sets_of(&mut sets, "exclude", exclude);

    let output = Hook {
        exclude_all: exclude.local,
        exclude: [
            local_sources(exclude, "exclude"),
            destinations(exclude, "exclude", HookKind::Output),
        ]
        .concat(),
        include_all: include.local,
        include: local_sources(include, "include"),
        destinations: destinations(include, "include", HookKind::Output),
    };
    let prerouting = Hook {
        exclude_all: false,
        exclude: [
            forward_sources(exclude),
            destinations(exclude, "exclude", HookKind::Prerouting),
        ]
        .concat(),
        include_all: false,
        include: forward_sources(include),
        destinations: destinations(include, "include", HookKind::Prerouting),
    };

    Ruleset {
        table: TABLE,
        sets,
        output,
        prerouting,
        mask: format!("{:#x}", marks.mask),
        keep: format!("{:#010x}", !marks.mask),
        local: format!("{:#x}", marks.local),
        forward: format!("{:#x}", marks.forward),
        dns: format!("{:#x}", marks.mask),
        tproxy_port: ports.tproxy,
        dns_port: ports.dns,
    }
    .render()
    .expect("the ruleset template has no fallible parts")
}

#[derive(Template)]
#[template(path = "kernel/nft/ruleset.nft", escape = "none")]
struct Ruleset {
    table: &'static str,
    sets: Vec<Set>,
    output: Hook,
    prerouting: Hook,
    /// The bits of a mark outside uta's mask, kept when uta sets its own bits.
    keep: String,
    mask: String,
    local: String,
    forward: String,
    dns: String,
    tproxy_port: u16,
    dns_port: u16,
}

struct Set {
    name: String,
    declaration: String,
    elements: Vec<String>,
}

/// The selector matchers of one hook. Excludes are checked first; a source
/// include continues to the destination chain, which passes everything when
/// there are no include destinations.
struct Hook {
    exclude_all: bool,
    exclude: Vec<String>,
    include_all: bool,
    include: Vec<String>,
    destinations: Vec<String>,
}

#[derive(Clone, Copy)]
enum HookKind {
    Output,
    Prerouting,
}

fn sets_of(sets: &mut Vec<Set>, side_name: &str, side: &Side) {
    let mut add = |name: String, declaration: String, elements: Vec<String>| {
        sets.push(Set {
            name,
            declaration,
            elements,
        });
    };
    if !side.uids.is_empty() {
        add(
            format!("uid_{side_name}"),
            "type uid;".to_owned(),
            side.uids.iter().map(u32::to_string).collect(),
        );
    }
    for (level, cgroups) in &side.cgroups {
        add(
            format!("cgroup_{side_name}_{level}"),
            format!("typeof socket cgroupv2 level {level};"),
            cgroups.iter().map(|cgroup| quote(&cgroup.path)).collect(),
        );
    }
    let (v4, v6): (Vec<&IpNet>, Vec<&IpNet>) = side
        .nets
        .iter()
        .partition(|net| matches!(net, IpNet::V4(_)));
    for (name, kind, nets) in [("dst4", "ipv4_addr", v4), ("dst6", "ipv6_addr", v6)] {
        if !nets.is_empty() {
            add(
                format!("{name}_{side_name}"),
                format!("type {kind}; flags interval; auto-merge;"),
                nets.iter().map(ToString::to_string).collect(),
            );
        }
    }
    if !side.ports.is_empty() {
        add(
            format!("port_{side_name}"),
            "type inet_service;".to_owned(),
            side.ports.iter().map(u16::to_string).collect(),
        );
    }
}

/// Matchers for sockets of this host, except `local`, which matches everything.
fn local_sources(side: &Side, side_name: &str) -> Vec<String> {
    let mut matchers = Vec::new();
    if !side.uids.is_empty() {
        matchers.push(format!("meta skuid @uid_{side_name}"));
    }
    for level in side.cgroups.keys() {
        matchers.push(format!(
            "socket cgroupv2 level {level} @cgroup_{side_name}_{level}"
        ));
    }
    matchers
}

fn forward_sources(side: &Side) -> Vec<String> {
    if side.iifs.is_empty() {
        Vec::new()
    } else {
        vec![format!("iifname {}", ifname_set(&side.iifs))]
    }
}

fn destinations(side: &Side, side_name: &str, hook: HookKind) -> Vec<String> {
    let mut matchers = Vec::new();
    if side.nets.iter().any(|net| matches!(net, IpNet::V4(_))) {
        matchers.push(format!("ip daddr @dst4_{side_name}"));
    }
    if side.nets.iter().any(|net| matches!(net, IpNet::V6(_))) {
        matchers.push(format!("ip6 daddr @dst6_{side_name}"));
    }
    if !side.ports.is_empty() {
        matchers.push(format!("th dport @port_{side_name}"));
    }
    if !side.oifs.is_empty() {
        let set = ifname_set(&side.oifs);
        matchers.push(match hook {
            // The output hook has no fib oif lookup; meta oifname is the device
            // chosen by the routing decision made before uta reroutes the
            // packet.
            HookKind::Output => format!("oifname {set}"),
            HookKind::Prerouting => format!("fib daddr oifname {set}"),
        });
    }
    matchers
}

fn ifname_set(patterns: &[IfacePattern]) -> String {
    let names: Vec<String> = patterns.iter().map(|p| quote(p.as_str())).collect();
    format!("{{ {} }}", names.join(", "))
}

fn quote(s: &str) -> String {
    format!("\"{s}\"")
}
