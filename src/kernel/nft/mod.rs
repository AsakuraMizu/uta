//! The nftables table that selects traffic and hands it to sing-box's tproxy
//! inbound.

use std::fmt::Display;

use askama::Template;
use ipnet::IpNet;

use crate::{
    config::{
        Marks, Ports,
        rules::{IfacePattern, Origin},
    },
    selection::{Match, Selection, Test, Value},
};

pub const TABLE: &str = "uta";

/// A script for `nft -f` that replaces uta's table in one transaction.
pub fn ruleset(selection: &Selection, marks: &Marks, ports: &Ports) -> String {
    let mut sets = Vec::new();
    let mut hook = |origin| Hook {
        exclude: statements(&selection.exclude, origin, "exclude", &mut sets),
        include: statements(&selection.include, origin, "include", &mut sets),
    };
    let output = hook(Origin::Local);
    let prerouting = hook(Origin::Forwarded);

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

/// The matchers of the rules that apply in one hook. Each excluding matcher
/// returns; each including one sends the packet on to be captured.
struct Hook {
    exclude: Vec<String>,
    include: Vec<String>,
}

/// The matchers for the rules in `matches` that apply to traffic of `origin`.
/// A rule may need several, as one nft rule cannot express every rule.
fn statements(matches: &[Match], origin: Origin, side: &str, sets: &mut Vec<Set>) -> Vec<String> {
    let mut statements = Vec::new();
    for (index, resolved) in matches.iter().enumerate() {
        if resolved.origin.is_some_and(|of| of != origin) {
            continue;
        }
        let name = format!("{side}{index}");
        for matchers in alternatives(resolved, origin, &name, sets) {
            statements.push(matchers.join(" "));
        }
    }
    statements
}

/// The alternatives, each a list of matchers that must all hold, that
/// together match what `resolved` matches.
fn alternatives(
    resolved: &Match,
    origin: Origin,
    name: &str,
    sets: &mut Vec<Set>,
) -> Vec<Vec<String>> {
    let mut alternatives = families(&resolved.tests);
    for test in &resolved.tests {
        let not = if test.negated { "!= " } else { "" };
        let matcher = match &test.value {
            // Every packet in the output hook comes from a socket of this host.
            Value::Local => continue,
            // In the alternatives already, one for each address family.
            Value::Src(_) | Value::Dst(_) => continue,
            Value::Cgroup(levels) => {
                // `socket cgroupv2 level N` tests one level of the socket's
                // cgroup, so cgroups of several levels need a set and a test
                // each: any of them for a condition, none for a negated one.
                let mut per_level = Vec::new();
                for (level, cgroups) in levels {
                    let set = format!("{name}_cgroup{level}");
                    sets.push(Set {
                        name: set.clone(),
                        declaration: format!("typeof socket cgroupv2 level {level};"),
                        elements: cgroups.iter().map(|cgroup| quote(&cgroup.path)).collect(),
                    });
                    per_level.push(format!("socket cgroupv2 level {level} {not}@{set}"));
                }
                if test.negated {
                    for alternative in &mut alternatives {
                        alternative.extend(per_level.iter().cloned());
                    }
                } else {
                    alternatives = alternatives
                        .iter()
                        .flat_map(|alternative| {
                            per_level.iter().map(move |matcher| {
                                let mut alternative = alternative.clone();
                                alternative.push(matcher.clone());
                                alternative
                            })
                        })
                        .collect();
                }
                continue;
            }
            Value::Uid(spans) => format!("meta skuid {not}{}", anonymous(spans)),
            Value::Gid(spans) => format!("meta skgid {not}{}", anonymous(spans)),
            Value::Iif(patterns) => format!("iifname {not}{}", names(patterns)),
            Value::Mac(macs) => format!("ether saddr {not}{}", anonymous(macs)),
            Value::Proto(protos) => format!("meta l4proto {not}{}", anonymous(protos)),
            Value::Port(spans) => format!("th dport {not}{}", anonymous(spans)),
            Value::Oif(patterns) => match origin {
                // The output hook has no fib oif lookup; meta oifname is the
                // device chosen by the routing decision made before uta
                // reroutes the packet.
                Origin::Local => format!("oifname {not}{}", names(patterns)),
                Origin::Forwarded => format!("fib daddr oifname {not}{}", names(patterns)),
            },
        };
        for alternative in &mut alternatives {
            alternative.push(matcher.clone());
        }
    }
    alternatives
}

/// One alternative per address family that the address tests of `tests` can
/// match, with those tests; one alternative without matchers if there are no
/// address tests.
fn families(tests: &[Test]) -> Vec<Vec<String>> {
    let addresses: Vec<(&Test, &str, &[IpNet])> = tests
        .iter()
        .filter_map(|test| match &test.value {
            Value::Src(nets) => Some((test, "saddr", nets.as_slice())),
            Value::Dst(nets) => Some((test, "daddr", nets.as_slice())),
            _ => None,
        })
        .collect();
    if addresses.is_empty() {
        return vec![Vec::new()];
    }
    let mut alternatives = Vec::new();
    'family: for (family, field) in [("ipv4", "ip"), ("ipv6", "ip6")] {
        let mut matchers = vec![format!("meta nfproto {family}")];
        for (test, direction, nets) in &addresses {
            let nets: Vec<&IpNet> = nets
                .iter()
                .filter(|net| matches!(net, IpNet::V4(_)) == (family == "ipv4"))
                .collect();
            match (nets.is_empty(), test.negated) {
                // No address of this family can match.
                (true, false) => continue 'family,
                // Every address of this family is outside the list.
                (true, true) => {}
                (false, negated) => matchers.push(format!(
                    "{field} {direction} {}{}",
                    if negated { "!= " } else { "" },
                    anonymous(&nets)
                )),
            }
        }
        alternatives.push(matchers);
    }
    alternatives
}

fn anonymous<T: Display>(items: &[T]) -> String {
    let items: Vec<String> = items.iter().map(ToString::to_string).collect();
    format!("{{ {} }}", items.join(", "))
}

fn names(patterns: &[IfacePattern]) -> String {
    let names: Vec<String> = patterns.iter().map(|p| quote(p.as_str())).collect();
    format!("{{ {} }}", names.join(", "))
}

fn quote(s: &str) -> String {
    format!("\"{s}\"")
}
