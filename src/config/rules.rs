//! The rules file: one selector per line, `#` starts a comment.
//!
//! A connection is captured when it matches an include source selector, matches
//! an include destination selector if there are any, and matches no exclude
//! selector.

use std::{fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use thiserror::Error;

/// One line of the rules file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub exclude: bool,
    pub selector: Selector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// Every socket of this host.
    Local,
    /// Sockets owned by a user.
    Uid(User),
    /// Sockets of processes in a matching cgroup or one of its descendants.
    Cgroup(CgroupPattern),
    /// Forwarded traffic entering through a matching interface.
    Iif(IfacePattern),
    /// Traffic to a destination network.
    Dst(IpNet),
    /// Traffic to a destination port.
    Port(u16),
    /// Traffic that normal routing sends out through a matching interface.
    Oif(IfacePattern),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum User {
    Id(u32),
    /// Resolved through NSS when rules are applied.
    Name(String),
}

/// An absolute cgroup path whose segments may contain `*`, which matches any
/// run of characters within one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupPattern {
    segments: Vec<String>,
}

impl CgroupPattern {
    /// Depth below the cgroup root, as used by `socket cgroupv2 level`.
    pub fn level(&self) -> usize {
        self.segments.len()
    }

    /// Whether `name` matches the segment at `depth`, counted from 0 below the
    /// root.
    pub fn matches_segment(&self, depth: usize, name: &str) -> bool {
        self.segments
            .get(depth)
            .is_some_and(|segment| glob(segment, name))
    }
}

/// An interface name, optionally ending in `*` to match a prefix as nftables
/// does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfacePattern(String);

impl IfacePattern {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct InvalidRule(String);

/// Every invalid line of a rules file.
#[derive(Debug, Error)]
pub struct ParseError(Vec<(usize, InvalidRule)>);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (line, error)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "line {line}: {error}")?;
        }
        Ok(())
    }
}

pub fn parse(text: &str) -> Result<Vec<Rule>, ParseError> {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let content = line
            .split_once('#')
            .map_or(line, |(content, _)| content)
            .trim();
        if content.is_empty() {
            continue;
        }
        match content.parse() {
            Ok(rule) => rules.push(rule),
            Err(error) => errors.push((index + 1, error)),
        }
    }
    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(ParseError(errors))
    }
}

impl FromStr for Rule {
    type Err = InvalidRule;

    fn from_str(s: &str) -> Result<Self, InvalidRule> {
        if s.contains(char::is_whitespace) {
            return Err(InvalidRule(format!("`{s}` is not a single selector")));
        }
        let (exclude, selector) = match s.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        Ok(Self {
            exclude,
            selector: selector.parse()?,
        })
    }
}

impl Rule {
    /// Parses a rule that adds a source to capture, as `uta run --with` takes:
    /// one of the kinds that select traffic by where it comes from, not
    /// excluding.
    pub fn parse_source(s: &str) -> Result<Self, InvalidRule> {
        let rule: Self = s.parse()?;
        let source = matches!(
            rule.selector,
            Selector::Local | Selector::Uid(_) | Selector::Cgroup(_) | Selector::Iif(_)
        );
        if rule.exclude || !source {
            return Err(InvalidRule(format!(
                "`{s}` is not a local, uid:, cgroup: or iif: rule"
            )));
        }
        Ok(rule)
    }
}

impl FromStr for Selector {
    type Err = InvalidRule;

    fn from_str(s: &str) -> Result<Self, InvalidRule> {
        let invalid = |message: String| Err(InvalidRule(message));
        let Some((kind, value)) = s.split_once(':') else {
            return match s {
                "local" => Ok(Self::Local),
                "uid" | "cgroup" | "iif" | "dst" | "port" | "oif" => {
                    invalid(format!("`{s}` needs a value, as in `{s}:VALUE`"))
                }
                _ => invalid(format!("unknown selector `{s}`")),
            };
        };
        if value.is_empty() {
            return invalid(format!("`{kind}:` has an empty value"));
        }
        match kind {
            "local" => invalid("`local` takes no value".to_owned()),
            "uid" => Ok(Self::Uid(match value.parse() {
                Ok(id) => User::Id(id),
                Err(_) if value.bytes().all(|b| b.is_ascii_digit()) => {
                    return invalid(format!("uid `{value}` is out of range"));
                }
                Err(_) => User::Name(value.to_owned()),
            })),
            "cgroup" => parse_cgroup(value).map(Self::Cgroup),
            "iif" => parse_iface(value).map(Self::Iif),
            "oif" => parse_iface(value).map(Self::Oif),
            "dst" => parse_net(value).map(Self::Dst),
            "port" => match value.parse() {
                Ok(port) if port != 0 => Ok(Self::Port(port)),
                _ => invalid(format!("`{value}` is not a port between 1 and 65535")),
            },
            _ => invalid(format!("unknown selector kind `{kind}`")),
        }
    }
}

fn parse_cgroup(value: &str) -> Result<CgroupPattern, InvalidRule> {
    let invalid = |reason: &str| Err(InvalidRule(format!("cgroup `{value}` {reason}")));
    let Some(rest) = value.strip_prefix('/') else {
        return invalid("must be an absolute path");
    };
    if rest.is_empty() {
        return invalid("is the cgroup root; use `local` for every socket");
    }
    let mut segments = Vec::new();
    for segment in rest.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return invalid("has an empty, `.` or `..` segment");
        }
        if segment.contains(|c: char| c == '"' || c.is_control()) {
            return invalid("contains `\"` or a control character");
        }
        segments.push(segment.to_owned());
    }
    Ok(CgroupPattern { segments })
}

fn parse_iface(value: &str) -> Result<IfacePattern, InvalidRule> {
    let invalid = |reason: &str| Err(InvalidRule(format!("interface `{value}` {reason}")));
    let name = value.strip_suffix('*').unwrap_or(value);
    // IFNAMSIZ is 16 including the terminating NUL.
    if name.len() > 15 {
        return invalid("is longer than 15 bytes");
    }
    if name.contains(|c: char| matches!(c, '/' | '"' | '*') || c.is_control()) {
        return invalid("contains `/`, `\"`, a control character, or `*` before the end");
    }
    Ok(IfacePattern(value.to_owned()))
}

fn parse_net(value: &str) -> Result<IpNet, InvalidRule> {
    if let Ok(addr) = value.parse::<IpAddr>() {
        return Ok(addr.into());
    }
    let Ok(net) = value.parse::<IpNet>() else {
        return Err(InvalidRule(format!(
            "`{value}` is not an IP address or network"
        )));
    };
    if net.trunc() != net {
        return Err(InvalidRule(format!(
            "`{value}` has host bits set; the network is {}",
            net.trunc()
        )));
    }
    Ok(net)
}

/// Matches `name` against `pattern`, where `*` matches any run of characters.
fn glob(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty();
    };
    for part in parts {
        let Some(start) = rest.find(part) else {
            return false;
        };
        rest = &rest[start + part.len()..];
    }
    rest.ends_with(last)
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.exclude {
            f.write_str("!")?;
        }
        self.selector.fmt(f)
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::Uid(User::Id(id)) => write!(f, "uid:{id}"),
            Self::Uid(User::Name(name)) => write!(f, "uid:{name}"),
            Self::Cgroup(pattern) => write!(f, "cgroup:/{}", pattern.segments.join("/")),
            Self::Iif(pattern) => write!(f, "iif:{}", pattern.0),
            Self::Dst(net) => write!(f, "dst:{net}"),
            Self::Port(port) => write!(f, "port:{port}"),
            Self::Oif(pattern) => write!(f, "oif:{}", pattern.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> Rule {
        s.parse().unwrap()
    }

    fn error(s: &str) -> String {
        s.parse::<Rule>().unwrap_err().to_string()
    }

    #[test]
    fn parses_file_with_comments_and_reports_every_bad_line() {
        let text =
            "# workstation\nuid:alice  # trailing comment\n\n!dst:10.0.0.0/8\nbogus\nport:0\n";
        let errors = parse(text).unwrap_err().to_string();
        assert_eq!(
            errors,
            "line 5: unknown selector `bogus`\nline 6: `0` is not a port between 1 and 65535"
        );

        let rules =
            parse("# workstation\nuid:alice  # trailing comment\n\n!dst:10.0.0.0/8\n").unwrap();
        assert_eq!(rules, [rule("uid:alice"), rule("!dst:10.0.0.0/8")]);
        assert!(rules[1].exclude);
    }

    #[test]
    fn rejects_more_than_one_selector_per_line() {
        assert!(parse("uid:1 uid:2\n").is_err());
    }

    #[test]
    fn uid_is_numeric_or_a_name() {
        assert_eq!(rule("uid:1000").selector, Selector::Uid(User::Id(1000)));
        assert_eq!(
            rule("uid:alice").selector,
            Selector::Uid(User::Name("alice".to_owned()))
        );
        assert!(error("uid:99999999999").contains("out of range"));
    }

    #[test]
    fn dst_accepts_addresses_and_networks_but_not_host_bits() {
        assert_eq!(rule("dst:192.0.2.1").to_string(), "dst:192.0.2.1/32");
        assert_eq!(rule("dst:2001:db8::/32").to_string(), "dst:2001:db8::/32");
        assert_eq!(
            error("dst:10.1.2.3/8"),
            "`10.1.2.3/8` has host bits set; the network is 10.0.0.0/8"
        );
    }

    #[test]
    fn values_are_required_where_expected() {
        assert_eq!(error("local:x"), "`local` takes no value");
        assert_eq!(error("uid"), "`uid` needs a value, as in `uid:VALUE`");
        assert_eq!(error("port:"), "`port:` has an empty value");
        assert_eq!(error("pid:1"), "unknown selector kind `pid`");
    }

    #[test]
    fn interface_wildcard_only_at_the_end() {
        assert_eq!(rule("iif:br-*").to_string(), "iif:br-*");
        assert_eq!(rule("oif:*").to_string(), "oif:*");
        assert!(error("iif:br*lan").contains("before the end"));
        assert!(error("iif:abcdefghijklmnop").contains("longer than 15 bytes"));
    }

    #[test]
    fn cgroup_must_be_absolute_and_below_root() {
        assert!(error("cgroup:system.slice").contains("absolute"));
        assert!(error("cgroup:/").contains("use `local`"));
        assert!(error("cgroup:/a//b").contains("empty"));
        assert!(error("cgroup:/a/../b").contains("`..`"));
    }

    #[test]
    fn sources_are_including_rules_of_the_first_four_kinds() {
        for s in [
            "local",
            "uid:bob",
            "cgroup:/system.slice/docker.service",
            "iif:eth0",
        ] {
            assert_eq!(Rule::parse_source(s).unwrap().to_string(), s);
        }
        for s in ["!uid:bob", "dst:10.0.0.0/8", "port:443", "oif:eth0"] {
            assert!(Rule::parse_source(s).is_err(), "{s}");
        }
    }

    #[test]
    fn cgroup_glob_stays_within_a_segment() {
        let pattern = |s: &str| match rule(&format!("cgroup:{s}")).selector {
            Selector::Cgroup(pattern) => pattern,
            _ => unreachable!(),
        };
        let user_app = pattern("/user.slice/user-*.slice/user@*.service/app.slice/agent.scope");
        assert_eq!(user_app.level(), 5);
        assert!(user_app.matches_segment(1, "user-1000.slice"));
        assert!(user_app.matches_segment(2, "user@1000.service"));
        assert!(!user_app.matches_segment(4, "other.scope"));
        assert!(!user_app.matches_segment(5, "agent.scope"));

        let infix = pattern("/system.slice/run-*-x*.scope");
        assert!(infix.matches_segment(1, "run-u12-x3.scope"));
        assert!(!infix.matches_segment(1, "run-u12.scope"));
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "local",
            "!uid:1000",
            "cgroup:/system.slice/docker.service",
            "!oif:wg0",
        ] {
            assert_eq!(rule(s).to_string(), s);
        }
    }
}
