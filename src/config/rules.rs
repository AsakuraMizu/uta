//! The rules file: one rule per line, `#` starts a comment.
//!
//! A rule is a list of conditions separated by spaces, all of which must hold;
//! a rule starting with `!` excludes what it matches. A condition is
//! `kind:VALUES`, where values separated by commas are alternatives and a `!`
//! before them negates the condition. A connection is captured when it matches
//! an including rule and no excluding rule; the order of rules does not matter.

use std::{fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use thiserror::Error;

/// One line of the rules file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub exclude: bool,
    /// Sorted by kind, at most one of each kind.
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    pub negated: bool,
    pub selector: Selector,
}

/// What a condition tests, with its alternatives sorted and deduplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// Every socket of this host.
    Local,
    /// Sockets owned by a user.
    Uid(Vec<Id>),
    /// Sockets created with a group as the effective group.
    Gid(Vec<Id>),
    /// Sockets of processes in a matching cgroup or one of its descendants.
    Cgroup(Vec<CgroupPattern>),
    /// Forwarded traffic entering through a matching interface.
    Iif(Vec<IfacePattern>),
    /// Forwarded traffic from a source network.
    Src(Vec<IpNet>),
    /// Forwarded traffic from a link-layer address.
    Mac(Vec<Mac>),
    Proto(Vec<Proto>),
    /// Traffic to a destination network.
    Dst(Vec<IpNet>),
    /// Traffic to a destination port.
    Port(Vec<Span<u16>>),
    /// Traffic from a source port.
    Sport(Vec<Span<u16>>),
    /// Traffic that normal routing sends out through a matching interface.
    Oif(Vec<IfacePattern>),
}

/// Where the traffic a source condition selects comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// Sockets of this host.
    Local,
    /// Traffic this host forwards.
    Forwarded,
}

/// A user or group: IDs, or a name resolved through NSS when rules are
/// applied.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Id {
    Numbers(Span<u32>),
    Name(String),
}

/// An inclusive range of numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span<T> {
    pub first: T,
    pub last: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

/// An absolute cgroup path whose segments may contain `*`, which matches any
/// run of characters within one segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
        let (exclude, body) = match s.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        if body.is_empty() || body.starts_with(char::is_whitespace) {
            return Err(InvalidRule(format!(
                "`{s}`: `!` must be followed directly by a condition"
            )));
        }
        let mut conditions = body
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<Condition>, _>>()?;
        conditions.sort_by_key(|condition| condition.selector.order());
        for pair in conditions.windows(2) {
            if pair[0].selector.order() == pair[1].selector.order() {
                let kind = pair[0].selector.kind();
                return Err(InvalidRule(format!(
                    "`{s}` has `{kind}` twice; list the values of one condition, as in \
                     `{kind}:A,B`"
                )));
            }
        }
        let sources = |origin| {
            conditions
                .iter()
                .find(|condition| condition.selector.origin() == Some(origin))
        };
        if let (Some(local), Some(forwarded)) = (sources(Origin::Local), sources(Origin::Forwarded))
        {
            return Err(InvalidRule(format!(
                "`{s}` cannot match anything: `{}` selects sockets of this host and `{}` \
                 forwarded traffic",
                local.selector.kind(),
                forwarded.selector.kind()
            )));
        }
        let captures_a_source = conditions
            .iter()
            .any(|condition| !condition.negated && condition.selector.origin().is_some());
        if !exclude && !captures_a_source {
            return Err(InvalidRule(format!(
                "`{s}` has no source to capture; add local, uid:, gid:, cgroup:, iif:, src: or \
                 mac:"
            )));
        }
        Ok(Self {
            exclude,
            conditions,
        })
    }
}

impl Rule {
    /// Parses a rule that adds traffic to capture, as `uta run --with` takes.
    pub fn parse_include(s: &str) -> Result<Self, InvalidRule> {
        let rule: Self = s.parse()?;
        if rule.exclude {
            return Err(InvalidRule(format!(
                "`{s}` excludes traffic; --with takes a rule that captures"
            )));
        }
        Ok(rule)
    }

    /// Where the traffic the rule tests comes from, as its source conditions
    /// tell, or `None` if it has none and applies to all traffic.
    pub fn origin(&self) -> Option<Origin> {
        self.conditions
            .iter()
            .find_map(|condition| condition.selector.origin())
    }
}

impl Selector {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Uid(_) => "uid",
            Self::Gid(_) => "gid",
            Self::Cgroup(_) => "cgroup",
            Self::Iif(_) => "iif",
            Self::Src(_) => "src",
            Self::Mac(_) => "mac",
            Self::Proto(_) => "proto",
            Self::Dst(_) => "dst",
            Self::Port(_) => "port",
            Self::Sport(_) => "sport",
            Self::Oif(_) => "oif",
        }
    }

    /// The position of the kind in a rule as uta writes it.
    fn order(&self) -> usize {
        match self {
            Self::Local => 0,
            Self::Uid(_) => 1,
            Self::Gid(_) => 2,
            Self::Cgroup(_) => 3,
            Self::Iif(_) => 4,
            Self::Src(_) => 5,
            Self::Mac(_) => 6,
            Self::Proto(_) => 7,
            Self::Dst(_) => 8,
            Self::Port(_) => 9,
            Self::Sport(_) => 10,
            Self::Oif(_) => 11,
        }
    }

    /// Where the traffic comes from, for the kinds that select a source.
    pub fn origin(&self) -> Option<Origin> {
        match self {
            Self::Local | Self::Uid(_) | Self::Gid(_) | Self::Cgroup(_) => Some(Origin::Local),
            Self::Iif(_) | Self::Src(_) | Self::Mac(_) => Some(Origin::Forwarded),
            Self::Proto(_) | Self::Dst(_) | Self::Port(_) | Self::Sport(_) | Self::Oif(_) => None,
        }
    }
}

impl FromStr for Condition {
    type Err = InvalidRule;

    fn from_str(s: &str) -> Result<Self, InvalidRule> {
        let invalid = |message: String| Err(InvalidRule(message));
        let Some((kind, value)) = s.split_once(':') else {
            return match s {
                "local" => Ok(Self {
                    negated: false,
                    selector: Selector::Local,
                }),
                "uid" | "gid" | "cgroup" | "iif" | "src" | "mac" | "proto" | "dst" | "port"
                | "sport" | "oif" => invalid(format!("`{s}` needs a value, as in `{s}:VALUE`")),
                _ => invalid(format!("unknown condition `{s}`")),
            };
        };
        if kind == "local" {
            return invalid("`local` takes no value".to_owned());
        }
        let (negated, values) = match value.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        if values.is_empty() {
            return invalid(format!("`{s}` has an empty value"));
        }
        let selector = match kind {
            "uid" => Selector::Uid(list(values, parse_id)?),
            "gid" => Selector::Gid(list(values, parse_id)?),
            "cgroup" => Selector::Cgroup(list(values, parse_cgroup)?),
            "iif" => Selector::Iif(list(values, parse_iface)?),
            "src" => Selector::Src(list(values, parse_net)?),
            "mac" => Selector::Mac(list(values, parse_mac)?),
            "proto" => Selector::Proto(list(values, |value| match value {
                "tcp" => Ok(Proto::Tcp),
                "udp" => Ok(Proto::Udp),
                _ => Err(InvalidRule(format!("`{value}` is not tcp or udp"))),
            })?),
            "dst" => Selector::Dst(list(values, parse_net)?),
            "port" => Selector::Port(list(values, parse_port)?),
            "sport" => Selector::Sport(list(values, parse_port)?),
            "oif" => Selector::Oif(list(values, parse_iface)?),
            _ => return invalid(format!("unknown condition kind `{kind}`")),
        };
        Ok(Self { negated, selector })
    }
}

/// The comma-separated `values`, sorted and without duplicates.
fn list<T: Ord>(
    values: &str,
    parse: impl Fn(&str) -> Result<T, InvalidRule>,
) -> Result<Vec<T>, InvalidRule> {
    let mut items = values
        .split(',')
        .map(|value| {
            if value.is_empty() {
                Err(InvalidRule(format!("`{values}` has an empty value")))
            } else {
                parse(value)
            }
        })
        .collect::<Result<Vec<T>, _>>()?;
    items.sort();
    items.dedup();
    Ok(items)
}

fn parse_id(value: &str) -> Result<Id, InvalidRule> {
    let number = |s: &str| {
        s.parse::<u32>()
            .map_err(|_| InvalidRule(format!("`{s}` is out of range")))
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if digits(value) {
        let id = number(value)?;
        return Ok(Id::Numbers(Span {
            first: id,
            last: id,
        }));
    }
    match value.split_once('-') {
        Some((first, last)) if digits(first) && digits(last) => {
            span(number(first)?, number(last)?, value).map(Id::Numbers)
        }
        _ => Ok(Id::Name(value.to_owned())),
    }
}

fn parse_port(value: &str) -> Result<Span<u16>, InvalidRule> {
    let port = |s: &str| match s.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(InvalidRule(format!(
            "`{s}` is not a port between 1 and 65535"
        ))),
    };
    match value.split_once('-') {
        Some((first, last)) => span(port(first)?, port(last)?, value),
        None => {
            let port = port(value)?;
            Ok(Span {
                first: port,
                last: port,
            })
        }
    }
}

fn span<T: Ord>(first: T, last: T, value: &str) -> Result<Span<T>, InvalidRule> {
    if first > last {
        return Err(InvalidRule(format!(
            "`{value}` is an empty range; write the smaller number first"
        )));
    }
    Ok(Span { first, last })
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

fn parse_mac(value: &str) -> Result<Mac, InvalidRule> {
    let mut octets = [0; 6];
    let mut parts = value.split(':');
    for octet in &mut octets {
        match parts
            .next()
            .map(|part| (part.len(), u8::from_str_radix(part, 16)))
        {
            Some((2, Ok(byte))) => *octet = byte,
            _ => {
                return Err(InvalidRule(format!(
                    "`{value}` is not a MAC address like 02:00:5e:10:00:01"
                )));
            }
        }
    }
    if parts.next().is_some() {
        return Err(InvalidRule(format!(
            "`{value}` is not a MAC address like 02:00:5e:10:00:01"
        )));
    }
    Ok(Mac(octets))
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
        for (i, condition) in self.conditions.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            condition.fmt(f)?;
        }
        Ok(())
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = self.selector.kind();
        if let Selector::Local = self.selector {
            return f.write_str(kind);
        }
        write!(f, "{kind}:{}", if self.negated { "!" } else { "" })?;
        match &self.selector {
            Selector::Local => Ok(()),
            Selector::Uid(ids) | Selector::Gid(ids) => join(f, ids),
            Selector::Cgroup(patterns) => join(f, patterns),
            Selector::Iif(patterns) | Selector::Oif(patterns) => join(f, patterns),
            Selector::Src(nets) | Selector::Dst(nets) => join(f, nets.iter().map(Net)),
            Selector::Mac(macs) => join(f, macs),
            Selector::Proto(protos) => join(f, protos),
            Selector::Port(ports) | Selector::Sport(ports) => join(f, ports),
        }
    }
}

fn join<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    items: impl IntoIterator<Item = T>,
) -> fmt::Result {
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            f.write_str(",")?;
        }
        item.fmt(f)?;
    }
    Ok(())
}

/// A network as the rules file writes it: a single address reads back as
/// written, without a /32 or /128.
pub struct Net<'a>(pub &'a IpNet);

impl fmt::Display for Net<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.prefix_len() == self.0.max_prefix_len() {
            self.0.addr().fmt(f)
        } else {
            self.0.fmt(f)
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Numbers(span) => span.fmt(f),
            Self::Name(name) => f.write_str(name),
        }
    }
}

impl<T: fmt::Display + PartialEq> fmt::Display for Span<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            self.first.fmt(f)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

impl fmt::Display for CgroupPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.segments.join("/"))
    }
}

impl fmt::Display for IfacePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
            "line 5: unknown condition `bogus`\nline 6: `0` is not a port between 1 and 65535"
        );

        let rules =
            parse("# workstation\nuid:alice  # trailing comment\n\n!dst:10.0.0.0/8\n").unwrap();
        assert_eq!(rules, [rule("uid:alice"), rule("!dst:10.0.0.0/8")]);
        assert!(rules[1].exclude);
    }

    #[test]
    fn conditions_and_values_have_no_order() {
        assert_eq!(
            rule("port:443,80 uid:bob,alice"),
            rule("uid:alice,bob port:80,443")
        );
        assert_eq!(
            rule("port:443,80,443 uid:bob,alice").to_string(),
            "uid:alice,bob port:80,443"
        );
        assert_eq!(
            rule("!port:!53 dst:10.0.0.0/8").to_string(),
            "!dst:10.0.0.0/8 port:!53"
        );
    }

    #[test]
    fn a_rule_tests_each_kind_once() {
        assert!(error("uid:alice port:80 port:443").contains("`port:A,B`"));
        assert!(error("local local").contains("`local` twice"));
    }

    #[test]
    fn including_rules_need_a_source() {
        assert!(error("port:9").contains("no source"));
        assert!(error("uid:!alice").contains("no source"));
        assert!(error("dst:10.0.0.0/8 proto:tcp").contains("no source"));
        for s in [
            "local uid:!alice",
            "gid:proxied",
            "src:192.0.2.0/24",
            "mac:02:00:5e:10:00:01",
        ] {
            assert_eq!(rule(s).to_string(), s);
        }
        // Excluding rules may test anything.
        for s in [
            "!local",
            "!port:9",
            "!dst:10.0.0.0/8 port:!53",
            "!uid:!alice",
        ] {
            assert_eq!(rule(s).to_string(), s);
        }
    }

    #[test]
    fn a_rule_selects_sockets_or_forwarded_traffic_not_both() {
        assert!(error("uid:alice iif:eth0").contains("cannot match anything"));
        assert!(error("!cgroup:/a mac:02:00:5e:10:00:01").contains("cannot match anything"));
        assert_eq!(
            rule("iif:eth0 src:192.0.2.0/24").origin(),
            Some(Origin::Forwarded)
        );
        assert_eq!(rule("local uid:!alice").origin(), Some(Origin::Local));
        assert_eq!(rule("!dst:10.0.0.0/8").origin(), None);
    }

    #[test]
    fn negation_and_lists_attach_to_the_value() {
        let rule = rule("!dst:!10.0.0.0/8,fd00::/8");
        assert!(rule.exclude);
        assert!(rule.conditions[0].negated);
        assert!(error("! dst:10.0.0.0/8").contains("followed directly"));
        assert!(error("!").contains("followed directly"));
        assert_eq!(error("port:80,"), "`80,` has an empty value");
        assert_eq!(error("port:!"), "`port:!` has an empty value");
    }

    #[test]
    fn ids_are_numbers_ranges_or_names() {
        assert_eq!(
            rule("uid:1000-1999,alice,0,systemd-network").to_string(),
            "uid:0,1000-1999,alice,systemd-network"
        );
        assert!(error("uid:99999999999").contains("out of range"));
        assert!(error("gid:20-10").contains("empty range"));
    }

    #[test]
    fn ports_are_numbers_or_ranges() {
        assert_eq!(rule("!port:443,1-1023").to_string(), "!port:1-1023,443");
        assert!(error("!port:0").contains("between 1 and 65535"));
        assert!(error("!port:9-8").contains("empty range"));
        assert_eq!(
            rule("!sport:41641 iif:eth0 proto:udp").to_string(),
            "!iif:eth0 proto:udp sport:41641"
        );
    }

    #[test]
    fn addresses_are_networks_without_host_bits() {
        assert_eq!(rule("!dst:192.0.2.1/32"), rule("!dst:192.0.2.1"));
        assert_eq!(rule("!dst:192.0.2.1/32").to_string(), "!dst:192.0.2.1");
        assert_eq!(
            rule("!src:2001:db8::/32,2001:db8::1").to_string(),
            "!src:2001:db8::/32,2001:db8::1"
        );
        assert_eq!(
            error("!dst:10.1.2.3/8"),
            "`10.1.2.3/8` has host bits set; the network is 10.0.0.0/8"
        );
    }

    #[test]
    fn macs_and_protocols() {
        assert_eq!(
            rule("mac:02:00:5E:10:00:01").to_string(),
            "mac:02:00:5e:10:00:01"
        );
        assert!(error("mac:02:00:5e:10:00").contains("not a MAC address"));
        assert!(error("mac:02:00:5e:10:00:01:02").contains("not a MAC address"));
        assert!(error("mac:2:00:5e:10:00:01").contains("not a MAC address"));
        assert_eq!(rule("!proto:udp,tcp").to_string(), "!proto:tcp,udp");
        assert!(error("!proto:icmp").contains("not tcp or udp"));
    }

    #[test]
    fn values_are_required_where_expected() {
        assert_eq!(error("local:x"), "`local` takes no value");
        assert_eq!(error("uid"), "`uid` needs a value, as in `uid:VALUE`");
        assert_eq!(error("port:"), "`port:` has an empty value");
        assert_eq!(error("pid:1"), "unknown condition kind `pid`");
    }

    #[test]
    fn interface_wildcard_only_at_the_end() {
        assert_eq!(rule("iif:br-*").to_string(), "iif:br-*");
        assert_eq!(rule("!oif:*").to_string(), "!oif:*");
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
    fn with_takes_including_rules() {
        for s in [
            "local",
            "cgroup:/system.slice/docker.service port:443",
            "iif:eth0",
        ] {
            assert_eq!(Rule::parse_include(s).unwrap().to_string(), s);
        }
        assert!(Rule::parse_include("!uid:bob").is_err());
    }

    #[test]
    fn cgroup_glob_stays_within_a_segment() {
        let pattern = |s: &str| match &rule(&format!("cgroup:{s}")).conditions[0].selector {
            Selector::Cgroup(patterns) => patterns[0].clone(),
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
}
