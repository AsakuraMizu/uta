//! Policy routing that delivers captured packets to the local stack, where
//! tproxy assigns them to sing-box.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use futures_util::TryStreamExt;
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType},
    rule::{RuleAction, RuleAttribute},
};
use nix::errno::Errno;
use rtnetlink::{
    Handle, IpVersion, RouteMessageBuilder, RuleAddRequest,
    packet_core::{NetlinkMessage, NetlinkPayload},
};

use crate::config::Kernel;

/// The protocol of uta's rules and routes, so that cleanup finds them without
/// reading the configuration.
pub const PROTOCOL: RouteProtocol = RouteProtocol::Other(117);

/// Every network namespace numbers its loopback device 1 (`LOOPBACK_IFINDEX`).
const LOOPBACK_IFINDEX: u32 = 1;

/// Installs, for both address families, the rules that send marked packets to
/// uta's table and the table's route to the local stack. Entries that exist
/// are kept, so that installing again puts back what another program removed.
/// Returns how many entries it added.
pub async fn install(handle: &Handle, kernel: &Kernel) -> Result<usize, rtnetlink::Error> {
    let Kernel {
        marks,
        route_table: table,
        rule_priority: first,
    } = *kernel;
    let skip = first + 3;
    let mut added = 0;
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let rule = |priority, action| rule(handle, family, priority, action);
        added += new(rule(skip, RuleAction::Nop).execute().await)?;
        added += new(with_mark(
            rule(first + 2, RuleAction::ToTable),
            marks.forward,
            marks.mask,
        )
        .table_id(table)
        .execute()
        .await)?;
        added += new(with_mark(
            rule(first + 1, RuleAction::ToTable),
            marks.local,
            marks.mask,
        )
        .table_id(table)
        .execute()
        .await)?;
        // With src_valid_mark set, reverse path validation of a forwarded
        // packet looks up its source with the packet's mark and iif lo
        // (`__fib_validate_source` in net/ipv4/fib_frontend.c). That lookup
        // must skip uta's table, or the local default route makes the source
        // look local and the packet is dropped as a martian.
        let mut goto = with_mark(rule(first, RuleAction::Goto), marks.forward, marks.mask)
            .input_interface("lo");
        goto.message_mut()
            .attributes
            .push(RuleAttribute::Goto(skip));
        added += new(goto.execute().await)?;
    }
    for route in [
        local_default(RouteMessageBuilder::<Ipv4Addr>::new(), table),
        local_default(RouteMessageBuilder::<Ipv6Addr>::new(), table),
    ] {
        added += new(handle.route().add(route).execute().await)?;
    }
    Ok(added)
}

/// 1 if an entry was added, 0 if it existed.
fn new(result: Result<(), rtnetlink::Error>) -> Result<usize, rtnetlink::Error> {
    match result {
        Ok(()) => Ok(1),
        Err(rtnetlink::Error::NetlinkError(error))
            if error.raw_code() == -(Errno::EEXIST as i32) =>
        {
            Ok(0)
        }
        Err(error) => Err(error),
    }
}

/// What of the rules and routes `install` adds is not in the kernel.
pub async fn missing(handle: &Handle, kernel: &Kernel) -> Result<Vec<String>> {
    let first = kernel.rule_priority;
    let mut missing = Vec::new();
    for (version, name) in [(IpVersion::V4, "IPv4"), (IpVersion::V6, "IPv6")] {
        let rules: Vec<_> = handle.rule().get(version).execute().try_collect().await?;
        let priorities: Vec<u32> = rules
            .iter()
            .filter(|rule| rule.attributes.contains(&RuleAttribute::Protocol(PROTOCOL)))
            .filter_map(|rule| {
                rule.attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RuleAttribute::Priority(priority) => Some(*priority),
                        _ => None,
                    })
            })
            .collect();
        for priority in first..=first + 3 {
            if !priorities.contains(&priority) {
                missing.push(format!("{name} rule {priority}"));
            }
        }
    }
    for (dump, name) in [
        (RouteMessageBuilder::<Ipv4Addr>::new().build(), "IPv4"),
        (RouteMessageBuilder::<Ipv6Addr>::new().build(), "IPv6"),
    ] {
        let routes: Vec<_> = handle.route().get(dump).execute().try_collect().await?;
        if !routes.iter().any(|route| route.header.protocol == PROTOCOL) {
            missing.push(format!("{name} route in table {}", kernel.route_table));
        }
    }
    Ok(missing)
}

/// Whether `message` reports that one of uta's rules or routes was deleted.
pub fn removes_ours(message: &NetlinkMessage<RouteNetlinkMessage>) -> bool {
    match &message.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRule(rule)) => {
            rule.attributes.contains(&RuleAttribute::Protocol(PROTOCOL))
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route)) => {
            route.header.protocol == PROTOCOL
        }
        _ => false,
    }
}

/// Removes every rule and route with uta's protocol, continuing past failures.
pub async fn remove(handle: &Handle) -> Result<()> {
    let mut errors = Vec::new();
    for version in [IpVersion::V4, IpVersion::V6] {
        let rules: Vec<_> = handle.rule().get(version).execute().try_collect().await?;
        for rule in rules {
            if rule.attributes.contains(&RuleAttribute::Protocol(PROTOCOL))
                && let Err(error) = handle.rule().del(rule).execute().await
            {
                errors.push(format!("delete rule: {error}"));
            }
        }
    }
    // Without strict checking, a route dump covers every table of the family.
    for dump in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let routes: Vec<_> = handle.route().get(dump).execute().try_collect().await?;
        for route in routes {
            if route.header.protocol == PROTOCOL
                && let Err(error) = handle.route().del(route).execute().await
            {
                errors.push(format!("delete route: {error}"));
            }
        }
    }
    if !errors.is_empty() {
        bail!("{}", errors.join("; "));
    }
    Ok(())
}

fn rule(
    handle: &Handle,
    family: AddressFamily,
    priority: u32,
    action: RuleAction,
) -> RuleAddRequest {
    let mut request = handle.rule().add().priority(priority).action(action);
    let message = request.message_mut();
    message.header.family = family;
    message.header.table = RouteHeader::RT_TABLE_UNSPEC;
    message.attributes.push(RuleAttribute::Protocol(PROTOCOL));
    request
}

fn with_mark(mut request: RuleAddRequest, mark: u32, mask: u32) -> RuleAddRequest {
    let attributes = &mut request.message_mut().attributes;
    attributes.push(RuleAttribute::FwMark(mark));
    attributes.push(RuleAttribute::FwMask(mask));
    request
}

fn local_default<T>(builder: RouteMessageBuilder<T>, table: u32) -> RouteMessage {
    builder
        .table_id(table)
        .kind(RouteType::Local)
        .scope(RouteScope::Host)
        .output_interface(LOOPBACK_IFINDEX)
        .protocol(PROTOCOL)
        .build()
}
