use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crate::dial::magic_network_bytes;
use crate::route::{RouteLoopResult, RouteRule, route_loop};

pub const OUTBOUND_DIRECT: u8 = 0;
pub const OUTBOUND_BLOCK: u8 = 1;
pub const OUTBOUND_USER_DEFINED_MIN: u8 = 2;
pub const OUTBOUND_USER_DEFINED_MAX: u8 = 0xfb;
pub const OUTBOUND_CONTROL_PLANE_ROUTING: u8 = 0xfd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDialMode {
    Ip,
    Domain,
    DomainPlus,
    DomainPlusPlus,
}

impl TcpDialMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::DomainPlus => "domain+",
            Self::DomainPlusPlus => "domain++",
        }
    }
}

impl FromStr for TcpDialMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ip" => Ok(Self::Ip),
            "domain" => Ok(Self::Domain),
            "domain+" => Ok(Self::DomainPlus),
            "domain++" => Ok(Self::DomainPlusPlus),
            _ => Err(format!("unsupported TCP dial mode: {value}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChooseDialTargetDecision {
    pub requested_mode: TcpDialMode,
    pub effective_mode: TcpDialMode,
    pub outbound: u8,
    pub destination: SocketAddr,
    pub domain: String,
    pub domain_is_real: bool,
    pub dial_target: String,
    pub should_reroute: bool,
    pub dial_ip: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDialTcpPlanInput {
    pub dial_mode: TcpDialMode,
    pub initial_outbound: u8,
    pub destination: SocketAddr,
    pub domain: String,
    pub domain_is_real: bool,
    pub initial_mark: u32,
    pub so_mark_from_dae: u32,
    pub mptcp: bool,
    pub route_rules: Vec<RouteRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDialTcpPlan {
    pub initial_outbound: u8,
    pub final_outbound: u8,
    pub userspace_route_executed: bool,
    pub userspace_route_result: Option<RouteLoopResult>,
    pub first_choose: ChooseDialTargetDecision,
    pub second_choose: Option<ChooseDialTargetDecision>,
    pub final_dial_target: String,
    pub strict_ip_version: bool,
    pub network_type: String,
    pub initial_mark: u32,
    pub final_mark: u32,
    pub mark_defaulted_from_so_mark: bool,
    pub mptcp: bool,
    pub magic_network: Vec<u8>,
}

pub fn outbound_is_reserved(outbound: u8) -> bool {
    !(OUTBOUND_USER_DEFINED_MIN..=OUTBOUND_USER_DEFINED_MAX).contains(&outbound)
}

pub fn choose_dial_target(
    dial_mode: TcpDialMode,
    outbound: u8,
    destination: SocketAddr,
    domain: &str,
    domain_is_real: bool,
) -> ChooseDialTargetDecision {
    let mut effective_mode = TcpDialMode::Ip;
    let mut should_reroute = false;

    if !domain.is_empty() && destination.ip().is_unspecified() {
        effective_mode = TcpDialMode::Domain;
    } else if !outbound_is_reserved(outbound) && !domain.is_empty() {
        match dial_mode {
            TcpDialMode::Ip => {}
            TcpDialMode::Domain if domain_is_real => effective_mode = TcpDialMode::Domain,
            TcpDialMode::Domain => {}
            TcpDialMode::DomainPlus => effective_mode = TcpDialMode::Domain,
            TcpDialMode::DomainPlusPlus => {
                effective_mode = TcpDialMode::Domain;
                should_reroute = true;
            }
        }
    }

    let (dial_target, dial_ip) = match effective_mode {
        TcpDialMode::Ip => (destination.to_string(), true),
        TcpDialMode::Domain | TcpDialMode::DomainPlus | TcpDialMode::DomainPlusPlus => {
            format_domain_target(domain, destination.port())
        }
    };

    ChooseDialTargetDecision {
        requested_mode: dial_mode,
        effective_mode,
        outbound,
        destination,
        domain: domain.to_owned(),
        domain_is_real,
        dial_target,
        should_reroute,
        dial_ip,
    }
}

pub fn route_dial_tcp_plan(input: &RouteDialTcpPlanInput) -> RouteDialTcpPlan {
    let first_choose = choose_dial_target(
        input.dial_mode,
        input.initial_outbound,
        input.destination,
        &input.domain,
        input.domain_is_real,
    );

    let mut outbound = input.initial_outbound;
    let mut mark = input.initial_mark;
    let mut userspace_route_executed = false;
    let mut userspace_route_result = None;

    if first_choose.should_reroute {
        outbound = OUTBOUND_CONTROL_PLANE_ROUTING;
    }
    if outbound == OUTBOUND_CONTROL_PLANE_ROUTING {
        userspace_route_executed = true;
        if let Some(result) = route_loop(&input.route_rules) {
            mark = result.mark;
            outbound = result.outbound;
            userspace_route_result = Some(result);
        }
    }

    let second_choose = if userspace_route_executed {
        Some(choose_dial_target(
            input.dial_mode,
            outbound,
            input.destination,
            &input.domain,
            input.domain_is_real,
        ))
    } else {
        None
    };
    let final_choose = second_choose.as_ref().unwrap_or(&first_choose);
    let final_dial_target = final_choose.dial_target.clone();
    let strict_ip_version = final_choose.dial_ip;
    let mark_defaulted_from_so_mark = mark == 0;
    if mark_defaulted_from_so_mark {
        mark = input.so_mark_from_dae;
    }
    let network_type = if input.destination.is_ipv4() {
        "tcp4"
    } else {
        "tcp6"
    }
    .to_owned();

    RouteDialTcpPlan {
        initial_outbound: input.initial_outbound,
        final_outbound: outbound,
        userspace_route_executed,
        userspace_route_result,
        first_choose,
        second_choose,
        final_dial_target,
        strict_ip_version,
        network_type,
        initial_mark: input.initial_mark,
        final_mark: mark,
        mark_defaulted_from_so_mark,
        mptcp: input.mptcp,
        magic_network: magic_network_bytes("tcp", mark, input.mptcp),
    }
}

fn format_domain_target(domain: &str, port: u16) -> (String, bool) {
    let stripped = domain
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(domain);
    if let Ok(ip) = stripped.parse::<IpAddr>() {
        return (SocketAddr::new(ip, port).to_string(), true);
    }
    if has_explicit_port(domain) {
        return (domain.to_owned(), false);
    }
    (join_host_port(domain, port), false)
}

fn has_explicit_port(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix('[') {
        let Some((_, port)) = rest.rsplit_once("]:") else {
            return false;
        };
        return port.parse::<u16>().is_ok();
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.contains(':') && port.parse::<u16>().is_ok()
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
