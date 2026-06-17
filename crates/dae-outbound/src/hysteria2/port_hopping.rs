use crate::error::OutboundError;

use super::link::server_contract;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hysteria2PortHopSchedule {
    pub server: String,
    pub host: String,
    pub port_expr: String,
    pub port_hopping: bool,
    pub normalized_ports: Vec<u16>,
    pub udp_hop_interval_ms: u64,
    pub selected_ports: Vec<u16>,
    pub selected_endpoints: Vec<String>,
    pub scheduler_admitted: bool,
}

pub fn build_port_hop_schedule(
    server: &str,
    udp_hop_interval_ms: u64,
    selection_count: usize,
) -> Result<Hysteria2PortHopSchedule, OutboundError> {
    if selection_count == 0 {
        return Err(bad_port_hopping(
            "Hysteria2 port hopping selection count must be greater than zero",
        ));
    }
    if udp_hop_interval_ms == 0 {
        return Err(bad_port_hopping(
            "Hysteria2 UDP hop interval must be greater than zero",
        ));
    }
    let contract = server_contract(server);
    let normalized_ports = parse_port_union(&contract.port)?;
    let selected_ports = (0..selection_count)
        .map(|index| normalized_ports[index % normalized_ports.len()])
        .collect::<Vec<_>>();
    let selected_endpoints = selected_ports
        .iter()
        .map(|port| format!("{}:{port}", contract.host))
        .collect::<Vec<_>>();
    let scheduler_admitted = contract.port_hopping
        && normalized_ports.len() > 1
        && selected_ports.len() == selection_count
        && selected_ports
            .iter()
            .all(|port| normalized_ports.contains(port));

    Ok(Hysteria2PortHopSchedule {
        server: contract.server,
        host: contract.host,
        port_expr: contract.port,
        port_hopping: contract.port_hopping,
        normalized_ports,
        udp_hop_interval_ms,
        selected_ports,
        selected_endpoints,
        scheduler_admitted,
    })
}

pub fn parse_port_union(port_expr: &str) -> Result<Vec<u16>, OutboundError> {
    let mut ranges = Vec::<(u16, u16)>::new();
    for part in port_expr.split(',') {
        if part.is_empty() {
            return Err(bad_port_hopping(format!(
                "invalid empty Hysteria2 port segment in {port_expr}"
            )));
        }
        if let Some((start, end)) = part.split_once('-') {
            let mut start = parse_port(start, port_expr)?;
            let mut end = parse_port(end, port_expr)?;
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            ranges.push((start, end));
        } else {
            let port = parse_port(part, port_expr)?;
            ranges.push((port, port));
        }
    }
    if ranges.is_empty() {
        return Err(bad_port_hopping(format!(
            "invalid Hysteria2 port union: {port_expr}"
        )));
    }
    ranges.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut normalized = Vec::<(u16, u16)>::new();
    for (start, end) in ranges {
        if let Some(last) = normalized.last_mut()
            && u32::from(start) <= u32::from(last.1) + 1
        {
            if end > last.1 {
                last.1 = end;
            }
            continue;
        }
        normalized.push((start, end));
    }
    let mut ports = Vec::new();
    for (start, end) in normalized {
        for port in start..=end {
            ports.push(port);
        }
    }
    Ok(ports)
}

fn parse_port(input: &str, port_expr: &str) -> Result<u16, OutboundError> {
    input
        .parse::<u16>()
        .map_err(|_| bad_port_hopping(format!("{port_expr} is not a valid port number or range")))
}

fn bad_port_hopping(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
