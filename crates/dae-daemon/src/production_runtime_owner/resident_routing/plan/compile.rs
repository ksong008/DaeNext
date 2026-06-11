use super::*;
pub(super) fn compile_rule(
    plan: &mut ResidentRoutingPlan,
    groups: &BTreeMap<String, u8>,
    rule: &RoutingRule,
) -> Result<(), String> {
    let outbound = parse_outbound(&rule.outbound, groups)?;
    for (function_index, function) in rule.and_functions.iter().enumerate() {
        let function = aliased_function(function);
        let grouped = grouped_params(&function.params);
        if grouped.is_empty() {
            return Err(format!("function {} has no params", function.name));
        }
        for (group_index, (key, values)) in grouped.iter().enumerate() {
            let outbound = if group_index == grouped.len() - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_AND)
                }
            } else {
                logical_outbound(OutboundIndex::LOGICAL_OR)
            };
            add_function_match_sets(plan, &function, key, values, outbound)?;
        }
    }
    Ok(())
}

pub(super) fn add_function_match_sets(
    plan: &mut ResidentRoutingPlan,
    function: &Function,
    param_key: &str,
    values: &[String],
    outbound: OutboundSpec,
) -> Result<(), String> {
    match function.name.as_str() {
        "domain" => {
            if !matches!(param_key, "full" | "keyword" | "suffix" | "regex") {
                return Err(format!(
                    "unsupported resident domain parameter key: {param_key}"
                ));
            }
            let rule_index = plan.matches.len();
            plan.domain_sets.push(ResidentDomainSet {
                rule_index,
                key: param_key.to_owned(),
                values: values.to_vec(),
            });
            plan.matches.push(match_set(
                [0; 16],
                function.not,
                MATCH_TYPE_DOMAIN_SET,
                outbound,
                "DomainSet",
            ));
            Ok(())
        }
        "ip" | "sip" | "mac" => {
            let lpm_index = plan.lpm_sets.len() as u32;
            let prefixes = match function.name.as_str() {
                "mac" => values
                    .iter()
                    .map(|value| parse_mac_prefix(value))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => parse_ip_prefix_group(param_key, values)?,
            };
            plan.lpm_sets.push(prefixes);
            let mut raw = [0_u8; 16];
            raw[..4].copy_from_slice(&lpm_index.to_le_bytes());
            let kind = match function.name.as_str() {
                "sip" => (MATCH_TYPE_SOURCE_IP_SET, "SourceIpSet"),
                "mac" => (MATCH_TYPE_MAC, "Mac"),
                _ => (MATCH_TYPE_IP_SET, "IpSet"),
            };
            plan.matches
                .push(match_set(raw, function.not, kind.0, outbound, kind.1));
            Ok(())
        }
        "port" | "sport" => {
            let ranges = values
                .iter()
                .map(|value| parse_port_range(value))
                .collect::<Result<Vec<_>, _>>()?;
            let kind = if function.name == "sport" {
                (MATCH_TYPE_SOURCE_PORT, "SourcePort")
            } else {
                (MATCH_TYPE_PORT, "Port")
            };
            for (index, (start, end)) in ranges.into_iter().enumerate() {
                let outbound = if index == values.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_OR)
                };
                let mut raw = [0_u8; 16];
                raw[..2].copy_from_slice(&start.to_le_bytes());
                raw[2..4].copy_from_slice(&end.to_le_bytes());
                plan.matches
                    .push(match_set(raw, function.not, kind.0, outbound, kind.1));
            }
            Ok(())
        }
        "l4proto" => {
            let mut raw = [0_u8; 16];
            raw[0] = parse_l4_proto(values)?;
            plan.matches.push(match_set(
                raw,
                function.not,
                MATCH_TYPE_L4_PROTO,
                outbound,
                "L4Proto",
            ));
            Ok(())
        }
        "ipversion" => {
            let mut raw = [0_u8; 16];
            raw[0] = parse_ip_version(values)?;
            plan.matches.push(match_set(
                raw,
                function.not,
                MATCH_TYPE_IP_VERSION,
                outbound,
                "IpVersion",
            ));
            Ok(())
        }
        "pname" => {
            for (index, value) in values.iter().enumerate() {
                let outbound = if index == values.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_OR)
                };
                let mut raw = [0_u8; 16];
                let name = value.as_bytes();
                let copy_len = name.len().min(raw.len());
                raw[..copy_len].copy_from_slice(&name[..copy_len]);
                plan.matches.push(match_set(
                    raw,
                    function.not,
                    MATCH_TYPE_PROCESS_NAME,
                    outbound,
                    "ProcessName",
                ));
            }
            Ok(())
        }
        "dscp" => {
            for (index, value) in values.iter().enumerate() {
                let outbound = if index == values.len() - 1 {
                    outbound.clone()
                } else {
                    logical_outbound(OutboundIndex::LOGICAL_OR)
                };
                let mut raw = [0_u8; 16];
                raw[0] = value
                    .parse::<u8>()
                    .map_err(|err| format!("invalid dscp {value}: {err}"))?;
                plan.matches.push(match_set(
                    raw,
                    function.not,
                    MATCH_TYPE_DSCP,
                    outbound,
                    "Dscp",
                ));
            }
            Ok(())
        }
        other => Err(format!("unsupported resident routing function: {other}")),
    }
}
