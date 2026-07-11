use super::*;
use crate::production_runtime_owner::resident_dataplane::ResidentRuntimeResourceConfig;

mod actions;
mod qtype;
mod upstream_parse;

use actions::{
    dynamic_to_optional_single_function, parse_request_action_function,
    parse_response_action_function, request_action_from_index, request_index_for_dynamic,
    request_index_for_function, response_action_from_index, response_index_for_dynamic,
    response_index_for_function,
};
use qtype::{grouped_params, parse_dns_qtype};
#[cfg(test)]
pub(super) use upstream_parse::parse_dns_upstream;
use upstream_parse::split_keyable_link;
use upstream_parse::{parse_dns_fallback_resolver, parse_dns_upstream_with_refresh_interval};

pub(super) fn parse_dns_upstreams(config: &Config) -> Result<ResidentDnsUpstreams, String> {
    let fallback_resolver = parse_dns_fallback_resolver(config)?;
    let resolver_mark = effective_so_mark_from_dae(config.global.so_mark_from_dae);
    let refresh_interval =
        ResidentRuntimeResourceConfig::from_config(config).dns_upstream_refresh_interval();
    let mut by_tag = BTreeMap::new();
    let mut tag_to_index = BTreeMap::new();
    let mut request_actions = Vec::new();
    let mut response_actions = Vec::new();
    for (index, raw) in config.dns.upstream.iter().enumerate() {
        if index >= DnsRequestOutboundIndex::REJECT.value() as usize {
            return Err("too many DNS upstreams for resident request routing".to_owned());
        }
        let (tag, link) = split_keyable_link(raw);
        let Some(tag) = tag else {
            return Err(format!("bad DNS upstream format: {raw:?} has no tag"));
        };
        if by_tag.contains_key(&tag) {
            return Err(format!("duplicated DNS upstream tag {tag:?}"));
        }
        let upstream = parse_dns_upstream_with_refresh_interval(
            index as u8,
            &tag,
            &link,
            fallback_resolver,
            resolver_mark,
            refresh_interval,
        )?;
        tag_to_index.insert(tag.clone(), index as u8);
        request_actions.push(ResidentDnsRequestAction::Upstream(upstream.clone()));
        response_actions.push(ResidentDnsResponseAction::Upstream(upstream.clone()));
        by_tag.insert(tag, upstream);
    }
    Ok(ResidentDnsUpstreams {
        by_tag,
        tag_to_index,
        request_actions,
        response_actions,
    })
}

pub(super) fn parse_request_default_action(
    default_action: &DynamicFunctionValue,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
) -> Result<ResidentDnsRequestAction, String> {
    let Some(function) = dynamic_to_optional_single_function(default_action)? else {
        return Ok(ResidentDnsRequestAction::AsIs);
    };
    parse_request_action_function(&function, upstreams, "dns.routing.request default action")
}

pub(super) fn build_request_matcher(
    config: &Config,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<Option<RequestMatcher>, String> {
    if config.dns.routing.request.rules.is_empty() {
        return Ok(None);
    }

    let rules = expand_resident_dns_request_qname_rules_with_resolver(
        &config.dns.routing.request.rules,
        geodata,
    )
    .map_err(|err| format!("expand dns.routing.request geodata: {err}"))?;
    let mut domain_sets = Vec::new();
    let mut matches = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        compile_request_rule(&mut domain_sets, &mut matches, rule, upstreams, geodata).map_err(
            |err| {
                format!(
                    "dns.routing.request rule {index} failed: {err}; rule={}",
                    rule.to_config_string(false, false, true)
                )
            },
        )?;
    }
    let fallback = request_index_for_dynamic(
        &config.dns.routing.request.fallback,
        upstreams,
        "dns.routing.request fallback",
    )?;
    matches.push(DnsRequestMatchSpec {
        kind: DnsRequestMatchKind::Fallback,
        value: 0,
        not: false,
        upstream: fallback,
    });
    let matcher = RequestMatcher::from_shared_typed_sets(domain_sets, matches)
        .map_err(|err| format!("build resident DNS request matcher: {err}"))?;
    Ok(Some(matcher))
}

pub(super) fn parse_response_default_action(
    default_action: &DynamicFunctionValue,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
) -> Result<ResidentDnsResponseAction, String> {
    let Some(function) = dynamic_to_optional_single_function(default_action)? else {
        return Ok(ResidentDnsResponseAction::Accept);
    };
    parse_response_action_function(&function, upstreams, "dns.routing.response default action")
}

pub(super) fn build_response_matcher(
    config: &Config,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<Option<ResponseMatcher>, String> {
    if config.dns.routing.response.rules.is_empty() {
        return Ok(None);
    }

    let rules = expand_resident_dns_response_qname_rules_with_resolver(
        &config.dns.routing.response.rules,
        geodata,
    )
    .map_err(|err| format!("expand dns.routing.response geodata: {err}"))?;
    let mut domain_sets = Vec::new();
    let mut lpm_sets = Vec::new();
    let mut matches = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        compile_response_rule(
            &mut domain_sets,
            &mut lpm_sets,
            &mut matches,
            rule,
            upstreams,
            geodata,
        )
        .map_err(|err| {
            format!(
                "dns.routing.response rule {index} failed: {err}; rule={}",
                rule.to_config_string(false, false, true)
            )
        })?;
    }
    let fallback = response_index_for_dynamic(
        &config.dns.routing.response.fallback,
        upstreams,
        "dns.routing.response fallback",
    )?;
    matches.push(DnsResponseMatchSpec {
        kind: DnsResponseMatchKind::Fallback,
        value: 0,
        not: false,
        upstream: fallback,
    });
    let matcher = ResponseMatcher::from_shared_typed_sets(domain_sets, lpm_sets, matches)
        .map_err(|err| format!("build resident DNS response matcher: {err}"))?;
    Ok(Some(matcher))
}

fn compile_request_rule(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsRequestMatchSpec>,
    rule: &RoutingRule,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<(), String> {
    if rule.and_functions.is_empty() {
        return Err("request rule has no functions".to_owned());
    }
    let rule_upstream =
        request_index_for_function(&rule.outbound, upstreams, "dns.routing.request rule action")?;
    for (function_index, function) in rule.and_functions.iter().enumerate() {
        let grouped = grouped_params(&function.params);
        if grouped.is_empty() {
            return Err(format!("function {} has no params", function.name));
        }
        let group_count = grouped.len();
        for (group_index, (key, values)) in grouped.into_iter().enumerate() {
            if values.is_empty() {
                return Err(format!("function {} has empty param group", function.name));
            }
            let upstream = if group_index == group_count - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    rule_upstream
                } else {
                    DnsRequestOutboundIndex::LOGICAL_AND
                }
            } else {
                DnsRequestOutboundIndex::LOGICAL_OR
            };
            match function.name.as_str() {
                "qname" => add_request_qname_match(
                    domain_sets,
                    matches,
                    geodata,
                    function,
                    &key,
                    values,
                    upstream,
                )?,
                "qtype" => add_request_qtype_matches(matches, function, &values, upstream)?,
                other => {
                    return Err(format!(
                        "unsupported dns.routing.request function: {other}; resident DNS request routing admits qname and qtype only"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn compile_response_rule(
    domain_sets: &mut Vec<DnsDomainSet>,
    lpm_sets: &mut Vec<Vec<IpPrefix>>,
    matches: &mut Vec<DnsResponseMatchSpec>,
    rule: &RoutingRule,
    upstreams: &ResidentDnsUpstreams,
    geodata: &ResidentGeodataStore,
) -> Result<(), String> {
    if rule.and_functions.is_empty() {
        return Err("response rule has no functions".to_owned());
    }
    let rule_upstream = response_index_for_function(
        &rule.outbound,
        upstreams,
        "dns.routing.response rule action",
    )?;
    for (function_index, function) in rule.and_functions.iter().enumerate() {
        let grouped = grouped_params(&function.params);
        if grouped.is_empty() {
            return Err(format!("function {} has no params", function.name));
        }
        let group_count = grouped.len();
        for (group_index, (key, values)) in grouped.into_iter().enumerate() {
            if values.is_empty() {
                return Err(format!("function {} has empty param group", function.name));
            }
            let upstream = if group_index == group_count - 1 {
                if function_index == rule.and_functions.len() - 1 {
                    rule_upstream
                } else {
                    DnsResponseOutboundIndex::LOGICAL_AND
                }
            } else {
                DnsResponseOutboundIndex::LOGICAL_OR
            };
            match function.name.as_str() {
                "qname" => add_response_qname_match(
                    domain_sets,
                    matches,
                    geodata,
                    function,
                    &key,
                    values,
                    upstream,
                )?,
                "qtype" => add_response_qtype_matches(matches, function, &values, upstream)?,
                "upstream" => {
                    add_response_upstream_matches(matches, upstreams, function, &values, upstream)?
                }
                "ip" => add_response_ip_match(
                    lpm_sets, matches, geodata, function, &key, values, upstream,
                )?,
                other => {
                    return Err(format!(
                        "unsupported dns.routing.response function: {other}; resident DNS response routing admits qname, qtype, upstream, and ip"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn add_request_qname_match(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsRequestMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    mut values: Vec<String>,
    upstream: DnsRequestOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "full" | "keyword" | "suffix" | "regex") {
        return Err(format!("qname has unsupported domain key: {key}"));
    }
    let bit = matches.len();
    values.sort();
    values.dedup();
    let patterns = geodata.shared_domain_set(key, values)?;
    domain_sets.push(DnsDomainSet { bit, patterns });
    matches.push(DnsRequestMatchSpec {
        kind: DnsRequestMatchKind::DomainSet,
        value: 0,
        not: function.not,
        upstream,
    });
    Ok(())
}

fn add_request_qtype_matches(
    matches: &mut Vec<DnsRequestMatchSpec>,
    function: &Function,
    values: &[String],
    upstream: DnsRequestOutboundIndex,
) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        let item_upstream = if index == values.len() - 1 {
            upstream
        } else {
            DnsRequestOutboundIndex::LOGICAL_OR
        };
        matches.push(DnsRequestMatchSpec {
            kind: DnsRequestMatchKind::QType,
            value: parse_dns_qtype(value)?,
            not: function.not,
            upstream: item_upstream,
        });
    }
    Ok(())
}

fn add_response_qname_match(
    domain_sets: &mut Vec<DnsDomainSet>,
    matches: &mut Vec<DnsResponseMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    mut values: Vec<String>,
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "full" | "keyword" | "suffix" | "regex") {
        return Err(format!("qname has unsupported domain key: {key}"));
    }
    let bit = matches.len();
    values.sort();
    values.dedup();
    let patterns = geodata.shared_domain_set(key, values)?;
    domain_sets.push(DnsDomainSet { bit, patterns });
    matches.push(DnsResponseMatchSpec {
        kind: DnsResponseMatchKind::DomainSet,
        value: 0,
        not: function.not,
        upstream,
    });
    Ok(())
}

fn add_response_qtype_matches(
    matches: &mut Vec<DnsResponseMatchSpec>,
    function: &Function,
    values: &[String],
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        let item_upstream = if index == values.len() - 1 {
            upstream
        } else {
            DnsResponseOutboundIndex::LOGICAL_OR
        };
        matches.push(DnsResponseMatchSpec {
            kind: DnsResponseMatchKind::QType,
            value: parse_dns_qtype(value)?,
            not: function.not,
            upstream: item_upstream,
        });
    }
    Ok(())
}

fn add_response_upstream_matches(
    matches: &mut Vec<DnsResponseMatchSpec>,
    upstreams: &ResidentDnsUpstreams,
    function: &Function,
    values: &[String],
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        let item_upstream = if index == values.len() - 1 {
            upstream
        } else {
            DnsResponseOutboundIndex::LOGICAL_OR
        };
        let value = match value.as_str() {
            "asis" => DnsRequestOutboundIndex::ASIS.value() as u16,
            tag => upstreams
                .tag_to_index
                .get(tag)
                .copied()
                .map(u16::from)
                .ok_or_else(|| {
                    format!("dns.routing.response upstream references unknown upstream {tag:?}")
                })?,
        };
        matches.push(DnsResponseMatchSpec {
            kind: DnsResponseMatchKind::Upstream,
            value,
            not: function.not,
            upstream: item_upstream,
        });
    }
    Ok(())
}

fn add_response_ip_match(
    lpm_sets: &mut Vec<Vec<IpPrefix>>,
    matches: &mut Vec<DnsResponseMatchSpec>,
    geodata: &ResidentGeodataStore,
    function: &Function,
    key: &str,
    values: Vec<String>,
    upstream: DnsResponseOutboundIndex,
) -> Result<(), String> {
    if !matches!(key, "" | "geoip" | "ext") {
        return Err(format!("ip has unsupported key: {key}"));
    }
    let params = values
        .into_iter()
        .map(|val| Param {
            key: key.to_owned(),
            val,
            ..Param::default()
        })
        .collect::<Vec<_>>();
    let expanded = expand_resident_dns_response_ip_params_with_resolver(&params, geodata)?;
    let mut prefixes = Vec::with_capacity(expanded.len());
    for param in expanded {
        prefixes.push(parse_response_ip_prefix(&param.val)?);
    }
    let index = lpm_sets.len();
    lpm_sets.push(prefixes);
    matches.push(DnsResponseMatchSpec {
        kind: DnsResponseMatchKind::IpSet,
        value: index as u16,
        not: function.not,
        upstream,
    });
    Ok(())
}

fn parse_response_ip_prefix(value: &str) -> Result<IpPrefix, String> {
    if value.contains('/') {
        return IpPrefix::parse(value).map_err(|err| err.to_string());
    }
    let ip = value
        .parse::<IpAddr>()
        .map_err(|err| format!("parse DNS response ip matcher {value:?}: {err}"))?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    IpPrefix::new(ip, bits).map_err(|err| err.to_string())
}

pub(super) fn select_request_action(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
) -> Result<ResidentDnsRequestAction, String> {
    let Some(matcher) = &plan.request_matcher else {
        return Ok(plan.request_default_action.clone());
    };
    let question = request
        .questions()
        .next()
        .ok_or_else(|| "DNS request has no question".to_owned())?;
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS request qname: {err}"))?;
    let outbound = matcher
        .match_request(&qname, question.qtype())
        .map_err(|err| format!("match dns.routing.request: {err}"))?;
    request_action_from_index(plan, outbound)
}

pub(super) fn select_response_action(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
    response_payload: &[u8],
    upstream: &ResidentDnsUpstream,
) -> Result<ResidentDnsResponseAction, String> {
    select_response_action_for_upstream(
        plan,
        request,
        response_payload,
        DnsRequestOutboundIndex(upstream.index),
    )
}

pub(super) fn select_response_action_for_upstream(
    plan: &ResidentDnsPlan,
    request: &DnsPacketView<'_>,
    response_payload: &[u8],
    upstream: DnsRequestOutboundIndex,
) -> Result<ResidentDnsResponseAction, String> {
    let Some(matcher) = &plan.response_matcher else {
        return Ok(plan.response_default_action.clone());
    };
    let response = DnsPacketView::parse(response_payload)
        .map_err(|err| format!("parse DNS response: {err}"))?;
    if !response.response() {
        return Err("DNS response expected but DNS request received".to_owned());
    }
    let question = request
        .questions()
        .next()
        .ok_or_else(|| "DNS request has no question".to_owned())?;
    let qname = question
        .qname_to_canonical_string()
        .map_err(|err| format!("read DNS response routing qname: {err}"))?;
    let mut ips = Vec::new();
    for answer in response.answers() {
        let answer = answer.map_err(|err| format!("read DNS response answer: {err}"))?;
        if let Some(ip) = answer.ip() {
            ips.push(ip);
        }
    }
    let outbound = matcher
        .match_response(&qname, question.qtype(), &ips, upstream)
        .map_err(|err| format!("match dns.routing.response: {err}"))?;
    response_action_from_index(plan, outbound)
}
