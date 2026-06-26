use super::*;

pub(super) fn parse_dns_upstreams(config: &Config) -> Result<ResidentDnsUpstreams, String> {
    let fallback_resolver = parse_dns_fallback_resolver(config)?;
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
        let upstream = parse_dns_upstream(
            index as u8,
            &tag,
            &link,
            fallback_resolver,
            config.global.so_mark_from_dae,
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

fn request_action_from_index(
    plan: &ResidentDnsPlan,
    outbound: DnsRequestOutboundIndex,
) -> Result<ResidentDnsRequestAction, String> {
    if outbound == DnsRequestOutboundIndex::ASIS {
        return Ok(ResidentDnsRequestAction::AsIs);
    }
    if outbound == DnsRequestOutboundIndex::REJECT {
        return Ok(ResidentDnsRequestAction::Reject);
    }
    if outbound == DnsRequestOutboundIndex::LOGICAL_OR
        || outbound == DnsRequestOutboundIndex::LOGICAL_AND
    {
        return Err(format!(
            "dns.routing.request returned internal logical outbound {outbound}"
        ));
    }
    plan.request_actions
        .get(outbound.value() as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "dns.routing.request selected unknown upstream index {}",
                outbound.value()
            )
        })
}

fn request_index_for_dynamic(
    value: &DynamicFunctionValue,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsRequestOutboundIndex, String> {
    let Some(function) = dynamic_to_optional_single_function(value)? else {
        return Ok(DnsRequestOutboundIndex::ASIS);
    };
    request_index_for_function(&function, upstreams, context)
}

fn request_index_for_function(
    function: &Function,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsRequestOutboundIndex, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "asis" => Ok(DnsRequestOutboundIndex::ASIS),
        "reject" => Ok(DnsRequestOutboundIndex::REJECT),
        tag => upstreams
            .tag_to_index
            .get(tag)
            .copied()
            .map(DnsRequestOutboundIndex)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn response_index_for_dynamic(
    value: &DynamicFunctionValue,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsResponseOutboundIndex, String> {
    let Some(function) = dynamic_to_optional_single_function(value)? else {
        return Ok(DnsResponseOutboundIndex::ACCEPT);
    };
    response_index_for_function(&function, upstreams, context)
}

fn response_index_for_function(
    function: &Function,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsResponseOutboundIndex, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "accept" => Ok(DnsResponseOutboundIndex::ACCEPT),
        "reject" => Ok(DnsResponseOutboundIndex::REJECT),
        tag => upstreams
            .tag_to_index
            .get(tag)
            .copied()
            .map(DnsResponseOutboundIndex)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn parse_request_action_function(
    function: &Function,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
    context: &str,
) -> Result<ResidentDnsRequestAction, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "asis" => Ok(ResidentDnsRequestAction::AsIs),
        "reject" => Ok(ResidentDnsRequestAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsRequestAction::Upstream)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn parse_response_action_function(
    function: &Function,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
    context: &str,
) -> Result<ResidentDnsResponseAction, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "accept" => Ok(ResidentDnsResponseAction::Accept),
        "reject" => Ok(ResidentDnsResponseAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsResponseAction::Upstream)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

fn response_action_from_index(
    plan: &ResidentDnsPlan,
    outbound: DnsResponseOutboundIndex,
) -> Result<ResidentDnsResponseAction, String> {
    if outbound == DnsResponseOutboundIndex::ACCEPT {
        return Ok(ResidentDnsResponseAction::Accept);
    }
    if outbound == DnsResponseOutboundIndex::REJECT {
        return Ok(ResidentDnsResponseAction::Reject);
    }
    if outbound == DnsResponseOutboundIndex::LOGICAL_OR
        || outbound == DnsResponseOutboundIndex::LOGICAL_AND
    {
        return Err(format!(
            "dns.routing.response returned internal logical outbound {outbound}"
        ));
    }
    plan.response_actions
        .get(outbound.value() as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "dns.routing.response selected unknown upstream index {}",
                outbound.value()
            )
        })
}

fn dynamic_to_optional_single_function(
    value: &DynamicFunctionValue,
) -> Result<Option<Function>, String> {
    match value {
        DynamicFunctionValue::Nil => Ok(None),
        DynamicFunctionValue::String(name) => Ok(Some(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        })),
        DynamicFunctionValue::Function(function) => Ok(Some(function.clone())),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(Some(functions[0].clone()))
        }
        DynamicFunctionValue::FunctionList(_) => {
            Err("default action function list is not admitted".to_owned())
        }
    }
}

fn grouped_params(params: &[Param]) -> Vec<(String, Vec<String>)> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for param in params {
        if !groups.contains_key(&param.key) {
            order.push(param.key.clone());
        }
        groups
            .entry(param.key.clone())
            .or_default()
            .push(param.val.clone());
    }
    order
        .into_iter()
        .map(|key| {
            let values = groups.remove(&key).unwrap_or_default();
            (key, values)
        })
        .collect()
}

fn parse_dns_qtype(value: &str) -> Result<u16, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u16::from_str_radix(hex, 16)
            .map_err(|err| format!("invalid DNS qtype {value}: {err}"));
    }
    if let Ok(parsed) = value.parse::<u16>() {
        return Ok(parsed);
    }
    dns_qtype_name(value).ok_or_else(|| format!("unknown DNS qtype: {value}"))
}

fn dns_qtype_name(value: &str) -> Option<u16> {
    Some(match value.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP" => 22,
        "NSAPPTR" | "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "DOA" => 259,
        "AMTRELAY" => 260,
        "TA" => 32768,
        "DLV" => 32769,
        _ => return None,
    })
}

pub(super) fn parse_dns_fallback_resolver(config: &Config) -> Result<SocketAddr, String> {
    config
        .global
        .fallback_resolver
        .parse::<SocketAddr>()
        .map_err(|err| {
            format!(
                "invalid global.fallback_resolver {:?}: {err}",
                config.global.fallback_resolver
            )
        })
}

pub(super) fn parse_dns_upstream(
    index: u8,
    tag: &str,
    link: &str,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
) -> Result<ResidentDnsUpstream, String> {
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| format!("DNS upstream {tag} has no scheme: {link}"))?;
    let scheme = match scheme {
        "udp" => ResidentDnsUpstreamScheme::Udp,
        "tcp" => ResidentDnsUpstreamScheme::Tcp,
        "tcp+udp" | "udp+tcp" => ResidentDnsUpstreamScheme::TcpUdp,
        "tls" => ResidentDnsUpstreamScheme::Tls,
        "https" => ResidentDnsUpstreamScheme::Https,
        "quic" => ResidentDnsUpstreamScheme::Quic,
        "h3" | "http3" => ResidentDnsUpstreamScheme::Http3,
        other => {
            return Err(format!(
                "resident DNS upstream {tag} uses unsupported scheme {other}; resident DNS upstream shape remains fail-closed until this scheme is admitted"
            ));
        }
    };
    let (authority, path) = split_dns_upstream_authority_and_path(rest, scheme);
    let target = parse_dns_upstream_authority(
        authority,
        scheme.default_port(),
        fallback_resolver,
        resolver_mark,
    )?;
    Ok(ResidentDnsUpstream {
        index,
        tag: tag.to_owned(),
        target,
        scheme,
        path,
    })
}

impl ResidentDnsUpstreamScheme {
    const fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp | Self::TcpUdp => DNS_DEFAULT_PORT,
            Self::Tls | Self::Quic => DNS_TLS_DEFAULT_PORT,
            Self::Https | Self::Http3 => DNS_HTTPS_DEFAULT_PORT,
        }
    }

    const fn default_path(self) -> &'static str {
        match self {
            Self::Https | Self::Http3 => DNS_DEFAULT_DOH_PATH,
            Self::Udp | Self::Tcp | Self::TcpUdp | Self::Tls | Self::Quic => "",
        }
    }
}

fn split_dns_upstream_authority_and_path(
    rest: &str,
    scheme: ResidentDnsUpstreamScheme,
) -> (&str, String) {
    match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].to_owned()),
        None => (rest, scheme.default_path().to_owned()),
    }
}

fn parse_dns_upstream_authority(
    authority: &str,
    default_port: u16,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
) -> Result<ResidentDnsUpstreamTarget, String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("DNS upstream authority is empty".to_owned());
    }
    let (authority, host, port, literal_addr) =
        dns_upstream_authority_with_default_port(authority, default_port)?;
    Ok(ResidentDnsUpstreamTarget {
        authority,
        host,
        port,
        literal_addr,
        fallback_resolver,
        resolver_mark,
        resolved_addr: Arc::new(OnceCell::new()),
    })
}

fn dns_upstream_authority_with_default_port(
    authority: &str,
    default_port: u16,
) -> Result<(String, String, u16, Option<SocketAddr>), String> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok((
            addr.to_string(),
            addr.ip().to_string(),
            addr.port(),
            Some(addr),
        ));
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, default_port);
        return Ok((addr.to_string(), ip.to_string(), default_port, Some(addr)));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(format!(
                "DNS upstream {authority} has malformed IPv6 authority"
            ));
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|err| format!("DNS upstream {authority} has invalid port: {err}"))?,
            None if tail.is_empty() => default_port,
            None => {
                return Err(format!(
                    "DNS upstream {authority} has unexpected text after bracketed host"
                ));
            }
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, port);
            return Ok((addr.to_string(), ip.to_string(), port, Some(addr)));
        }
        return Ok((format!("[{host}]:{port}"), host.to_owned(), port, None));
    }
    if authority.matches(':').count() > 1 {
        return Err(format!(
            "DNS upstream {authority} is an IPv6 literal and must be bracketed when a port is supplied"
        ));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|err| format!("DNS upstream {authority} has invalid port: {err}"))?;
        return Ok((authority.to_owned(), host.to_owned(), port, None));
    }
    Ok((
        format!("{authority}:{default_port}"),
        authority.to_owned(),
        default_port,
        None,
    ))
}

fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}
