use super::*;
pub(super) fn optimize_routing_rules(
    rules: &[RoutingRule],
    resolver: &GeodataResolver,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<Vec<RoutingRule>, String> {
    let mut rules = rules.to_vec();
    for rule in &mut rules {
        for function in &mut rule.and_functions {
            *function = aliased_function(function);
            expand_function_params(function, resolver, geodata_report)?;
        }
        rule.and_functions
            .sort_by(|left, right| left.name.cmp(&right.name));
    }

    let mut merged: Vec<RoutingRule> = Vec::new();
    for rule in rules {
        if let Some(last) = merged.last_mut()
            && can_merge_singleton_rule(last, &rule)
        {
            last.and_functions[0]
                .params
                .extend(rule.and_functions[0].params.clone());
            continue;
        }
        merged.push(rule);
    }

    for rule in &mut merged {
        for function in &mut rule.and_functions {
            sort_function_params(function);
            deduplicate_function_params(function);
        }
    }

    Ok(merged)
}

pub(super) fn expand_function_params(
    function: &mut Function,
    resolver: &GeodataResolver,
    geodata_report: &mut GeodataResolutionReport,
) -> Result<(), String> {
    let mut expanded = Vec::new();
    for param in &function.params {
        match param.key.as_str() {
            "geosite" => {
                expanded.extend(load_geosite_params(
                    resolver,
                    "geosite",
                    &param.val,
                    geodata_report,
                )?);
            }
            "geoip" => {
                expanded.extend(load_geoip_params(
                    resolver,
                    "geoip",
                    &param.val,
                    geodata_report,
                )?);
            }
            "ext" => {
                let (filename, code) = param
                    .val
                    .split_once(':')
                    .ok_or_else(|| format!("ext parameter must be file:code, got {}", param.val))?;
                match function.name.as_str() {
                    "domain" | "qname" => {
                        expanded.extend(load_geosite_params(
                            resolver,
                            filename,
                            code,
                            geodata_report,
                        )?);
                    }
                    "ip" => {
                        expanded.extend(load_geoip_params(
                            resolver,
                            filename,
                            code,
                            geodata_report,
                        )?);
                    }
                    other => {
                        return Err(format!(
                            "unsupported extension file extraction in function {other}"
                        ));
                    }
                }
            }
            _ => expanded.push(normalize_param(function, param)),
        }
    }
    function.params = expanded;
    Ok(())
}

pub(super) fn normalize_param(function: &Function, param: &Param) -> Param {
    let mut param = param.clone();
    if function.name == "domain" {
        match param.key.as_str() {
            "" | "domain" => param.key = "suffix".to_owned(),
            "contains" => param.key = "keyword".to_owned(),
            _ => {}
        }
    }
    param
}

pub(super) fn can_merge_singleton_rule(left: &RoutingRule, right: &RoutingRule) -> bool {
    left.and_functions.len() == 1
        && right.and_functions.len() == 1
        && left.and_functions[0].name == right.and_functions[0].name
        && left.and_functions[0].not == right.and_functions[0].not
        && left.outbound == right.outbound
}

pub(super) fn sort_function_params(function: &mut Function) {
    if function.name == "ip" || function.name == "sip" {
        function.params.sort_by(|left, right| {
            let left_version = if left.val.contains(':') { 6 } else { 4 };
            let right_version = if right.val.contains(':') { 6 } else { 4 };
            left_version
                .cmp(&right_version)
                .then_with(|| left.val.cmp(&right.val))
        });
    } else {
        function.params.sort_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then_with(|| left.val.cmp(&right.val))
        });
    }
}

pub(super) fn deduplicate_function_params(function: &mut Function) {
    let mut seen = BTreeMap::<(String, String), ()>::new();
    function.params.retain(|param| {
        seen.insert((param.key.clone(), param.val.clone()), ())
            .is_none()
    });
}
