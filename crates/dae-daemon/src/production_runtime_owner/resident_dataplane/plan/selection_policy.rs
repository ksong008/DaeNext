use super::*;
pub(super) fn referenced_user_outbounds(config: &Config) -> Vec<String> {
    let mut outbounds = Vec::new();
    for rule in &config.routing.rules {
        push_user_outbound(&mut outbounds, &rule.outbound.name);
    }
    match &config.routing.fallback {
        DynamicFunctionValue::String(name) => push_user_outbound(&mut outbounds, name),
        DynamicFunctionValue::Function(function) => {
            push_user_outbound(&mut outbounds, &function.name)
        }
        DynamicFunctionValue::FunctionList(functions) => {
            for function in functions {
                push_user_outbound(&mut outbounds, &function.name);
            }
        }
        DynamicFunctionValue::Nil => {}
    }
    outbounds
}

pub(super) fn push_user_outbound(outbounds: &mut Vec<String>, name: &str) {
    if matches!(
        name,
        "direct" | "block" | "must_rules" | "logical_or" | "logical_and"
    ) {
        return;
    }
    if !outbounds.iter().any(|seen| seen == name) {
        outbounds.push(name.to_owned());
    }
}

pub(super) fn select_group_nodes(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> Result<GroupNodeSelection, String> {
    let (explicit_name_filter, unresolved_names) =
        unresolved_positive_name_filters(group, node_links);
    let filter_groups = outbound_filter_groups(group);
    let annotations = outbound_filter_annotations(group)?;
    let dialer_set = DialerSet {
        dialers: node_links
            .iter()
            .map(|(tag, link)| Dialer::new(tag.clone(), "").with_link(link.clone()))
            .collect(),
    };
    let matched = dialer_set
        .filter_and_annotate(&filter_groups, &annotations)
        .map_err(|err| format!("resident dataplane group {} filter: {err}", group.name))?;
    if matched.is_empty() {
        return Ok(GroupNodeSelection::NoCandidate {
            explicit_name_filter,
            unresolved_names,
        });
    }
    let mut nodes = Vec::with_capacity(matched.len());
    for (match_index, matched) in matched.into_iter().enumerate() {
        let link = node_links
            .get(&matched.name)
            .ok_or_else(|| {
                format!(
                    "group {} selected missing node {}",
                    group.name, matched.name
                )
            })?
            .clone();
        nodes.push(SelectedGroupNode {
            match_index,
            tag: matched.name,
            link,
            annotation_add_latency_ms: matched.annotation.add_latency_ms,
        });
    }
    Ok(GroupNodeSelection::Selected(nodes))
}

pub(super) fn unresolved_positive_name_filters(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> (bool, Vec<String>) {
    let mut unresolved_names = Vec::<String>::new();
    let mut explicit_name_filter = false;
    for filter in &group.filter {
        for function in filter {
            if function.name != "name" || function.not {
                continue;
            }
            explicit_name_filter = true;
            for param in &function.params {
                if param.key.is_empty() && !node_links.contains_key(&param.val) {
                    unresolved_names.push(param.val.clone());
                }
            }
        }
    }
    (explicit_name_filter, unresolved_names)
}

pub(super) fn outbound_filter_groups(group: &Group) -> Vec<Vec<Filter>> {
    group
        .filter
        .iter()
        .map(|filters| filters.iter().map(outbound_filter).collect())
        .collect()
}

pub(super) fn outbound_filter(function: &Function) -> Filter {
    Filter {
        name: function.name.clone(),
        not: function.not,
        params: function
            .params
            .iter()
            .map(|param| FilterParam::new(param.key.clone(), param.val.clone()))
            .collect(),
    }
}

pub(super) fn outbound_filter_annotations(group: &Group) -> Result<Vec<Annotation>, String> {
    if group.filter.is_empty() {
        return Ok(Vec::new());
    }
    if group.filter_annotation.is_empty() {
        return Ok(vec![Annotation::default(); group.filter.len()]);
    }
    if group.filter_annotation.len() != group.filter.len() {
        return Err(format!(
            "unmatched filter annotation length: {} filters and {} annotations",
            group.filter.len(),
            group.filter_annotation.len()
        ));
    }
    group
        .filter_annotation
        .iter()
        .map(|params| match params {
            Some(params) => annotation_from_params(params),
            None => Ok(Annotation::default()),
        })
        .collect()
}

pub(super) fn annotation_from_params(params: &[Param]) -> Result<Annotation, String> {
    let pairs = params
        .iter()
        .map(|param| (param.key.as_str(), param.val.as_str()))
        .collect::<Vec<_>>();
    Annotation::from_params(&pairs).map_err(|err| err.to_string())
}

pub(super) fn parse_group_policy(
    policy: &DynamicFunctionValue,
) -> Result<ResidentGroupPolicyPlan, String> {
    match policy {
        DynamicFunctionValue::Nil => Ok(ResidentGroupPolicyPlan::Fixed { index: 0 }),
        DynamicFunctionValue::String(value) => parse_group_policy_string(value),
        DynamicFunctionValue::Function(function) => parse_group_policy_function(function),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            parse_group_policy_function(&functions[0])
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "policy should be exact 1 function: got {}",
            functions.len()
        )),
    }
}

pub(super) fn parse_group_policy_string(value: &str) -> Result<ResidentGroupPolicyPlan, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(ResidentGroupPolicyPlan::Fixed { index: 0 });
    }
    if let Some(raw) = value
        .strip_prefix("fixed(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        let index = raw
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid fixed policy index {raw}: {err}"))?;
        return Ok(ResidentGroupPolicyPlan::Fixed { index });
    }
    match value {
        "fixed" => Ok(ResidentGroupPolicyPlan::Fixed { index: 0 }),
        "random" => Ok(ResidentGroupPolicyPlan::Random),
        "min" => Ok(ResidentGroupPolicyPlan::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(ResidentGroupPolicyPlan::MinAverage10),
        "min_moving_avg" => Ok(ResidentGroupPolicyPlan::MinMovingAverage),
        other => Err(format!("unexpected policy: {other}")),
    }
}

pub(super) fn parse_group_policy_function(
    function: &Function,
) -> Result<ResidentGroupPolicyPlan, String> {
    match function.name.as_str() {
        "fixed" => {
            if function.not {
                return Err("policy param does not support not operator: !fixed()".to_owned());
            }
            let Some(param) = function.params.first() else {
                return Ok(ResidentGroupPolicyPlan::Fixed { index: 0 });
            };
            if param.key != "" {
                return Err(r#"invalid "fixed" param format"#.to_owned());
            }
            let index = param
                .val
                .parse::<usize>()
                .map_err(|err| format!(r#"invalid "fixed" param format: {err}"#))?;
            Ok(ResidentGroupPolicyPlan::Fixed { index })
        }
        "random" => Ok(ResidentGroupPolicyPlan::Random),
        "min" => Ok(ResidentGroupPolicyPlan::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(ResidentGroupPolicyPlan::MinAverage10),
        "min_moving_avg" => Ok(ResidentGroupPolicyPlan::MinMovingAverage),
        other => Err(format!("unexpected policy: {other}")),
    }
}
