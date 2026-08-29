use super::parse::ParsedDaeFile;
use super::*;
use dae_config::marshal::{marshal_dns_section, marshal_global_section, marshal_routing_section};
use dae_config::{DynamicFunctionValue, Item};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StagedDaeFile {
    pub(super) global: String,
    pub(super) dns: String,
    pub(super) routing: String,
    pub(super) nodes: Vec<StagedDaeNode>,
    pub(super) groups: Vec<StagedDaeGroup>,
    pub(super) warnings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StagedDaeNode {
    pub(super) tag: String,
    pub(super) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StagedDaeGroup {
    pub(super) name: String,
    pub(super) policy: String,
    pub(super) policy_params: Vec<(String, String)>,
    pub(super) node_tags: Vec<String>,
}

pub(super) fn stage_dae_file(parsed: ParsedDaeFile) -> io::Result<StagedDaeFile> {
    let nodes = stage_nodes(&parsed)?;
    let node_tags = nodes
        .iter()
        .map(|node| node.tag.as_str())
        .collect::<HashSet<_>>();
    let groups = parsed
        .config
        .group
        .iter()
        .map(|group| stage_group(group, &node_tags))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(StagedDaeFile {
        global: marshal_global_section(&parsed.config.global, 4)
            .map_err(|err| invalid_dae_file(format!("marshal global section: {err}")))?,
        dns: marshal_dns_section(&parsed.config.dns, 4)
            .map_err(|err| invalid_dae_file(format!("marshal dns section: {err}")))?,
        routing: marshal_routing_section(&parsed.config.routing, 4)
            .map_err(|err| invalid_dae_file(format!("marshal routing section: {err}")))?,
        nodes,
        groups,
        warnings: Vec::new(),
    })
}

fn stage_nodes(parsed: &ParsedDaeFile) -> io::Result<Vec<StagedDaeNode>> {
    let Some(section) = parsed
        .sections
        .iter()
        .find(|section| section.name == "node")
    else {
        return Ok(Vec::new());
    };
    let mut seen = HashSet::new();
    let mut nodes = Vec::with_capacity(section.items.len());
    for item in &section.items {
        let Item::Param(param) = item else {
            return Err(invalid_dae_file(format!(
                "node section contains unsupported {:?} item",
                item.kind()
            )));
        };
        let tag = param.key.trim();
        let link = param.val.trim();
        if tag.is_empty() || link.is_empty() || !param.and_functions.is_empty() {
            return Err(invalid_dae_file(
                "every imported node must have one non-empty tag and link",
            ));
        }
        if !seen.insert(tag.to_owned()) {
            return Err(invalid_dae_file(format!(
                "duplicate node tag {tag:?} is ambiguous"
            )));
        }
        let parsed_link = parse_node_link(link, Some(tag));
        if parsed_link.protocol.trim().is_empty() || parsed_link.address.trim().is_empty() {
            return Err(invalid_dae_file(format!(
                "node {tag:?} has an unsupported or incomplete link"
            )));
        }
        nodes.push(StagedDaeNode {
            tag: tag.to_owned(),
            link: link.to_owned(),
        });
    }
    Ok(nodes)
}

fn stage_group(
    group: &dae_config::Group,
    imported_node_tags: &HashSet<&str>,
) -> io::Result<StagedDaeGroup> {
    reject_unrepresentable_group_options(group)?;
    let (policy, policy_params) = stage_group_policy(&group.policy)?;
    let mut node_tags = Vec::new();
    let mut seen = HashSet::new();
    for filter in &group.filter {
        if filter.len() != 1 || filter[0].not || filter[0].name != "name" {
            return Err(invalid_dae_file(format!(
                "group {:?} uses a filter that cannot be represented by product node bindings",
                group.name
            )));
        }
        for param in &filter[0].params {
            if !param.key.is_empty() || !param.and_functions.is_empty() {
                return Err(invalid_dae_file(format!(
                    "group {:?} has an ambiguous name filter parameter",
                    group.name
                )));
            }
            let tag = param.val.trim();
            if !imported_node_tags.contains(tag) {
                return Err(invalid_dae_file(format!(
                    "group {:?} references node {tag:?} that is not present in the imported node section",
                    group.name
                )));
            }
            if seen.insert(tag.to_owned()) {
                node_tags.push(tag.to_owned());
            }
        }
    }
    if node_tags.is_empty() {
        return Err(invalid_dae_file(format!(
            "group {:?} has no materialized node candidates",
            group.name
        )));
    }
    if policy == GROUP_POLICY_FIXED && node_tags.len() != 1 {
        return Err(invalid_dae_file(format!(
            "fixed group {:?} must resolve to exactly one node; got {}",
            group.name,
            node_tags.len()
        )));
    }
    Ok(StagedDaeGroup {
        name: group.name.clone(),
        policy,
        policy_params,
        node_tags,
    })
}

fn stage_group_policy(
    policy: &DynamicFunctionValue,
) -> io::Result<(String, Vec<(String, String)>)> {
    let (name, params) = match policy {
        DynamicFunctionValue::String(name) => (name.clone(), Vec::new()),
        DynamicFunctionValue::Function(function) if !function.not => (
            function.name.clone(),
            function
                .params
                .iter()
                .map(|param| (param.key.clone(), param.val.clone()))
                .collect(),
        ),
        DynamicFunctionValue::Nil => (DEFAULT_PRODUCT_GROUP_POLICY.to_owned(), Vec::new()),
        DynamicFunctionValue::Function(_) | DynamicFunctionValue::FunctionList(_) => {
            return Err(invalid_dae_file(
                "group policy expression cannot be represented by one product policy",
            ));
        }
    };
    if !SUPPORTED_GROUP_POLICIES.contains(&name.as_str()) {
        return Err(invalid_dae_file(format!(
            "unsupported imported group policy {name:?}; allowed values: {}",
            SUPPORTED_GROUP_POLICIES.join(", ")
        )));
    }
    Ok((name, params))
}

fn reject_unrepresentable_group_options(group: &dae_config::Group) -> io::Result<()> {
    let has_annotations = group
        .filter_annotation
        .iter()
        .any(|annotation| annotation.as_ref().is_some_and(|items| !items.is_empty()));
    if has_annotations
        || group.tcp_check_url.is_some()
        || !group.tcp_check_http_method.is_empty()
        || group.udp_check_dns.is_some()
        || group.check_interval != Default::default()
        || group.check_tolerance != Default::default()
    {
        return Err(invalid_dae_file(format!(
            "group {:?} contains health-check or annotation fields that product groups cannot store losslessly",
            group.name
        )));
    }
    Ok(())
}
