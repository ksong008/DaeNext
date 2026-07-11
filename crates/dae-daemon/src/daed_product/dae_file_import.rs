use super::*;

mod commit;
mod parse;
mod stage;

use self::commit::commit_dae_file_import;
use self::parse::parse_dae_file;
use self::stage::stage_dae_file;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DaeFileImportOutcome {
    pub(super) config_id: i64,
    pub(super) dns_id: i64,
    pub(super) routing_id: i64,
    pub(super) group_ids: Vec<i64>,
    pub(super) node_ids: Vec<i64>,
    pub(super) warnings: Vec<String>,
}

pub(super) struct DaeFilePreview {
    pub(super) bundle: Value,
    pub(super) warnings: Vec<String>,
}

pub(super) fn import_dae_file(
    state: &Path,
    content: &str,
    name_prefix: &str,
    user: &UserRecord,
) -> io::Result<DaeFileImportOutcome> {
    let parsed = parse_dae_file(content)?;
    let staged = stage_dae_file(parsed)?;
    commit_dae_file_import(state, name_prefix, user, staged)
}

pub(super) fn preview_dae_file(content: &str, name_prefix: &str) -> io::Result<DaeFilePreview> {
    let parsed = parse_dae_file(content)?;
    let staged = stage_dae_file(parsed)?;
    let prefix = name_prefix.trim();
    let prefix = if prefix.is_empty() {
        DEFAULT_IMPORTED_CONFIG_NAME_PREFIX
    } else {
        prefix
    };
    let node_ids = staged
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.tag.clone(), index as i64 + 1))
        .collect::<BTreeMap<_, _>>();
    let nodes = staged
        .nodes
        .iter()
        .map(|node| {
            let parsed = parse_node_link(&node.link, Some(&node.tag));
            json!({
                "id": node_ids[&node.tag],
                "link": node.link,
                "name": parsed.display_name,
                "address": parsed.address,
                "protocol": parsed.protocol,
                "tag": node.tag,
                "subscriptionId": Value::Null,
            })
        })
        .collect::<Vec<_>>();
    let groups = staged
        .groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            json!({
                "id": index as i64 + 1,
                "name": group.name,
                "policy": group.policy,
                "policyParams": group.policy_params.iter().map(|(key, value)| {
                    json!({"key": key, "val": value})
                }).collect::<Vec<_>>(),
                "nodeIds": group.node_tags.iter().map(|tag| node_ids[tag]).collect::<Vec<_>>(),
                "subscriptionBindings": [],
            })
        })
        .collect::<Vec<_>>();
    let first_group_id = (!groups.is_empty()).then_some(1_i64);
    let bundle = json!({
        "schemaVersion": 1,
        "exportedAt": now_text(),
        "mode": DEFAULT_PRODUCT_MODE,
        "defaults": {
            "configId": 1,
            "dnsId": 1,
            "routingId": 1,
            "groupId": first_group_id,
        },
        "selected": {
            "configId": 1,
            "dnsId": 1,
            "routingId": 1,
        },
        "configs": [{
            "id": 1,
            "name": format!("{prefix}-{IMPORTED_CONFIG_NAME_SUFFIX}"),
            "global": staged.global,
        }],
        "dnss": [{
            "id": 1,
            "name": format!("{prefix}-{IMPORTED_DNS_NAME_SUFFIX}"),
            "dns": staged.dns,
        }],
        "routings": [{
            "id": 1,
            "name": format!("{prefix}-{IMPORTED_ROUTING_NAME_SUFFIX}"),
            "routing": staged.routing,
        }],
        "subscriptions": [],
        "nodes": nodes,
        "groups": groups,
    });
    Ok(DaeFilePreview {
        bundle,
        warnings: staged.warnings,
    })
}

pub(super) fn invalid_dae_file(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
