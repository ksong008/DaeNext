use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;

use dae_config::Config;
use dae_config::parser::parse_config;
use dae_config::schema::build_config;
use dae_product_core::{
    DEFAULT_PRODUCT_GROUP_POLICY, DEFAULT_PRODUCT_MODE, GROUP_POLICY_FIXED,
    SUPPORTED_GROUP_POLICIES, SectionKind, product_now_text as now_text,
};
use dae_product_persistence::{
    ProductUserRecord, ensure_state_schema, open_state_connection, set_value_at_path,
    sqlite_io_error,
};
use dae_product_runtime::{build_runtime_config_from_content, render_generated_config};
use dae_product_subscription::{
    ParsedNodeLink, StableNodeKey, get_group_value_with_conn, parse_node_link,
    subscription_node_row_value as node_row_value,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};

type UserRecord = ProductUserRecord;

const DEFAULT_IMPORTED_CONFIG_NAME_PREFIX: &str = "imported";
const IMPORTED_CONFIG_NAME_SUFFIX: &str = "global";
const IMPORTED_DNS_NAME_SUFFIX: &str = "dns";
const IMPORTED_ROUTING_NAME_SUFFIX: &str = "routing";

mod commit;
mod parse;
mod stage;

use self::commit::commit_dae_file_import;
use self::parse::parse_dae_file;
use self::stage::stage_dae_file;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeFileImportOutcome {
    pub config_id: i64,
    pub dns_id: i64,
    pub routing_id: i64,
    pub group_ids: Vec<i64>,
    pub node_ids: Vec<i64>,
    pub warnings: Vec<String>,
}

pub struct DaeFilePreview {
    pub bundle: Value,
    pub warnings: Vec<String>,
}

pub fn import_dae_file(
    state: &Path,
    content: &str,
    name_prefix: &str,
    user: &ProductUserRecord,
) -> io::Result<DaeFileImportOutcome> {
    let parsed = parse_dae_file(content)?;
    let staged = stage_dae_file(parsed)?;
    commit_dae_file_import(state, name_prefix, user, staged)
}

pub fn preview_dae_file(content: &str, name_prefix: &str) -> io::Result<DaeFilePreview> {
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
