use super::stage::StagedDaeFile;
use super::*;

mod groups;
mod nodes;
mod sections;
mod storage;
mod validation;

use self::groups::upsert_imported_group;
use self::nodes::{load_existing_nodes, upsert_imported_node};
use self::sections::{select_imported_section, upsert_imported_section};
use self::storage::update_imported_defaults;
use self::validation::validate_imported_materialization;

pub(super) fn commit_dae_file_import(
    state: &Path,
    name_prefix: &str,
    user: &ProductUserRecord,
    staged: StagedDaeFile,
) -> io::Result<DaeFileImportOutcome> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let prefix = name_prefix.trim();
    let prefix = if prefix.is_empty() {
        DEFAULT_IMPORTED_CONFIG_NAME_PREFIX
    } else {
        prefix
    };

    let config = upsert_imported_section(
        &tx,
        SectionKind::Config,
        &format!("{prefix}-{IMPORTED_CONFIG_NAME_SUFFIX}"),
        &staged.global,
    )?;
    let dns = upsert_imported_section(
        &tx,
        SectionKind::Dns,
        &format!("{prefix}-{IMPORTED_DNS_NAME_SUFFIX}"),
        &staged.dns,
    )?;
    let routing = upsert_imported_section(
        &tx,
        SectionKind::Routing,
        &format!("{prefix}-{IMPORTED_ROUTING_NAME_SUFFIX}"),
        &staged.routing,
    )?;

    let mut existing_nodes = load_existing_nodes(&tx)?;
    let mut node_ids_by_tag = BTreeMap::new();
    let mut node_ids = Vec::with_capacity(staged.nodes.len());
    for node in &staged.nodes {
        let id = upsert_imported_node(&tx, &mut existing_nodes, node)?;
        node_ids_by_tag.insert(node.tag.clone(), id);
        node_ids.push(id);
    }

    let mut group_ids = Vec::with_capacity(staged.groups.len());
    for group in &staged.groups {
        group_ids.push(upsert_imported_group(&tx, group, &node_ids_by_tag)?);
    }

    select_imported_section(&tx, SectionKind::Config, config.id)?;
    select_imported_section(&tx, SectionKind::Dns, dns.id)?;
    select_imported_section(&tx, SectionKind::Routing, routing.id)?;
    update_imported_defaults(
        &tx,
        user,
        config.id,
        dns.id,
        routing.id,
        group_ids.first().copied(),
    )?;
    validate_imported_materialization(&tx, &config, &dns, &routing)?;
    tx.commit().map_err(sqlite_io_error)?;

    Ok(DaeFileImportOutcome {
        config_id: config.id,
        dns_id: dns.id,
        routing_id: routing.id,
        group_ids,
        node_ids,
        warnings: staged.warnings,
    })
}
