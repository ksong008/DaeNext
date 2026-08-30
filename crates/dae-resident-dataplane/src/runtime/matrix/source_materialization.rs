use super::*;
use dae_outbound_core::{SourceShapeReconciliationKind, source_shape_reconciliation};

pub(super) struct ResidentSourceMaterialization<'a> {
    pub(super) node: &'a plan::ResidentNodeLinkShape,
    outcome: Result<MaterializedResidentSourcePlan, String>,
}

struct MaterializedResidentSourcePlan {
    proxy: plan::ResidentProxyPlan,
    shape: dae_outbound_core::MaterializedSourceShape,
}

pub(super) fn resident_source_materializations<'a>(
    config: &Config,
    nodes: &'a [plan::ResidentNodeLinkShape],
    rows: &[SourceShapeRegistryRow],
) -> Vec<ResidentSourceMaterialization<'a>> {
    nodes
        .iter()
        .filter_map(|node| {
            let relevant = |row: &&SourceShapeRegistryRow| {
                source_shape_has_production_witness(row)
                    && source_shape_candidate_is_relevant(row, node)
            };
            let first_relevant_row = rows.iter().find(relevant)?;
            let outcome =
                build_resident_source_plan(config, first_relevant_row.protocol_family, node).map(
                    |proxy| MaterializedResidentSourcePlan {
                        shape: materialized_source_shape(&proxy, &node.link),
                        proxy,
                    },
                );
            Some(ResidentSourceMaterialization { node, outcome })
        })
        .collect()
}

pub(super) fn resident_source_materialization_is_candidate(
    row: &SourceShapeRegistryRow,
    materialization: &ResidentSourceMaterialization<'_>,
) -> bool {
    if !source_shape_candidate_is_relevant(row, materialization.node) {
        return false;
    }
    let Ok(materialized) = &materialization.outcome else {
        return false;
    };
    source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
        reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
            && reconciliation.matches(materialized.shape)
    })
}

pub(super) fn resident_source_materialization_is_classified(
    row: &SourceShapeRegistryRow,
    materialization: &ResidentSourceMaterialization<'_>,
) -> bool {
    let Ok(materialized) = &materialization.outcome else {
        return false;
    };
    source_shape_classifies_materialization(row, &materialized.proxy, &materialization.node.link)
}

pub(super) fn resident_source_materialization_diagnostics(
    rows: &[SourceShapeRegistryRow],
    materializations: &[ResidentSourceMaterialization<'_>],
) -> Vec<Value> {
    materializations
        .iter()
        .filter_map(|materialization| {
            let status = match &materialization.outcome {
                Err(_) => "source-materialization-failed",
                Ok(materialized) => {
                    let mut typed_shape_found = false;
                    let resolved = rows.iter().any(|row| {
                        source_shape_reconciliation(row.shape_id).is_some_and(|reconciliation| {
                            let shape_matches = reconciliation.matches(materialized.shape)
                                || reconciliation.classifies(materialized.shape);
                            typed_shape_found |= shape_matches;
                            shape_matches
                                && source_and_materialized_ownership_agree(row, &materialized.proxy)
                        })
                    });
                    if resolved {
                        return None;
                    }
                    if typed_shape_found {
                        "source-ownership-mismatch"
                    } else {
                        "unclassified-materialized-shape"
                    }
                }
            };
            Some(json!({
                "schemaVersion": 1,
                "status": status,
                "nodeIdentity": link_hash(&materialization.node.link),
                "nodeTag": safe_matrix_node_tag(&materialization.node.tag),
                "nodeTagSource": matrix_node_tag_source(&materialization.node.tag),
                "scheme": &materialization.node.scheme,
                "detail": if status == "source-materialization-failed" {
                    sanitize_matrix_error("")
                } else if status == "source-ownership-mismatch" {
                    "materialized source ownership is not admitted by its typed source disposition".to_owned()
                } else {
                    "materialized source has no typed production, aggregate, deferred, or rejection disposition".to_owned()
                },
            }))
        })
        .collect()
}

pub(super) fn source_shape_reconciliation_kind(
    row: &SourceShapeRegistryRow,
) -> Option<SourceShapeReconciliationKind> {
    source_shape_reconciliation(row.shape_id).map(|reconciliation| reconciliation.kind)
}

fn source_shape_has_production_witness(row: &SourceShapeRegistryRow) -> bool {
    source_shape_reconciliation_kind(row) == Some(SourceShapeReconciliationKind::ProductionWitness)
}

fn build_resident_source_plan(
    config: &Config,
    group_name: &str,
    node: &plan::ResidentNodeLinkShape,
) -> Result<plan::ResidentProxyPlan, String> {
    #[cfg(test)]
    SOURCE_MATRIX_BUILDER_CALLS.with(|calls| calls.set(calls.get() + 1));

    plan::build_resident_proxy_plan_for_node(
        config,
        group_name.to_owned(),
        node.tag.clone(),
        node.link.clone(),
    )
}

pub(super) fn resident_source_shape_candidate_report(
    row: &SourceShapeRegistryRow,
    materialization: &ResidentSourceMaterialization<'_>,
) -> Value {
    debug_assert!(source_shape_has_production_witness(row));
    let node = materialization.node;
    match &materialization.outcome {
        Ok(materialized) => {
            let proxy = &materialized.proxy;
            let mut summary = resident_proxy_plan_summary_json(proxy);
            summary["group"] = json!(row.protocol_family);
            summary["scheme"] = json!(&node.scheme);
            summary["runtimeOwnershipLedger"] = materialized_runtime_ownership_value(proxy);
            summary["runtimeOwnershipAgreement"] =
                json!(source_and_materialized_ownership_agree(row, proxy));
            summary["sourceShapeReconciliation"] = source_shape_reconciliation_status(row);
            if source_shape_matches_materialization(row, proxy, &node.link) {
                summary["planner_status"] = json!("admitted");
                summary["admission"] = json!({
                    "status": "admitted",
                    "failClosed": true,
                    "unsupportedReason": Value::Null,
                });
            } else {
                let mismatch = source_shape_materialization_mismatch_reason(row);
                summary["planner_status"] = json!("blocked");
                summary["admission"] = json!({
                    "status": "fail-closed",
                    "failClosed": true,
                    "unsupportedReason": mismatch,
                });
                summary["error"] = json!(mismatch);
            }
            summary
        }
        Err(err) => json!({
            "planner_status": "blocked",
            "node_tag": safe_matrix_node_tag(&node.tag),
            "node_tag_source": matrix_node_tag_source(&node.tag),
            "scheme": &node.scheme,
            "admission": {
                "status": "fail-closed",
                "failClosed": true,
                "unsupportedReason": sanitize_matrix_error(err),
            },
            "error": sanitize_matrix_error(err),
        }),
    }
}

pub(super) fn resident_source_shape_classified_report(
    row: &SourceShapeRegistryRow,
    materialization: &ResidentSourceMaterialization<'_>,
) -> Value {
    let reconciliation = source_shape_reconciliation(row.shape_id)
        .expect("classified source row must have a reconciliation contract");
    debug_assert_ne!(
        reconciliation.kind,
        SourceShapeReconciliationKind::ProductionWitness
    );
    let materialized = materialization
        .outcome
        .as_ref()
        .expect("classified source row must have a materialized plan");
    json!({
        "schemaVersion": 1,
        "nodeIdentity": link_hash(&materialization.node.link),
        "nodeTag": safe_matrix_node_tag(&materialization.node.tag),
        "nodeTagSource": matrix_node_tag_source(&materialization.node.tag),
        "scheme": &materialization.node.scheme,
        "disposition": reconciliation.kind.as_report_str(),
        "contributesProductionWitness": false,
        "runtimeOwnershipLedger": materialized_runtime_ownership_value(&materialized.proxy),
        "runtimeOwnershipAgreement": source_and_materialized_ownership_agree(row, &materialized.proxy),
    })
}

#[cfg(test)]
std::thread_local! {
    static SOURCE_MATRIX_BUILDER_CALLS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn reset_source_matrix_builder_calls() {
    SOURCE_MATRIX_BUILDER_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn source_matrix_builder_calls() -> usize {
    SOURCE_MATRIX_BUILDER_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
#[path = "source_materialization/tests.rs"]
mod tests;
