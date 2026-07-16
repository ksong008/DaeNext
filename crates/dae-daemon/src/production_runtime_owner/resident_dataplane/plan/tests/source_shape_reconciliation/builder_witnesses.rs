use std::collections::BTreeMap;

use super::*;

mod chained_sources;
mod source_corpus;
mod source_fixtures;
mod standalone_sources;

use self::source_corpus::builder_sources;

#[test]
fn every_production_row_has_a_builder_and_ownership_witness() {
    let config = fixture_config();
    let sources = builder_sources();
    let built = sources
        .iter()
        .map(|source| {
            let proxy = build_resident_proxy_plan_for_node(
                &config,
                "proxy".to_owned(),
                "builder-witness".to_owned(),
                source.clone(),
            )
            .unwrap_or_else(|err| panic!("builder witness source must materialize: {err}"));
            let parsed = dae_outbound::parse_link_chain(source).unwrap();
            let node = ResidentNodeLinkShape {
                tag: "builder-witness".to_owned(),
                scheme: parsed.nodes.first().unwrap().scheme.clone(),
                link: source.clone(),
            };
            (source, proxy, node)
        })
        .collect::<Vec<_>>();
    let mut witnessed_by: BTreeMap<(&str, usize), Vec<&str>> = BTreeMap::new();

    for row in dae_outbound::source_shape_registry_rows() {
        let reconciliation = source_shape_reconciliation(row.shape_id).unwrap();
        if reconciliation.kind != SourceShapeReconciliationKind::ProductionWitness {
            continue;
        }
        for (source, proxy, node) in &built {
            if source_shape_matches_materialization(row, proxy, source) {
                assert!(
                    source_shape_candidate_is_relevant(row, node),
                    "typed builder witness is unreachable through candidate prefilter: {} <- {}",
                    row.shape_id,
                    proxy.protocol
                );
                let materialized = materialized_source_shape(proxy, source);
                for (selector_index, selector) in reconciliation.selectors.iter().enumerate() {
                    if selector.matches(materialized) {
                        witnessed_by
                            .entry((row.shape_id, selector_index))
                            .or_default()
                            .push(proxy.protocol);
                    }
                }
            }
        }
    }

    let missing_rows = dae_outbound::source_shape_reconciliations()
        .iter()
        .filter(|reconciliation| {
            reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
                && !reconciliation
                    .selectors
                    .iter()
                    .enumerate()
                    .any(|(index, _)| witnessed_by.contains_key(&(reconciliation.shape_id, index)))
        })
        .map(|reconciliation| reconciliation.shape_id)
        .collect::<Vec<_>>();
    let missing_selectors = dae_outbound::source_shape_reconciliations()
        .iter()
        .filter(|reconciliation| {
            reconciliation.kind == SourceShapeReconciliationKind::ProductionWitness
        })
        .flat_map(|reconciliation| {
            reconciliation
                .selectors
                .iter()
                .enumerate()
                .filter(|(index, _)| !witnessed_by.contains_key(&(reconciliation.shape_id, *index)))
                .map(|(index, _)| (reconciliation.shape_id, index))
        })
        .collect::<Vec<_>>();
    assert!(
        missing_rows.is_empty(),
        "production rows without builder witnesses: {missing_rows:?}"
    );
    assert!(
        missing_selectors.is_empty(),
        "production selectors without builder witnesses: {missing_selectors:?}"
    );
}
