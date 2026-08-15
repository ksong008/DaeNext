use dae_outbound::{
    MaterializedPortHopping, MaterializedQuicVerification, MaterializedSecurity,
    MaterializedSourceImport, MaterializedTlsFeatures, MaterializedXhttpSettings,
    SourceShapeReconciliationKind, VLESSLink, source_shape_reconciliation,
};

use super::*;
use crate::source_reconciliation::{
    materialized_source_runtime_ownership_model, materialized_source_shape,
    source_shape_candidate_is_relevant, source_shape_classifies_materialization,
    source_shape_matches_materialization,
};

mod builder_witnesses;
mod chain;
mod exact_fixture;
mod quic;
mod reverse_totality;
mod source_metadata;
mod trojan_scheme_aliases;
mod wrappers;
mod xhttp;
mod xhttp_h3;

fn fixture_config() -> Config {
    parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        routing {
        fallback: direct
        }
        "#,
    )
}

fn build(link: &str) -> Result<ResidentProxyPlan, String> {
    build_resident_proxy_plan_for_node(
        &fixture_config(),
        "proxy".to_owned(),
        "source-shape-fixture".to_owned(),
        link.to_owned(),
    )
}

fn assert_witness(shape_id: &str, link: String) {
    let proxy = build(&link).unwrap_or_else(|error| panic!("build {shape_id}: {error}"));
    let materialized = materialized_source_shape(&proxy, &link);
    let reconciliation = source_shape_reconciliation(shape_id)
        .unwrap_or_else(|| panic!("missing reconciliation for {shape_id}"));
    assert_eq!(
        reconciliation.kind,
        SourceShapeReconciliationKind::ProductionWitness,
        "{shape_id}"
    );
    assert!(
        reconciliation.matches(materialized),
        "{shape_id}: {materialized:?}"
    );
}
