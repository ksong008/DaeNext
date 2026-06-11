use super::*;
pub fn source_shape_registry_contract() -> SourceShapeRegistryContract {
    SourceShapeRegistryContract {
        schema: "outbound-source-shape-registry",
        schema_version: 1,
        rows: source_shape_registry_rows(),
        source_shape_registry_open: true,
        expanded_source_matrix_open: true,
        expanded_source_matrix_complete: false,
        scoped_expanded_source_matrix_evidence: SCOPED_EXPANDED_SOURCE_MATRIX_EVIDENCE,
        release_gate_may_use_current_config_matrix_as_source_matrix: false,
    }
}

pub fn source_shape_registry_rows() -> &'static [SourceShapeRegistryRow] {
    SOURCE_SHAPE_REGISTRY_ROWS
}

pub fn official_common_source_shape_ids() -> &'static [&'static str] {
    OFFICIAL_COMMON_SOURCE_SHAPE_IDS
}

pub fn official_common_fixture_requirements() -> &'static [OfficialCommonSourceShapeRequirement] {
    OFFICIAL_COMMON_FIXTURE_REQUIREMENTS
}

pub fn capability_reason_taxonomy() -> &'static [&'static str] {
    &CAPABILITY_REASON_TAXONOMY
}
