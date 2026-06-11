pub const PARSER_AST_BASIC: &str = "config/parser/ast_basic.json";
pub const SCHEMA_DEFAULT_PATCH: &str = "config/schema/default_patch.json";
pub const INCLUDE_MERGER: &str = "config/include/merger.json";
pub const MARSHAL_EXAMPLE_ROUNDTRIP: &str = "config/marshal/example_roundtrip.json";
pub const OUTLINE_EXPORT_OUTLINE: &str = "config/outline/export_outline.json";

pub const CONFIG_GOLDEN_FIXTURES: &[&str] = &[
    PARSER_AST_BASIC,
    SCHEMA_DEFAULT_PATCH,
    INCLUDE_MERGER,
    MARSHAL_EXAMPLE_ROUNDTRIP,
    OUTLINE_EXPORT_OUTLINE,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn load(path: &str) -> serde_json::Value {
        dae_golden::load_json(path).unwrap()
    }

    #[test]
    fn config_fixtures_are_available() {
        for path in CONFIG_GOLDEN_FIXTURES {
            assert!(load(path).is_object(), "{path}");
        }
    }

    #[test]
    fn parser_fixture_records_nested_section_parser_quirk() {
        let fixture = load(PARSER_AST_BASIC);
        assert_eq!(fixture["name"], "config-parser-ast-basic");

        let group_item = &fixture["cases"][0]["sections"][3]["items"][0];
        assert_eq!(group_item["item_type"], "Param");
        assert_eq!(group_item["value_kind"], "Section");
        assert_eq!(group_item["section"]["name"], "test_group");
    }

    #[test]
    fn schema_fixture_records_defaults_and_patch_errors() {
        let fixture = load(SCHEMA_DEFAULT_PATCH);
        assert_eq!(fixture["name"], "config-schema-default-patch");
        assert_eq!(
            fixture["cases"][0]["config"]["dns"]["routing"]["request"]["fallback"]["string"],
            "asis"
        );
        assert_eq!(
            fixture["cases"][2]["config"]["global"]["tcp_check_http_method"],
            "CONNECT"
        );

        let invalid_fallback = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "invalid-routing-fallback-function-list")
            .unwrap();
        assert!(
            invalid_fallback["error"]
                .as_str()
                .unwrap()
                .contains("invalid routing fallback")
        );
    }

    #[test]
    fn include_fixture_is_path_stable_and_records_success_projection() {
        let fixture = load(INCLUDE_MERGER);
        assert_eq!(fixture["name"], "config-include-merger");
        assert_eq!(fixture["cases"][0]["config_ok"], true);
        assert_eq!(fixture["cases"][0]["entries"][0], "config.d/child.dae");

        let serialized = serde_json::to_string(&fixture).unwrap();
        assert!(!serialized.contains("/tmp/"));
    }

    #[test]
    fn marshal_fixture_records_roundtrip_contract() {
        let fixture = load(MARSHAL_EXAMPLE_ROUNDTRIP);
        assert_eq!(fixture["name"], "config-marshal-example-roundtrip");
        assert_eq!(
            fixture["roundtrip"]["equal_after_filter_annotation_clear"],
            true
        );
        assert_eq!(
            fixture["marshal"]["sha256"],
            "260742073f9581939f0c1303efb4058c522f758380ad6d1872c5231ddca0b92e"
        );
    }
}
