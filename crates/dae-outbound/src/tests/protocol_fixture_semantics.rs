use std::fs;
use std::path::Path;

#[test]
fn protocol_golden_fixtures_use_generic_semantics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/rebuild-golden/outbound/protocol");
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let filename = path.file_name().unwrap().to_string_lossy();

        for digit in '0'..='9' {
            let needle = format!("{}{}{}", "sta", "ge", digit);
            assert!(
                !text.contains(&needle) && !filename.contains(&needle),
                "protocol fixture must not use planning labels: {filename} contains {needle}"
            );
        }

        for needle in [
            ["sta", "ge", "-"].concat(),
            ["#", "sta", "ge"].concat(),
            "matrix-".to_owned(),
            "://matrix".to_owned(),
            "/matrix-".to_owned(),
            "#matrix-".to_owned(),
            "tag=matrix-".to_owned(),
            "name=matrix-".to_owned(),
        ] {
            assert!(
                !text.contains(&needle) && !filename.contains(&needle),
                "protocol fixture must use protocol-generic semantics: {filename} contains {needle}"
            );
        }
    }
}
