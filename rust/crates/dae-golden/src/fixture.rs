use std::path::{Path, PathBuf};

use crate::GoldenError;

pub const GOLDEN_ROOT: &str = "testdata/rebuild-golden";

pub fn repo_root_from_manifest() -> Result<PathBuf, GoldenError> {
    find_repo_root(Path::new(env!("CARGO_MANIFEST_DIR")))
}

pub fn golden_root() -> Result<PathBuf, GoldenError> {
    Ok(repo_root_from_manifest()?.join(GOLDEN_ROOT))
}

pub fn fixture_path(relative: impl AsRef<Path>) -> Result<PathBuf, GoldenError> {
    Ok(golden_root()?.join(relative.as_ref()))
}

pub fn read_fixture(relative: impl AsRef<Path>) -> Result<String, GoldenError> {
    let path = fixture_path(relative)?;
    std::fs::read_to_string(&path).map_err(|source| GoldenError::Read { path, source })
}

pub fn load_json(relative: impl AsRef<Path>) -> Result<serde_json::Value, GoldenError> {
    let path = fixture_path(relative)?;
    let data = std::fs::read_to_string(&path).map_err(|source| GoldenError::Read {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&data).map_err(|source| GoldenError::Json { path, source })
}

fn find_repo_root(start: &Path) -> Result<PathBuf, GoldenError> {
    for candidate in start.ancestors() {
        if candidate.join("go.mod").is_file() && candidate.join(GOLDEN_ROOT).is_dir() {
            return Ok(candidate.to_path_buf());
        }
    }

    Err(GoldenError::RepoRootNotFound {
        start: start.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_repo_root_and_reads_known_fixtures() {
        let root = repo_root_from_manifest().unwrap();

        assert!(root.join("go.mod").is_file());
        assert!(golden_root().unwrap().is_dir());
        assert_eq!(
            load_json("abi/consts/reserved_indices.json").unwrap()["name"],
            "reserved-indices"
        );
        assert_eq!(
            load_json("abi/magic_network/mark_mptcp.json").unwrap()["name"],
            "magic-network-mark-mptcp"
        );
        assert_eq!(
            load_json("config/fuzzy/basic.json").unwrap()["name"],
            "fuzzy-decode-basic"
        );
        assert_eq!(
            load_json("config/parse/basic.json").unwrap()["name"],
            "config-parse-basic"
        );
        assert_eq!(
            load_json("config/utils/basic.json").unwrap()["name"],
            "config-utils-basic"
        );
        assert_eq!(
            load_json("config/utils/common.json").unwrap()["name"],
            "common-utils-basic"
        );
        assert_eq!(
            load_json("config/parser/ast_basic.json").unwrap()["name"],
            "config-parser-ast-basic"
        );
        assert_eq!(
            load_json("config/schema/default_patch.json").unwrap()["name"],
            "config-schema-default-patch"
        );
        assert_eq!(
            load_json("config/include/merger.json").unwrap()["name"],
            "config-include-merger"
        );
        assert_eq!(
            load_json("config/marshal/example_roundtrip.json").unwrap()["name"],
            "config-marshal-example-roundtrip"
        );
    }
}
