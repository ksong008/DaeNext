pub mod error;
pub mod fixture;

pub use error::GoldenError;
pub use fixture::{
    GOLDEN_ROOT, fixture_path, golden_root, load_json, read_fixture, repo_root_from_manifest,
};
