use std::io;
use std::path::{Path, PathBuf};

use dae_geodata::paths::{find_geodata_asset, geodata_asset_dirs, geodata_override_dir};

use crate::{GeodataKind, recover_geodata_transaction};

/// Product geodata follows the resident resolver, independently of Web assets.
#[derive(Clone, Debug)]
pub struct ProductGeodataPaths {
    search: Vec<PathBuf>,
    preferred: Option<PathBuf>,
    fallback: PathBuf,
}

impl ProductGeodataPaths {
    pub fn from_environment() -> Self {
        Self {
            search: geodata_asset_dirs("daed", Vec::<PathBuf>::new()),
            preferred: geodata_override_dir(),
            fallback: PathBuf::from("/usr/share/daed"),
        }
    }

    pub fn read_directory(&self, kind: GeodataKind) -> PathBuf {
        find_geodata_asset(&self.search, kind.file_name())
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| self.preferred.as_ref().unwrap_or(&self.fallback).clone())
    }

    pub fn update_directory(&self, kind: GeodataKind) -> PathBuf {
        self.preferred
            .clone()
            .unwrap_or_else(|| self.read_directory(kind))
    }

    pub fn recover(&self, state: &Path, kind: GeodataKind) -> io::Result<()> {
        // An explicit override is the only directory this product instance writes.
        // Fallback files may belong to another instance, including its journals.
        if let Some(dir) = &self.preferred {
            return recover_geodata_transaction(dir, state, kind);
        }
        // Without an override, scan possible write directories even when their
        // live file disappeared. Selecting only an existing file misses its journal.
        for dir in &self.search {
            recover_geodata_transaction(dir, state, kind)?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_directory(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            search: vec![dir.clone()],
            preferred: Some(dir.clone()),
            fallback: dir,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_search_directories(search: Vec<PathBuf>, preferred: Option<PathBuf>) -> Self {
        let fallback = search
            .last()
            .expect("at least one geodata directory")
            .clone();
        Self {
            search,
            preferred,
            fallback,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_override_does_not_recover_unrelated_fallback_transactions() {
        let root =
            std::env::temp_dir().join(format!("daed-geodata-recovery-scope-{}", fastrand::u64(..)));
        let preferred = root.join("override");
        let fallback = root.join("fallback");
        std::fs::create_dir_all(&preferred).unwrap();
        std::fs::create_dir_all(&fallback).unwrap();
        let other_journal = fallback.join(".geosite.dat.update-journal.json");
        std::fs::write(&other_journal, b"another instance owns this journal").unwrap();
        let paths = ProductGeodataPaths::for_search_directories(
            vec![preferred.clone(), fallback],
            Some(preferred),
        );
        paths
            .recover(&root.join("state.db"), GeodataKind::Geosite)
            .unwrap();
        assert_eq!(
            std::fs::read(&other_journal).unwrap(),
            b"another instance owns this journal"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_override_files_fall_back_independently_but_updates_use_override() {
        let root = std::env::temp_dir().join(format!("daed-geodata-paths-{}", fastrand::u64(..)));
        let preferred = root.join("override");
        let fallback = root.join("fallback");
        std::fs::create_dir_all(&preferred).unwrap();
        std::fs::create_dir_all(&fallback).unwrap();
        std::fs::write(preferred.join("geoip.dat"), b"geoip").unwrap();
        std::fs::write(fallback.join("geosite.dat"), b"geosite").unwrap();
        let paths = ProductGeodataPaths {
            search: vec![preferred.clone(), fallback.clone()],
            preferred: Some(preferred.clone()),
            fallback: fallback.clone(),
        };
        assert_eq!(paths.read_directory(GeodataKind::Geoip), preferred);
        assert_eq!(paths.read_directory(GeodataKind::Geosite), fallback);
        assert_eq!(paths.update_directory(GeodataKind::Geosite), preferred);
        std::fs::write(preferred.join("geosite.dat"), b"updated").unwrap();
        assert_eq!(paths.read_directory(GeodataKind::Geosite), preferred);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_override_updates_the_file_the_runtime_will_load() {
        let root = std::env::temp_dir().join(format!("daed-geodata-current-{}", fastrand::u64(..)));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("geoip.dat"), b"geoip").unwrap();
        let paths = ProductGeodataPaths {
            search: vec![root.clone()],
            preferred: None,
            fallback: root.join("new"),
        };
        assert_eq!(paths.update_directory(GeodataKind::Geoip), root);
        assert_eq!(
            paths.update_directory(GeodataKind::Geosite),
            root.join("new")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
