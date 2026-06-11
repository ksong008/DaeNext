use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use dae_config_util::ensure_file_in_sub_dir;

use crate::ast::{Item, Section};
use crate::error::ConfigError;
use crate::parser::parse_config;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeOutput {
    pub sections: Vec<Section>,
    pub entries: Vec<PathBuf>,
}

pub fn merge_config_file(entry: impl Into<PathBuf>) -> Result<MergeOutput, ConfigError> {
    let entry = entry.into();
    let entry_dir = parent_or_dot(&entry).to_path_buf();
    let mut merger = Merger {
        entry: entry.clone(),
        entry_dir,
        entry_to_section_map: BTreeMap::new(),
    };
    merger.dfs_merge(&entry, None)?;
    let entries = merger.entry_to_section_map.keys().cloned().collect();
    let section_map = merger
        .entry_to_section_map
        .remove(&entry)
        .unwrap_or_default();
    let sections = merger.convert_map_to_sections(section_map);
    Ok(MergeOutput { sections, entries })
}

struct Merger {
    entry: PathBuf,
    entry_dir: PathBuf,
    entry_to_section_map: BTreeMap<PathBuf, BTreeMap<String, Vec<Item>>>,
}

impl Merger {
    fn read_entry(&mut self, entry: &Path) -> Result<(), ConfigError> {
        if self.entry_to_section_map.contains_key(entry) {
            return Err(ConfigError::Merge(
                "circular include is not allowed".to_owned(),
            ));
        }

        if !entry.to_string_lossy().ends_with(".dae") {
            return Err(ConfigError::Merge(format!(
                "invalid config filename {}: must has suffix .dae",
                entry.display()
            )));
        }

        ensure_file_in_sub_dir(entry, &self.entry_dir).map_err(|err| {
            ConfigError::Merge(format!(
                "failed in checking path of config file {}: {err}",
                entry.display()
            ))
        })?;

        let mut file = std::fs::File::open(entry).map_err(|err| {
            ConfigError::Merge(format!(
                "failed to read config file {}: {err}",
                entry.display()
            ))
        })?;
        let metadata = file
            .metadata()
            .map_err(|err| ConfigError::Merge(err.to_string()))?;
        if metadata.is_dir() {
            return Err(ConfigError::Merge(format!(
                "cannot include a directory: {}",
                entry.display()
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o037 > 0 {
                return Err(ConfigError::Merge(format!(
                    "permissions {mode:04o} for '{}' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600",
                    entry.display()
                )));
            }
        }

        let mut input = String::new();
        file.read_to_string(&mut input)
            .map_err(|err| ConfigError::Merge(err.to_string()))?;
        let sections = parse_config(&input).map_err(|err| {
            ConfigError::Merge(format!(
                "failed to parse config file {}:\n{err}",
                entry.display()
            ))
        })?;
        let section_map = self.convert_sections_to_map(sections);
        self.entry_to_section_map
            .insert(entry.to_path_buf(), section_map);
        Ok(())
    }

    fn dfs_merge(&mut self, entry: &Path, father_entry: Option<&Path>) -> Result<(), ConfigError> {
        self.read_entry(entry).map_err(|err| {
            if matches!(err, ConfigError::Merge(ref message) if message == "circular include is not allowed")
            {
                let father = father_entry.unwrap_or(&self.entry);
                ConfigError::Merge(format!(
                    "circular include is not allowed: {} -> {} -> ... -> {}",
                    father.display(),
                    entry.display(),
                    father.display()
                ))
            } else {
                err
            }
        })?;

        let include_items = self
            .entry_to_section_map
            .get(entry)
            .and_then(|section_map| section_map.get("include"))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut patterns = Vec::new();
        for include in include_items {
            match include {
                Item::Param(param) => {
                    let next_entry = param.to_config_string(true, false);
                    let next_path = PathBuf::from(next_entry);
                    if next_path.is_absolute() {
                        patterns.push(next_path);
                    } else {
                        patterns.push(self.entry_dir.join(next_path));
                    }
                }
                other => {
                    return Err(ConfigError::Merge(format!(
                        "unsupported include grammar in {}: {}",
                        entry.display(),
                        other.to_config_string(false, false)
                    )));
                }
            }
        }

        let child_entries = unsqueeze_entries(patterns)?;
        for child in child_entries {
            self.dfs_merge(&child, Some(entry))?;
        }

        if let Some(father) = father_entry {
            let child_section_map = self
                .entry_to_section_map
                .get(entry)
                .cloned()
                .unwrap_or_default();
            let father_section_map =
                self.entry_to_section_map.get_mut(father).ok_or_else(|| {
                    ConfigError::Merge(format!(
                        "internal missing father entry {}",
                        father.display()
                    ))
                })?;
            for (section, items) in child_section_map {
                father_section_map.entry(section).or_default().extend(items);
            }
        }
        Ok(())
    }

    fn convert_sections_to_map(&self, sections: Vec<Section>) -> BTreeMap<String, Vec<Item>> {
        let mut section_map: BTreeMap<String, Vec<Item>> = BTreeMap::new();
        for section in sections {
            section_map
                .entry(section.name)
                .or_default()
                .extend(section.items);
        }
        section_map
    }

    fn convert_map_to_sections(&self, section_map: BTreeMap<String, Vec<Item>>) -> Vec<Section> {
        section_map
            .into_iter()
            .map(|(name, items)| Section { name, items })
            .collect()
    }
}

fn parent_or_dot(path: &Path) -> &Path {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }
}

fn unsqueeze_entries(pattern_entries: Vec<PathBuf>) -> Result<Vec<PathBuf>, ConfigError> {
    let mut out = Vec::new();
    for pattern in pattern_entries {
        let files = glob_paths(&pattern)?;
        for file in files {
            if !file.to_string_lossy().ends_with(".dae") {
                continue;
            }
            let Ok(metadata) = std::fs::metadata(&file) else {
                continue;
            };
            if metadata.is_dir() {
                continue;
            }
            out.push(file);
        }
    }
    out.sort();
    Ok(out)
}

fn glob_paths(pattern: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    if !path_has_meta(pattern) {
        return Ok(pattern
            .exists()
            .then(|| pattern.to_path_buf())
            .into_iter()
            .collect());
    }

    let mut prefixes = if pattern.is_absolute() {
        vec![PathBuf::from("/")]
    } else {
        vec![PathBuf::new()]
    };

    for component in pattern.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => continue,
            Component::CurDir => continue,
            Component::ParentDir => {
                for prefix in &mut prefixes {
                    prefix.push("..");
                }
            }
            Component::Normal(part) => {
                let part = part.to_string_lossy();
                if has_meta(&part) {
                    let mut expanded = Vec::new();
                    for prefix in &prefixes {
                        let dir = if prefix.as_os_str().is_empty() {
                            Path::new(".")
                        } else {
                            prefix.as_path()
                        };
                        let entries = match std::fs::read_dir(dir) {
                            Ok(entries) => entries,
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(err) => return Err(ConfigError::Merge(err.to_string())),
                        };
                        for entry in entries {
                            let entry = entry.map_err(|err| ConfigError::Merge(err.to_string()))?;
                            let name = entry.file_name().to_string_lossy().into_owned();
                            if wildcard_match(&part, &name) {
                                expanded.push(prefix.join(name));
                            }
                        }
                    }
                    expanded.sort();
                    prefixes = expanded;
                } else {
                    for prefix in &mut prefixes {
                        prefix.push(part.as_ref());
                    }
                }
            }
        }
    }
    Ok(prefixes.into_iter().filter(|path| path.exists()).collect())
}

fn path_has_meta(path: &Path) -> bool {
    path.components()
        .any(|component| has_meta(&component.as_os_str().to_string_lossy()))
}

fn has_meta(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    wildcard_match_bytes(pattern.as_bytes(), name.as_bytes())
}

fn wildcard_match_bytes(pattern: &[u8], name: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    match pattern[0] {
        b'*' => {
            wildcard_match_bytes(&pattern[1..], name)
                || (!name.is_empty() && wildcard_match_bytes(pattern, &name[1..]))
        }
        b'?' => !name.is_empty() && wildcard_match_bytes(&pattern[1..], &name[1..]),
        byte => {
            !name.is_empty() && byte == name[0] && wildcard_match_bytes(&pattern[1..], &name[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::build_config;

    #[test]
    fn merges_relative_glob_and_child_append_like_native() {
        let tree = TempTree::new();
        tree.mkdir("config.d");
        tree.mkdir("config.d/dir.dae");
        tree.write_mode(
            "entry.dae",
            r#"
include {
    config.d/*
    missing/*.dae
}
global {
    log_level: info
}
routing {
    fallback: parent
}
"#,
            0o640,
        );
        tree.write_mode(
            "config.d/child.dae",
            r#"
include {
    nested.dae
}
global {
    log_level: debug
}
routing {
    domain(child.example) -> child
}
"#,
            0o640,
        );
        tree.write_mode(
            "nested.dae",
            r#"
global {
    tcp_check_http_method: POST
}
node {
    nested: 'socks5://nested'
}
routing {
    domain(nested.example) -> nested
    fallback: nested
}
"#,
            0o640,
        );
        tree.write_mode("config.d/ignored.txt", "global {}", 0o640);

        let output = merge_config_file(tree.path("entry.dae")).unwrap();
        let mut entries = output
            .entries
            .iter()
            .map(|entry| {
                entry
                    .strip_prefix(&tree.root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        entries.sort();
        assert_eq!(entries, ["config.d/child.dae", "entry.dae", "nested.dae"]);

        let config = build_config(&output.sections).unwrap();
        assert_eq!(config.global.log_level, "debug");
        assert_eq!(config.global.tcp_check_http_method, "POST");
        assert_eq!(config.node, ["nested:socks5://nested"]);
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(
            config.routing.fallback,
            crate::DynamicFunctionValue::String("nested".to_owned())
        );
    }

    #[test]
    fn rejects_duplicate_suffix_escape_and_open_permissions() {
        let duplicate = TempTree::new();
        duplicate.mkdir("config.d");
        duplicate.write_mode(
            "entry.dae",
            "include { config.d/child.dae config.d/child.dae }\nglobal {}\nrouting {}\n",
            0o640,
        );
        duplicate.write_mode("config.d/child.dae", "global {}\nrouting {}\n", 0o640);
        let err = merge_config_file(duplicate.path("entry.dae"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("circular include is not allowed"));

        let suffix = TempTree::new();
        suffix.write_mode("entry.conf", "global {}\nrouting {}\n", 0o640);
        let err = merge_config_file(suffix.path("entry.conf"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must has suffix .dae"));

        let open = TempTree::new();
        open.mkdir("config.d");
        open.write_mode(
            "entry.dae",
            "include { config.d/open.dae }\nglobal {}\nrouting {}\n",
            0o640,
        );
        open.write_mode("config.d/open.dae", "global {}\nrouting {}\n", 0o644);
        let err = merge_config_file(open.path("entry.dae"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("permissions 0644"));
    }

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "dae-config-merger-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }

        fn mkdir(&self, rel: &str) {
            std::fs::create_dir_all(self.path(rel)).unwrap();
        }

        fn write_mode(&self, rel: &str, text: &str, mode: u32) {
            let path = self.path(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
