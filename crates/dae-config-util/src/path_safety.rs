use std::fmt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathSafetyError {
    rel: PathBuf,
}

impl fmt::Display for PathSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file is out of scope: {}", self.rel.display())
    }
}

impl std::error::Error for PathSafetyError {}

pub fn ensure_file_in_sub_dir(
    file_path: impl AsRef<Path>,
    dir: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let abs_dir = abs_clean(dir.as_ref())?;
    let abs_file_path = abs_clean(file_path.as_ref())?;
    let file_dir = abs_file_path.parent().unwrap_or(&abs_file_path);

    ensure_path_in_sub_dir(file_dir, &abs_dir)?;

    let real_dir = match std::fs::canonicalize(&abs_dir) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(Box::new(err)),
    };

    match std::fs::canonicalize(file_dir) {
        Ok(real_file_dir) => ensure_path_in_sub_dir(&real_file_dir, &real_dir)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Box::new(err)),
    }

    match std::fs::canonicalize(&abs_file_path) {
        Ok(real_file_path) => ensure_path_in_sub_dir(&real_file_path, &real_dir)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Box::new(err)),
    }

    Ok(())
}

fn ensure_path_in_sub_dir(path: &Path, dir: &Path) -> Result<(), PathSafetyError> {
    let rel = relative_path(path, dir);
    let escaped = rel == Path::new("..")
        || rel.starts_with(Path::new("../"))
        || rel.starts_with(Path::new("/"));

    if escaped {
        Err(PathSafetyError { rel })
    } else {
        Ok(())
    }
}

fn abs_clean(path: &Path) -> Result<PathBuf, std::io::Error> {
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    Ok(clean_path(&full))
}

fn clean_path(path: &Path) -> PathBuf {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => cleaned.push(prefix.as_os_str()),
            Component::RootDir => cleaned.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                cleaned.pop();
            }
            Component::Normal(part) => cleaned.push(part),
        }
    }
    cleaned
}

fn relative_path(path: &Path, base: &Path) -> PathBuf {
    let path_parts = normal_components(path);
    let base_parts = normal_components(base);
    let common = path_parts
        .iter()
        .zip(base_parts.iter())
        .take_while(|(left, right)| left == right)
        .count();

    let mut rel = PathBuf::new();
    for _ in common..base_parts.len() {
        rel.push("..");
    }
    for part in &path_parts[common..] {
        rel.push(part);
    }
    if rel.as_os_str().is_empty() {
        rel.push(".");
    }
    rel
}

fn normal_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_file_in_sub_dir_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/utils/basic.json").unwrap();
        let base = TempTree::new();

        for case in fixture["path_safety"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let (file_path, dir) = base.case_paths(name);
            let got = ensure_file_in_sub_dir(&file_path, &dir);
            assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap(), "{name}");
            if let Err(err) = got {
                assert_eq!(err.to_string(), case["error"].as_str().unwrap(), "{name}");
            }
        }
    }

    struct TempTree {
        base: PathBuf,
        root: PathBuf,
        missing_root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let unique = format!(
                "dae-config-util-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let base = std::env::temp_dir().join(unique);
            let root = base.join("root");
            let child = root.join("child");
            let dotdot_sibling = root.join("..sibling");
            let outside_dir = base.join("outside");
            std::fs::create_dir_all(&child).unwrap();
            std::fs::create_dir_all(&dotdot_sibling).unwrap();
            std::fs::create_dir_all(&outside_dir).unwrap();
            std::fs::write(child.join("file.txt"), b"child").unwrap();
            std::fs::write(dotdot_sibling.join("file.txt"), b"dotdot sibling").unwrap();
            std::fs::write(base.join("outside.txt"), b"outside").unwrap();
            std::os::unix::fs::symlink(&outside_dir, root.join("linkdir")).unwrap();
            std::os::unix::fs::symlink(base.join("outside.txt"), root.join("linkfile")).unwrap();
            let missing_root = base.join("missing-root");
            Self {
                base,
                root,
                missing_root,
            }
        }

        fn case_paths(&self, name: &str) -> (PathBuf, PathBuf) {
            match name {
                "normal-child-existing" => (self.root.join("child/file.txt"), self.root.clone()),
                "dotdot-sibling-name" => (self.root.join("..sibling/file.txt"), self.root.clone()),
                "lexical-parent-escape" => (self.root.join("../outside.txt"), self.root.clone()),
                "missing-child-allowed" => (self.root.join("missing/file.txt"), self.root.clone()),
                "missing-root-allowed" => (
                    self.missing_root.join("file.txt"),
                    self.missing_root.clone(),
                ),
                "symlink-dir-escape" => (self.root.join("linkdir/file.txt"), self.root.clone()),
                "symlink-file-escape" => (self.root.join("linkfile"), self.root.clone()),
                other => panic!("unknown path safety fixture case {other}"),
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }
}
