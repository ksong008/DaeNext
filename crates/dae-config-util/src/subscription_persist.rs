use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

pub const SUBSCRIPTION_RESOLVE_CONCURRENCY: usize = 6;

pub fn cleanup_subscription_persist_files(
    config_dir: impl AsRef<Path>,
    active_tags: &HashSet<String>,
) -> io::Result<Vec<String>> {
    let persist_dir = config_dir.as_ref().join("persist.d");
    let entries = match fs::read_dir(&persist_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut remaining = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let tag = file_name.strip_suffix(".sub").unwrap_or(&file_name);
        if active_tags.contains(tag) {
            remaining.push(file_name.into_owned());
            continue;
        }

        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }

    remaining.sort();
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_persist_cleanup_matches_golden_fixture() {
        let fixture = dae_golden::load_json("engine/subscription/persist_cleanup.json").unwrap();
        assert_eq!(
            SUBSCRIPTION_RESOLVE_CONCURRENCY,
            fixture["concurrency_limit"].as_u64().unwrap() as usize
        );
        let root = std::env::temp_dir().join(format!(
            "dae-config-util-subscription-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let persist_dir = root.join("persist.d");
        fs::create_dir_all(&persist_dir).unwrap();
        for file in fixture["input_files"].as_array().unwrap() {
            fs::write(persist_dir.join(file.as_str().unwrap()), "payload").unwrap();
        }
        let active = fixture["active_tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<HashSet<_>>();
        let remaining = cleanup_subscription_persist_files(&root, &active).unwrap();
        assert_eq!(
            remaining,
            fixture["remaining_files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        );
        assert!(
            cleanup_subscription_persist_files(root.join("missing"), &HashSet::new())
                .unwrap()
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
