use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub fn geodata_override_dir() -> Option<PathBuf> {
    env::var_os("DAE_LOCATION_ASSET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub fn geodata_asset_dirs(
    product: &str,
    extra: impl IntoIterator<Item = impl Into<PathBuf>>,
) -> Vec<PathBuf> {
    asset_dirs_with_env(product, extra.into_iter().map(Into::into), |key| {
        env::var_os(key)
    })
}

pub fn product_system_geodata_dirs(product: &str) -> Vec<PathBuf> {
    let product = if product.is_empty() { "dae" } else { product };
    ["/etc", "/usr/local/share", "/usr/share"]
        .into_iter()
        .map(|root| Path::new(root).join(product))
        .collect()
}

fn asset_dirs_with_env(
    product: &str,
    extra: impl IntoIterator<Item = PathBuf>,
    env: impl Fn(&str) -> Option<OsString>,
) -> Vec<PathBuf> {
    let product = if product.is_empty() { "dae" } else { product };
    let mut dirs = Vec::new();
    if let Some(dir) = env("DAE_LOCATION_ASSET").filter(|value| !value.is_empty()) {
        dirs.push(PathBuf::from(dir));
    }
    dirs.extend(extra);
    dirs.extend(product_system_geodata_dirs(product));
    if let Some(dir) = env("XDG_DATA_HOME") {
        dirs.push(PathBuf::from(dir).join(product));
    } else if let Some(home) = env("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share").join(product));
    }
    if let Some(paths) = env("XDG_DATA_DIRS") {
        dirs.extend(
            env::split_paths(&paths)
                .filter(|path| !path.as_os_str().is_empty())
                .map(|path| path.join(product)),
        );
    }
    let mut unique = Vec::new();
    for dir in dirs {
        if !unique.contains(&dir) {
            unique.push(dir);
        }
    }
    unique
}

pub fn find_geodata_asset(dirs: &[PathBuf], filename: &str) -> Option<PathBuf> {
    let filename = Path::new(filename);
    if filename.is_absolute() {
        return filename.is_file().then(|| filename.to_path_buf());
    }
    dirs.iter()
        .map(|dir| dir.join(filename))
        .find(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_order_preserves_override_extra_system_and_xdg_precedence() {
        let dirs = asset_dirs_with_env("daed", [PathBuf::from("/config")], |key| match key {
            "DAE_LOCATION_ASSET" => Some("/assets".into()),
            "XDG_DATA_HOME" => Some("/data".into()),
            "XDG_DATA_DIRS" => Some("/shared::/usr/share".into()),
            _ => None,
        });
        assert_eq!(
            dirs,
            [
                "/assets",
                "/config",
                "/etc/daed",
                "/usr/local/share/daed",
                "/usr/share/daed",
                "/data/daed",
                "/shared/daed"
            ]
            .map(PathBuf::from)
        );
    }

    #[test]
    fn empty_override_is_ignored_and_home_is_the_xdg_fallback() {
        let dirs = asset_dirs_with_env("daed", [], |key| match key {
            "DAE_LOCATION_ASSET" => Some("".into()),
            "HOME" => Some("/home/test".into()),
            _ => None,
        });
        assert_eq!(dirs.first().unwrap(), Path::new("/etc/daed"));
        assert_eq!(
            dirs.last().unwrap(),
            Path::new("/home/test/.local/share/daed")
        );
    }
}
