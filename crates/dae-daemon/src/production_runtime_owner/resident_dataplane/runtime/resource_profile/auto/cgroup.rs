use super::host::read_bounded_text;
use std::{
    io,
    path::{Component, Path, PathBuf},
};

const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";
const PROC_SELF_MOUNTINFO: &str = "/proc/self/mountinfo";
const PROC_CONTROL_FILE_READ_LIMIT: u64 = 256 * 1024;
const CGROUP_VALUE_READ_LIMIT: u64 = 4096;
pub(super) const CGROUP_V1_UNLIMITED_THRESHOLD: u64 = 1 << 60;

pub(super) fn read_process_cgroup_memory_limit() -> io::Result<Option<(u64, &'static str)>> {
    let cgroup = read_bounded_text(Path::new(PROC_SELF_CGROUP), PROC_CONTROL_FILE_READ_LIMIT)?;
    let mountinfo =
        read_bounded_text(Path::new(PROC_SELF_MOUNTINFO), PROC_CONTROL_FILE_READ_LIMIT)?;
    let Some((path, source, file_name)) = resolve_memory_limit_path(&cgroup, &mountinfo) else {
        return Ok(None);
    };
    let value = read_bounded_text(&path.join(file_name), CGROUP_VALUE_READ_LIMIT)?;
    parse_memory_limit(value.trim(), file_name).map(|limit| limit.map(|bytes| (bytes, source)))
}

pub(super) fn parse_memory_limit(value: &str, file_name: &str) -> io::Result<Option<u64>> {
    if value == "max" {
        return Ok(None);
    }
    let bytes = value
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if file_name == "memory.limit_in_bytes" && bytes >= CGROUP_V1_UNLIMITED_THRESHOLD {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

pub(super) fn resolve_memory_limit_path(
    cgroup: &str,
    mountinfo: &str,
) -> Option<(PathBuf, &'static str, &'static str)> {
    if let Some(cgroup_path) = parse_unified_cgroup_path(cgroup)
        && let Some((mount_root, mount_point)) = parse_cgroup_mount(mountinfo, "cgroup2", None)
    {
        return Some((
            join_cgroup_mount(&mount_root, &mount_point, &cgroup_path),
            "cgroup-v2-memory.max",
            "memory.max",
        ));
    }
    let cgroup_path = parse_v1_memory_cgroup_path(cgroup)?;
    let (mount_root, mount_point) = parse_cgroup_mount(mountinfo, "cgroup", Some("memory"))?;
    Some((
        join_cgroup_mount(&mount_root, &mount_point, &cgroup_path),
        "cgroup-v1-memory.limit_in_bytes",
        "memory.limit_in_bytes",
    ))
}

fn parse_unified_cgroup_path(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("0"), Some(""), Some(path)) => Some(path.to_owned()),
            _ => None,
        }
    })
}

fn parse_v1_memory_cgroup_path(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        controllers
            .split(',')
            .any(|controller| controller == "memory")
            .then(|| path.to_owned())
    })
}

fn parse_cgroup_mount(
    mountinfo: &str,
    filesystem: &str,
    controller: Option<&str>,
) -> Option<(String, String)> {
    mountinfo.lines().find_map(|line| {
        let (before, after) = line.split_once(" - ")?;
        let mut after_fields = after.split_whitespace();
        if after_fields.next()? != filesystem {
            return None;
        }
        let _source = after_fields.next()?;
        let super_options = after_fields.next().unwrap_or_default();
        if let Some(controller) = controller
            && !super_options.split(',').any(|item| item == controller)
        {
            return None;
        }
        let mut before_fields = before.split_whitespace();
        let mount_root = before_fields.nth(3)?;
        let mount_point = before_fields.next()?;
        Some((
            decode_mountinfo_path(mount_root),
            decode_mountinfo_path(mount_point),
        ))
    })
}

fn join_cgroup_mount(mount_root: &str, mount_point: &str, cgroup_path: &str) -> PathBuf {
    let relative = Path::new(cgroup_path)
        .strip_prefix(Path::new(mount_root))
        .unwrap_or_else(|_| Path::new(cgroup_path));
    let mut path = PathBuf::from(mount_point);
    for component in relative.components() {
        if let Component::Normal(value) = component {
            path.push(value);
        }
    }
    path
}

fn decode_mountinfo_path(path: &str) -> String {
    let mut decoded = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let digits: String = chars.by_ref().take(3).collect();
        if digits.len() == 3
            && let Ok(value) = u8::from_str_radix(&digits, 8)
        {
            decoded.push(value as char);
        } else {
            decoded.push('\\');
            decoded.push_str(&digits);
        }
    }
    decoded
}
