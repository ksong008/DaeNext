use super::*;

const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";
const PROC_SELF_MOUNTINFO: &str = "/proc/self/mountinfo";
const CGROUP_V2_MOUNT_TYPE: &str = "cgroup2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CgroupMemoryLocation {
    pub(super) path: PathBuf,
    pub(super) cgroup_path: String,
    pub(super) mount_point: String,
}

pub(super) fn resolve_cgroup_memory_location() -> Result<CgroupMemoryLocation, String> {
    resolve_cgroup_memory_location_from_files(PROC_SELF_CGROUP, PROC_SELF_MOUNTINFO)
}

pub(super) fn resolve_cgroup_memory_location_from_files(
    cgroup_file: &str,
    mountinfo_file: &str,
) -> Result<CgroupMemoryLocation, String> {
    let cgroup = read_bounded_cgroup_file(Path::new(cgroup_file))
        .map_err(|error| format!("read {cgroup_file}: {error}"))?;
    let mountinfo = read_bounded_cgroup_file(Path::new(mountinfo_file))
        .map_err(|error| format!("read {mountinfo_file}: {error}"))?;
    resolve_cgroup_memory_location_from_strs(&cgroup, &mountinfo)
}

pub(super) fn resolve_cgroup_memory_location_from_strs(
    cgroup: &str,
    mountinfo: &str,
) -> Result<CgroupMemoryLocation, String> {
    let cgroup_path = parse_cgroup_v2_path(cgroup)
        .ok_or_else(|| "process is not attached to a cgroup v2 hierarchy".to_owned())?;
    let mount_point = parse_cgroup_v2_mount_point(mountinfo)
        .ok_or_else(|| "cgroup v2 mount point not found".to_owned())?;
    let path = join_cgroup_path(&mount_point, &cgroup_path);
    Ok(CgroupMemoryLocation {
        path,
        cgroup_path,
        mount_point,
    })
}

fn parse_cgroup_v2_path(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("0"), Some(""), Some(path)) => Some(path.to_owned()),
            _ => None,
        }
    })
}

fn parse_cgroup_v2_mount_point(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let (pre_separator, post_separator) = line.split_once(" - ")?;
        let filesystem_type = post_separator.split_whitespace().next()?;
        if filesystem_type != CGROUP_V2_MOUNT_TYPE {
            return None;
        }
        let mount_point = pre_separator.split_whitespace().nth(4)?;
        Some(decode_mountinfo_path(mount_point))
    })
}

fn join_cgroup_path(mount_point: &str, cgroup_path: &str) -> PathBuf {
    let mut path = PathBuf::from(mount_point);
    for component in Path::new(cgroup_path).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {}
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
            continue;
        }
        decoded.push('\\');
        decoded.push_str(&digits);
    }
    decoded
}
