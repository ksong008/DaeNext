use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::os::fd::{FromRawFd, OwnedFd};

pub const MAP_USAGE_WARNING_RATIO: f64 = 0.70;
pub const MAP_USAGE_PRESSURE_RATIO: f64 = 0.90;

const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_LOOKUP_ELEM: libc::c_uint = 1;
const BPF_MAP_DELETE_ELEM: libc::c_uint = 3;
const BPF_MAP_GET_NEXT_ID: libc::c_uint = 12;
const BPF_MAP_GET_NEXT_KEY: libc::c_uint = 4;
const BPF_MAP_GET_FD_BY_ID: libc::c_uint = 14;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_uint = 15;
const BPF_ANY: u64 = 0;
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
const BPF_MAP_TYPE_HASH_OF_MAPS: u32 = 13;
const BPF_MAP_TYPE_SOCKHASH: u32 = 18;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeMapInfo {
    pub id: u32,
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RuntimeMapCapacity {
    pub info: RuntimeMapInfo,
    pub entries: u64,
    pub entries_exact: bool,
    pub usage_ratio: f64,
    pub pressure_applicable: bool,
    pub warning: bool,
    pub pressure: bool,
    pub near_capacity: bool,
}

impl RuntimeMapCapacity {
    fn new(info: RuntimeMapInfo, entries: u64, entries_exact: bool) -> Self {
        let usage_ratio = if info.max_entries == 0 || !entries_exact {
            0.0
        } else {
            entries as f64 / info.max_entries as f64
        };
        let pressure_applicable = map_type_has_occupancy_pressure(info.map_type);
        let warning =
            pressure_applicable && entries_exact && usage_ratio >= MAP_USAGE_WARNING_RATIO;
        let pressure =
            pressure_applicable && entries_exact && usage_ratio >= MAP_USAGE_PRESSURE_RATIO;
        Self {
            info,
            entries,
            entries_exact,
            usage_ratio,
            pressure_applicable,
            warning,
            pressure,
            near_capacity: warning,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeMapSnapshot {
    maps: Vec<RuntimeMapInfo>,
}

impl RuntimeMapSnapshot {
    pub fn collect() -> io::Result<Self> {
        let ids = map_ids()?;
        Self::from_ids(&ids)
    }

    pub fn from_ids(ids: &[u32]) -> io::Result<Self> {
        let mut maps = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(info) = map_info_by_id_if_alive(*id)? else {
                continue;
            };
            maps.push(info);
        }
        Ok(Self { maps })
    }

    pub fn maps(&self) -> &[RuntimeMapInfo] {
        &self.maps
    }

    pub fn ids(&self) -> Vec<u32> {
        self.maps.iter().map(|info| info.id).collect()
    }

    pub fn by_id(&self, id: u32) -> Option<&RuntimeMapInfo> {
        self.maps.iter().find(|info| info.id == id)
    }

    pub fn all_by_name<'a>(&'a self, name: &str) -> Vec<&'a RuntimeMapInfo> {
        self.maps
            .iter()
            .filter(|info| runtime_map_name_matches(&info.name, name))
            .collect()
    }

    pub fn all_by_name_in_ids<'a>(&'a self, ids: &[u32], name: &str) -> Vec<&'a RuntimeMapInfo> {
        self.maps
            .iter()
            .filter(|info| ids.contains(&info.id) && runtime_map_name_matches(&info.name, name))
            .collect()
    }

    pub fn latest_by_name(&self, name: &str) -> Option<&RuntimeMapInfo> {
        self.all_by_name(name)
            .into_iter()
            .max_by_key(|info| info.id)
    }

    pub fn latest_by_name_in_ids(&self, ids: &[u32], name: &str) -> Option<&RuntimeMapInfo> {
        self.all_by_name_in_ids(ids, name)
            .into_iter()
            .max_by_key(|info| info.id)
    }
}

pub fn runtime_map_name_matches(actual: &str, expected: &str) -> bool {
    actual == expected || actual.as_bytes() == truncated_bpf_name_bytes(expected)
}

pub fn truncated_bpf_name(name: &str) -> &str {
    let bytes = name.as_bytes();
    let len = bytes.len().min(BPF_OBJ_NAME_MAX_VISIBLE_LEN);
    std::str::from_utf8(&bytes[..len]).unwrap_or(name)
}

fn truncated_bpf_name_bytes(name: &str) -> &[u8] {
    let bytes = name.as_bytes();
    &bytes[..bytes.len().min(BPF_OBJ_NAME_MAX_VISIBLE_LEN)]
}

const BPF_OBJ_NAME_MAX_VISIBLE_LEN: usize = 15;

fn map_type_has_occupancy_pressure(map_type: u32) -> bool {
    matches!(
        map_type,
        BPF_MAP_TYPE_HASH
            | BPF_MAP_TYPE_LRU_HASH
            | BPF_MAP_TYPE_LPM_TRIE
            | BPF_MAP_TYPE_HASH_OF_MAPS
            | BPF_MAP_TYPE_SOCKHASH
    )
}

pub fn map_ids() -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    let mut start_id = 0;
    loop {
        let mut attr = BpfIdAttr {
            start_id,
            ..BpfIdAttr::default()
        };
        // SAFETY: The attr pointer references a valid BPF_MAP_GET_NEXT_ID payload
        // for the duration of the syscall.
        let status = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_GET_NEXT_ID,
                &mut attr as *mut BpfIdAttr,
                size_of::<BpfIdAttr>(),
            )
        };
        if status < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(err);
        }
        ids.push(attr.next_id);
        start_id = attr.next_id;
    }
    Ok(ids)
}

pub fn open_map_fd(id: u32) -> io::Result<OwnedFd> {
    let attr = BpfIdAttr {
        start_id: id,
        ..BpfIdAttr::default()
    };
    // SAFETY: The attr pointer references a valid BPF_MAP_GET_FD_BY_ID payload
    // for the duration of the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_GET_FD_BY_ID,
            &attr as *const BpfIdAttr,
            size_of::<BpfIdAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A successful BPF_MAP_GET_FD_BY_ID returns a new owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn map_info_by_id_if_alive(id: u32) -> io::Result<Option<RuntimeMapInfo>> {
    let fd = match open_map_fd(id) {
        Ok(fd) => fd,
        Err(err) if is_transient_missing_map_id(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    match map_info(fd.as_raw_fd()) {
        Ok(info) => Ok(Some(info)),
        Err(err) if is_transient_missing_map_id(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn is_transient_missing_map_id(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENOENT)
}

pub fn map_info(fd: i32) -> io::Result<RuntimeMapInfo> {
    let mut info = BpfMapInfo::default();
    let attr = BpfInfoAttr {
        bpf_fd: fd as u32,
        info_len: size_of::<BpfMapInfo>() as u32,
        info: (&mut info as *mut BpfMapInfo) as u64,
    };
    // SAFETY: The attr pointer and info buffer are valid for the syscall and
    // info_len matches the BpfMapInfo layout expected by this userspace wrapper.
    let status = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &attr as *const BpfInfoAttr,
            size_of::<BpfInfoAttr>(),
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = info
        .name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(info.name.len());
    Ok(RuntimeMapInfo {
        id: info.id,
        name: String::from_utf8_lossy(&info.name[..end]).into_owned(),
        map_type: info.map_type,
        key_size: info.key_size,
        value_size: info.value_size,
        max_entries: info.max_entries,
        flags: info.map_flags,
    })
}

/// Resolve the map's declared key/value sizes, used to validate caller slices
/// before handing raw pointers to the kernel.
///
/// Fails when the sizes cannot be queried (the fd is not a BPF map, or the
/// kernel denies `BPF_OBJ_GET_INFO_BY_FD`).  This is a safe public API: it
/// must not rely on an implicit caller precondition, so an unqueryable map
/// rejects the call instead of degrading to an unchecked syscall that could
/// write past a caller buffer.
fn map_elem_sizes(map_fd: RawFd) -> io::Result<(u32, u32)> {
    let info = map_info(map_fd)?;
    Ok((info.key_size, info.value_size))
}

/// Reject buffers shorter than the map's declared element size.
///
/// The kernel copies exactly `key_size`/`value_size` bytes through the raw
/// pointer passed to the syscall; a shorter caller slice is an out-of-bounds
/// read (update/delete) or write (lookup) on the caller's buffer.  Longer
/// slices are fine — the kernel only touches the first `size` bytes.
fn validate_elem_len(
    op: &str,
    which: &str,
    map_fd: RawFd,
    len: usize,
    size: u32,
) -> io::Result<()> {
    if len >= size as usize {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{op}_map_elem_bytes: {which} slice too short for map fd {map_fd}: \
                 len {len} < map {which}_size {size}"
            ),
        ))
    }
}

pub fn update_map_elem_bytes(map_fd: RawFd, key: &[u8], value: &[u8]) -> io::Result<()> {
    // Buffer-size contract: `key`/`value` must each be at least as long as the
    // map's key_size/value_size, because the kernel copies exactly that many
    // bytes from these pointers.  Sizes come from a fresh BPF_OBJ_GET_INFO_BY_FD
    // query per call — deliberately no cross-call cache, since RawFd numbers can
    // be reused after close and a stale entry would either wrongly reject valid
    // calls or silently accept undersized buffers.  An unqueryable map rejects
    // the call: this is a safe API and must not pass unchecked pointers through.
    let (key_size, value_size) = map_elem_sizes(map_fd)?;
    validate_elem_len("update", "key", map_fd, key.len(), key_size)?;
    validate_elem_len("update", "value", map_fd, value.len(), value_size)?;
    let attr = BpfMapUpdateElemAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        value: value.as_ptr() as u64,
        flags: BPF_ANY,
        ..BpfMapUpdateElemAttr::default()
    };
    // SAFETY: The key and value slices remain alive for the syscall and the
    // kernel reads exactly the map key/value sizes from their pointers.
    let status = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr as *const BpfMapUpdateElemAttr,
            size_of::<BpfMapUpdateElemAttr>(),
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn delete_map_elem_bytes(map_fd: RawFd, key: &[u8]) -> io::Result<()> {
    // Same buffer-size contract as `update_map_elem_bytes`: the kernel reads
    // exactly key_size bytes from `key`, so a shorter slice is an out-of-bounds
    // read.  An unqueryable map rejects the call (safe API, no implicit
    // precondition).
    let (key_size, _) = map_elem_sizes(map_fd)?;
    validate_elem_len("delete", "key", map_fd, key.len(), key_size)?;
    let attr = BpfMapDeleteElemAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        ..BpfMapDeleteElemAttr::default()
    };
    // SAFETY: The key slice remains alive for the syscall and points to the map
    // key bytes expected by the target map.
    let status = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_DELETE_ELEM,
            &attr as *const BpfMapDeleteElemAttr,
            size_of::<BpfMapDeleteElemAttr>(),
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn lookup_map_elem_bytes(map_fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<()> {
    // Buffer-size contract: `key` must be at least key_size bytes and `value`
    // at least value_size bytes — the kernel reads from `key` and WRITES
    // exactly value_size bytes into `value`, so a short `value` slice is a
    // heap/stack buffer overflow on the caller's side.  An unqueryable map
    // rejects the call (safe API, no implicit precondition).
    let (key_size, value_size) = map_elem_sizes(map_fd)?;
    validate_elem_len("lookup", "key", map_fd, key.len(), key_size)?;
    validate_elem_len("lookup", "value", map_fd, value.len(), value_size)?;
    let attr = BpfMapLookupElemAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        value: value.as_mut_ptr() as u64,
        ..BpfMapLookupElemAttr::default()
    };
    // SAFETY: The key and mutable value slices remain alive for the syscall and
    // the kernel writes into the provided value buffer.
    let status = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const BpfMapLookupElemAttr,
            size_of::<BpfMapLookupElemAttr>(),
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn count_map_entries_by_id(id: u32) -> io::Result<u64> {
    let fd = open_map_fd(id)?;
    count_map_entries_by_fd(fd.as_raw_fd())
}

pub fn count_map_entries_by_fd(map_fd: RawFd) -> io::Result<u64> {
    let info = map_info(map_fd)?;
    count_map_entries_by_fd_with_key_size(map_fd, info.key_size)
}

pub fn map_capacity_by_id(id: u32) -> io::Result<RuntimeMapCapacity> {
    let fd = open_map_fd(id)?;
    map_capacity_by_fd(fd.as_raw_fd())
}

pub fn map_capacity_by_fd(map_fd: RawFd) -> io::Result<RuntimeMapCapacity> {
    let info = map_info(map_fd)?;
    let entries = count_map_entries_by_fd_with_key_size(map_fd, info.key_size)?;
    Ok(RuntimeMapCapacity::new(info, entries, true))
}

pub fn map_capacity_fast_by_id(id: u32) -> io::Result<RuntimeMapCapacity> {
    let fd = open_map_fd(id)?;
    map_capacity_fast_by_fd(fd.as_raw_fd())
}

pub fn map_capacity_fast_by_fd(map_fd: RawFd) -> io::Result<RuntimeMapCapacity> {
    let info = map_info(map_fd)?;
    let entries = if map_type_has_occupancy_pressure(info.map_type) {
        0
    } else {
        u64::from(info.max_entries)
    };
    Ok(RuntimeMapCapacity::new(info, entries, false))
}

fn count_map_entries_by_fd_with_key_size(map_fd: RawFd, key_size: u32) -> io::Result<u64> {
    let max_keys = map_info(map_fd)
        .map(|info| u64::from(info.max_entries))
        .unwrap_or(u64::MAX);
    visit_map_keys_by_fd(map_fd, key_size, max_keys, |_| Ok(()))
}

pub fn visit_map_keys_by_fd(
    map_fd: RawFd,
    key_size: u32,
    max_keys: u64,
    mut visit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    if key_size == 0 || max_keys == 0 {
        return Ok(0);
    }
    if let Ok(info) = map_info(map_fd)
        && info.key_size != key_size
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "visit_map_keys_by_fd: key_size {key_size} does not match map key_size {}",
                info.key_size
            ),
        ));
    }

    let mut current_key = vec![0_u8; key_size as usize];
    let mut next_key = vec![0_u8; key_size as usize];
    let mut has_previous_key = false;
    let mut visited = 0_u64;

    loop {
        let key_ptr = if has_previous_key {
            current_key.as_ptr() as u64
        } else {
            0
        };
        let mut attr = BpfMapGetNextKeyAttr {
            map_fd: map_fd as u32,
            key: key_ptr,
            next_key: next_key.as_mut_ptr() as u64,
            ..BpfMapGetNextKeyAttr::default()
        };
        // SAFETY: current_key/next_key buffers are sized to the map key size and
        // remain valid for the duration of BPF_MAP_GET_NEXT_KEY.
        let status = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_GET_NEXT_KEY,
                &mut attr as *mut BpfMapGetNextKeyAttr,
                size_of::<BpfMapGetNextKeyAttr>(),
            )
        };
        if status < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(err);
        }
        visit(&next_key)?;
        visited += 1;
        if visited >= max_keys {
            break;
        }
        current_key.copy_from_slice(&next_key);
        has_previous_key = true;
    }

    Ok(visited)
}

pub fn map_keys_by_fd(map_fd: RawFd, key_size: u32) -> io::Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    let max_keys = map_info(map_fd)
        .map(|info| u64::from(info.max_entries))
        .unwrap_or(u64::MAX);
    visit_map_keys_by_fd(map_fd, key_size, max_keys, |key| {
        keys.push(key.to_vec());
        Ok(())
    })?;
    Ok(keys)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfIdAttr {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapUpdateElemAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapDeleteElemAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapLookupElemAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapGetNextKeyAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    next_key: u64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapInfo {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; 16],
    ifindex: u32,
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    padding: u32,
    map_extra: u64,
}
