use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::os::fd::{FromRawFd, OwnedFd};

const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_MAP_LOOKUP_ELEM: libc::c_uint = 1;
const BPF_MAP_GET_NEXT_ID: libc::c_uint = 12;
const BPF_MAP_GET_NEXT_KEY: libc::c_uint = 4;
const BPF_MAP_GET_FD_BY_ID: libc::c_uint = 14;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_uint = 15;
const BPF_ANY: u64 = 0;

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

pub fn map_ids() -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    let mut start_id = 0;
    loop {
        let mut attr = BpfIdAttr {
            start_id,
            ..BpfIdAttr::default()
        };
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
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub fn map_info(fd: i32) -> io::Result<RuntimeMapInfo> {
    let mut info = BpfMapInfo::default();
    let attr = BpfInfoAttr {
        bpf_fd: fd as u32,
        info_len: size_of::<BpfMapInfo>() as u32,
        info: (&mut info as *mut BpfMapInfo) as u64,
    };
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

pub fn update_map_elem_bytes(map_fd: RawFd, key: &[u8], value: &[u8]) -> io::Result<()> {
    let attr = BpfMapUpdateElemAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        value: value.as_ptr() as u64,
        flags: BPF_ANY,
        ..BpfMapUpdateElemAttr::default()
    };
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

pub fn lookup_map_elem_bytes(map_fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<()> {
    let attr = BpfMapLookupElemAttr {
        map_fd: map_fd as u32,
        key: key.as_ptr() as u64,
        value: value.as_mut_ptr() as u64,
        ..BpfMapLookupElemAttr::default()
    };
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
    if info.key_size == 0 {
        return Ok(0);
    }

    let mut current_key = vec![0_u8; info.key_size as usize];
    let mut next_key = vec![0_u8; info.key_size as usize];
    let mut has_previous_key = false;
    let mut count = 0_u64;

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
        count += 1;
        current_key.copy_from_slice(&next_key);
        has_previous_key = true;
    }

    Ok(count)
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
