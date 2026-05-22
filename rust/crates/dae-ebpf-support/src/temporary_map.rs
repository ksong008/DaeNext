use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_uint = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
const BPF_OBJ_PIN: libc::c_uint = 6;
const BPF_OBJ_GET: libc::c_uint = 7;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_ANY: u64 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporaryBpfArrayMapSmoke {
    pub map_type: &'static str,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_name: &'static str,
    pub key_written: u32,
    pub value_written: u32,
    pub value_read: u32,
    pub pin_path: PathBuf,
    pub map_fd_reopened: bool,
    pub pin_removed: bool,
}

pub fn default_bpffs_mount() -> io::Result<PathBuf> {
    let mounts = fs::read_to_string("/proc/mounts")?;
    mounts
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let _source = fields.next()?;
            let target = fields.next()?;
            let fs_type = fields.next()?;
            (fs_type == "bpf").then(|| PathBuf::from(target))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "bpffs mount not found"))
}

pub fn run_temporary_array_map_pin_smoke(
    pin_root: &Path,
    pin_name: &str,
) -> io::Result<TemporaryBpfArrayMapSmoke> {
    let pin_path = pin_root.join(pin_name);
    if !pin_root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("BPF pin root does not exist: {}", pin_root.display()),
        ));
    }
    if pin_path.exists() {
        fs::remove_file(&pin_path)?;
    }

    let map_fd = create_array_map()?;
    let key = 0_u32;
    let value = 161_u32;
    update_map_elem(map_fd.as_raw_fd(), &key, &value)?;
    let value_read = lookup_map_elem(map_fd.as_raw_fd(), &key)?;
    if value_read != value {
        return Err(io::Error::other(format!(
            "temporary BPF map roundtrip mismatch: wrote {value}, read {value_read}"
        )));
    }

    pin_obj(map_fd.as_raw_fd(), &pin_path)?;
    let reopened = obj_get(&pin_path)?;
    let reopened_info_available = reopened.as_raw_fd() >= 0;
    fs::remove_file(&pin_path)?;
    let pin_removed = !pin_path.exists();

    Ok(TemporaryBpfArrayMapSmoke {
        map_type: "Array",
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        map_name: "dae_stg161",
        key_written: key,
        value_written: value,
        value_read,
        pin_path,
        map_fd_reopened: reopened_info_available,
        pin_removed,
    })
}

fn create_array_map() -> io::Result<OwnedFd> {
    let mut attr = BpfMapCreateAttr {
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        ..BpfMapCreateAttr::default()
    };
    attr.map_name[..10].copy_from_slice(b"dae_stg161");
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const BpfMapCreateAttr,
            size_of::<BpfMapCreateAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn update_map_elem(map_fd: i32, key: &u32, value: &u32) -> io::Result<()> {
    let attr = BpfMapElemAttr {
        map_fd: map_fd as u32,
        key: (key as *const u32) as u64,
        value: (value as *const u32) as u64,
        flags: BPF_ANY,
        ..BpfMapElemAttr::default()
    };
    bpf_zero_status(BPF_MAP_UPDATE_ELEM, &attr, size_of::<BpfMapElemAttr>())
}

fn lookup_map_elem(map_fd: i32, key: &u32) -> io::Result<u32> {
    let mut value = 0_u32;
    let attr = BpfMapElemAttr {
        map_fd: map_fd as u32,
        key: (key as *const u32) as u64,
        value: (&mut value as *mut u32) as u64,
        flags: BPF_ANY,
        ..BpfMapElemAttr::default()
    };
    bpf_zero_status(BPF_MAP_LOOKUP_ELEM, &attr, size_of::<BpfMapElemAttr>())?;
    Ok(value)
}

fn pin_obj(fd: i32, path: &Path) -> io::Result<()> {
    let path = c_path(path)?;
    let attr = BpfObjAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    bpf_zero_status(BPF_OBJ_PIN, &attr, size_of::<BpfObjAttr>())
}

fn obj_get(path: &Path) -> io::Result<OwnedFd> {
    let path = c_path(path)?;
    let attr = BpfObjAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &attr as *const BpfObjAttr,
            size_of::<BpfObjAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains NUL byte: {err}"),
        )
    })
}

fn bpf_zero_status<T>(cmd: libc::c_uint, attr: &T, size: usize) -> io::Result<()> {
    let status = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *const T, size) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfMapElemAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}
