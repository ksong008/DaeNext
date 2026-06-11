use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeCgroupProgramKind {
    Sock,
    SockAddr,
}

impl DaeCgroupProgramKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sock => "cgroup_sock",
            Self::SockAddr => "cgroup_sock_addr",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaeCgroupAttachRole {
    SockCreate,
    SockRelease,
    Connect4,
    Connect6,
    Sendmsg4,
    Sendmsg6,
}

impl DaeCgroupAttachRole {
    pub const fn section_tail(self) -> &'static str {
        match self {
            Self::SockCreate => "sock_create",
            Self::SockRelease => "sock_release",
            Self::Connect4 => "connect4",
            Self::Connect6 => "connect6",
            Self::Sendmsg4 => "sendmsg4",
            Self::Sendmsg6 => "sendmsg6",
        }
    }

    pub const fn program_name(self) -> &'static str {
        match self {
            Self::SockCreate => "tproxy_wan_cg_sock_create",
            Self::SockRelease => "tproxy_wan_cg_sock_release",
            Self::Connect4 => "tproxy_wan_cg_connect4",
            Self::Connect6 => "tproxy_wan_cg_connect6",
            Self::Sendmsg4 => "tproxy_wan_cg_sendmsg4",
            Self::Sendmsg6 => "tproxy_wan_cg_sendmsg6",
        }
    }

    pub const fn attach_type(self) -> &'static str {
        match self {
            Self::SockCreate => "AttachCGroupInetSockCreate",
            Self::SockRelease => "AttachCgroupInetSockRelease",
            Self::Connect4 => "AttachCGroupInet4Connect",
            Self::Connect6 => "AttachCGroupInet6Connect",
            Self::Sendmsg4 => "AttachCGroupUDP4Sendmsg",
            Self::Sendmsg6 => "AttachCGroupUDP6Sendmsg",
        }
    }

    pub const fn bpf_attach_type(self) -> u32 {
        match self {
            Self::SockCreate => 2,
            Self::Connect4 => 10,
            Self::Connect6 => 11,
            Self::Sendmsg4 => 14,
            Self::Sendmsg6 => 15,
            Self::SockRelease => 34,
        }
    }

    pub const fn program_kind(self) -> DaeCgroupProgramKind {
        match self {
            Self::SockCreate | Self::SockRelease => DaeCgroupProgramKind::Sock,
            Self::Connect4 | Self::Connect6 | Self::Sendmsg4 | Self::Sendmsg6 => {
                DaeCgroupProgramKind::SockAddr
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeCgroupAttachLine {
    pub role: DaeCgroupAttachRole,
    pub section: &'static str,
    pub program_name: &'static str,
    pub attach_type: &'static str,
    pub aya_program_kind: DaeCgroupProgramKind,
    pub attach_mode: &'static str,
    pub link_lifetime_owned_by_backend: bool,
}

pub fn dae_cgroup_attach_matrix() -> Vec<DaeCgroupAttachLine> {
    [
        DaeCgroupAttachRole::SockCreate,
        DaeCgroupAttachRole::SockRelease,
        DaeCgroupAttachRole::Connect4,
        DaeCgroupAttachRole::Connect6,
        DaeCgroupAttachRole::Sendmsg4,
        DaeCgroupAttachRole::Sendmsg6,
    ]
    .into_iter()
    .map(|role| DaeCgroupAttachLine {
        role,
        section: match role {
            DaeCgroupAttachRole::SockCreate => "cgroup/sock_create",
            DaeCgroupAttachRole::SockRelease => "cgroup/sock_release",
            DaeCgroupAttachRole::Connect4 => "cgroup/connect4",
            DaeCgroupAttachRole::Connect6 => "cgroup/connect6",
            DaeCgroupAttachRole::Sendmsg4 => "cgroup/sendmsg4",
            DaeCgroupAttachRole::Sendmsg6 => "cgroup/sendmsg6",
        },
        program_name: role.program_name(),
        attach_type: role.attach_type(),
        aya_program_kind: role.program_kind(),
        attach_mode: "single",
        link_lifetime_owned_by_backend: true,
    })
    .collect()
}

pub fn detect_cgroup2_mount() -> io::Result<PathBuf> {
    let mounts = fs::read_to_string("/proc/mounts")?;
    detect_cgroup2_mount_from_proc_mounts(&mounts)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cgroup2 not mounted"))
}

pub fn detect_cgroup2_mount_from_proc_mounts(mounts: &str) -> Option<PathBuf> {
    mounts.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 3 && fields[2] == "cgroup2" {
            Some(PathBuf::from(fields[1]))
        } else {
            None
        }
    })
}

pub struct PinnedCgroupAttachOptions<'a> {
    pub program_root: &'a Path,
    pub link_root: &'a Path,
    pub cgroup_path: &'a Path,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedCgroupAttachReport {
    pub role: DaeCgroupAttachRole,
    pub cgroup_path: PathBuf,
    pub program_name: String,
    pub program_path: PathBuf,
    pub link_path: PathBuf,
    pub section: String,
    pub attach_type: u32,
    pub attach_mode: String,
    pub attached: bool,
    pub pinned: bool,
}

pub fn attach_pin_cgroup_monitor(
    options: PinnedCgroupAttachOptions<'_>,
) -> Result<Vec<PinnedCgroupAttachReport>, String> {
    if options.link_root.exists() {
        return Err(format!(
            "cgroup link root already exists: {}",
            options.link_root.display()
        ));
    }
    fs::create_dir_all(options.link_root).map_err(|err| {
        format!(
            "create cgroup link root {} failed: {err}",
            options.link_root.display()
        )
    })?;

    let mut reports = Vec::new();
    for line in dae_cgroup_attach_matrix() {
        let result = attach_pin_one_cgroup_line(&options, &line);
        match result {
            Ok(report) => reports.push(report),
            Err(err) => {
                let _ = fs::remove_dir_all(options.link_root);
                return Err(err);
            }
        }
    }
    Ok(reports)
}

fn attach_pin_one_cgroup_line(
    options: &PinnedCgroupAttachOptions<'_>,
    line: &DaeCgroupAttachLine,
) -> Result<PinnedCgroupAttachReport, String> {
    let program_path = options.program_root.join(line.program_name);
    let link_path = options.link_root.join(line.program_name);
    let program_fd = bpf_obj_get(&program_path)?;
    let cgroup_file = fs::File::open(options.cgroup_path).map_err(|err| {
        format!(
            "open cgroup path {} failed: {err}",
            options.cgroup_path.display()
        )
    })?;
    let link_fd = bpf_link_create(
        program_fd.as_raw_fd(),
        cgroup_file.as_raw_fd(),
        line.role.bpf_attach_type(),
    )?;
    bpf_obj_pin(link_fd.as_raw_fd(), &link_path)?;
    Ok(PinnedCgroupAttachReport {
        role: line.role,
        cgroup_path: options.cgroup_path.to_owned(),
        program_name: line.program_name.to_owned(),
        program_path,
        link_path,
        section: line.section.to_owned(),
        attach_type: line.role.bpf_attach_type(),
        attach_mode: line.attach_mode.to_owned(),
        attached: true,
        pinned: true,
    })
}

#[repr(C)]
#[derive(Default)]
struct BpfAttrObj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct BpfAttrLinkCreate {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    extra: [u64; 8],
}

const BPF_OBJ_PIN: u32 = 6;
const BPF_OBJ_GET: u32 = 7;
const BPF_LINK_CREATE: u32 = 28;

fn bpf_obj_get(path: &Path) -> Result<OwnedFd, String> {
    let path = c_path(path)?;
    let attr = BpfAttrObj {
        pathname: path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    let fd = bpf_syscall(BPF_OBJ_GET, &attr)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bpf_obj_pin(fd: i32, path: &Path) -> Result<(), String> {
    let path = c_path(path)?;
    let attr = BpfAttrObj {
        pathname: path.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    bpf_syscall(BPF_OBJ_PIN, &attr).map(|_| ())
}

fn bpf_link_create(prog_fd: i32, target_fd: i32, attach_type: u32) -> Result<OwnedFd, String> {
    let attr = BpfAttrLinkCreate {
        prog_fd: prog_fd as u32,
        target_fd: target_fd as u32,
        attach_type,
        flags: 0,
        extra: [0; 8],
    };
    let fd = bpf_syscall(BPF_LINK_CREATE, &attr)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bpf_syscall<T>(cmd: u32, attr: &T) -> Result<i32, String> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *const T as *const libc::c_void,
            std::mem::size_of::<T>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(ret as i32)
    }
}

fn c_path(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes()).map_err(|err| {
        format!(
            "path {} contains an interior NUL byte: {err}",
            path.display()
        )
    })
}
