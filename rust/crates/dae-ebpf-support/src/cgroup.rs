use std::fs;
use std::io;
use std::path::PathBuf;

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

    pub const fn go_attach_type(self) -> &'static str {
        match self {
            Self::SockCreate => "AttachCGroupInetSockCreate",
            Self::SockRelease => "AttachCgroupInetSockRelease",
            Self::Connect4 => "AttachCGroupInet4Connect",
            Self::Connect6 => "AttachCGroupInet6Connect",
            Self::Sendmsg4 => "AttachCGroupUDP4Sendmsg",
            Self::Sendmsg6 => "AttachCGroupUDP6Sendmsg",
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
    pub go_attach_type: &'static str,
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
        go_attach_type: role.go_attach_type(),
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
