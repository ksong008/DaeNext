use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use aya::maps::RingBuf;
use aya::programs::{
    CgroupAttachMode, CgroupSock, CgroupSockAddr, LinkOrder, Program, SchedClassifier,
    TcAttachType,
    links::FdLink,
    tc::{self, NlOptions, SchedClassifierLinkId, TcAttachOptions},
};

use crate::{
    AttachBackend, BpfDaeParam, DaeCgroupAttachLine, DaeCgroupProgramKind, LoaderBackend,
    RuntimeMapRole, TcAttachDirection, TcNativeAttachSpec, TcxAttachOrder, map_catalog,
    pinned_reuse_maps, trace_core_sideload_gate_report,
};

include!("aya_loader/types.rs");
include!("aya_loader/load_object.rs");
include!("aya_loader/trace.rs");
include!("aya_loader/tc_attach.rs");
include!("aya_loader/cgroup.rs");
include!("aya_loader/netns.rs");
include!("aya_loader/lpm_pinning.rs");
include!("aya_loader/report.rs");
include!("aya_loader/common_helpers.rs");
