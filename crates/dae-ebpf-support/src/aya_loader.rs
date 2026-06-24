use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use aya::maps::{Map, MapData, MapType, RingBuf};
use aya::programs::{
    CgroupAttachMode, CgroupSock, CgroupSockAddr, LinkOrder, Program, ProgramError,
    SchedClassifier, TcAttachType,
    links::FdLink,
    tc::{self, NlOptions, SchedClassifierLinkId, TcAttachOptions},
};

use crate::{
    AttachBackend, BpfDaeParam, DaeCgroupAttachLine, DaeCgroupProgramKind, LoaderBackend,
    RuntimeMapRole, TcAttachDirection, TcNativeAttachSpec, TcxAttachOrder, map_catalog,
    pinned_reuse_maps, trace_core_sideload_gate_report,
};

mod types;
pub use self::types::*;
mod load_object;
pub use self::load_object::*;
mod trace;
pub use self::trace::*;
mod tc_attach;
pub use self::tc_attach::*;
mod cgroup;
pub use self::cgroup::*;
mod netns;
use self::netns::*;
mod lpm_pinning;
pub use self::lpm_pinning::*;
mod target_btf;
pub use self::target_btf::*;
mod report;
pub use self::report::*;
mod common_helpers;
use self::common_helpers::*;
