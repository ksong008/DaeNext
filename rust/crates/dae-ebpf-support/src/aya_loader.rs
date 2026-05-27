use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use aya::programs::{
    CgroupAttachMode, CgroupSock, CgroupSockAddr, LinkOrder, SchedClassifier, TcAttachType,
    tc::{self, NlOptions, SchedClassifierLinkId, TcAttachOptions},
};

use crate::{
    AttachBackend, BpfDaeParam, DaeCgroupAttachLine, DaeCgroupProgramKind, LoaderBackend,
    RuntimeMapRole, TcAttachDirection, TcNativeAttachSpec, map_catalog, pinned_reuse_maps,
};

const BPF_MAP_CREATE: libc::c_uint = 0;
const BPF_OBJ_PIN: libc::c_uint = 6;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
const BPF_F_NO_PREALLOC: u32 = 1;
const LPM_ARRAY_MAP_NAME: &str = "lpm_array_map";
const UNUSED_LPM_TYPE_NAME: &str = "unused_lpm_type";

unsafe impl aya::Pod for BpfDaeParam {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaUserspaceLoaderOptions<'a> {
    pub object: &'a Path,
    pub param: Option<BpfDaeParam>,
    pub map_pin_path: Option<&'a Path>,
    pub allow_unsupported_maps: bool,
    pub max_entries_overrides: &'a [(&'a str, u32)],
    pub prepin_lpm_array_map: bool,
}

impl<'a> AyaUserspaceLoaderOptions<'a> {
    pub fn new(object: &'a Path) -> Self {
        Self {
            object,
            param: None,
            map_pin_path: None,
            allow_unsupported_maps: true,
            max_entries_overrides: &[],
            prepin_lpm_array_map: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaMapInMapPinReport {
    pub outer_map_name: &'static str,
    pub inner_template_name: &'static str,
    pub pin_path: PathBuf,
    pub outer_max_entries: u32,
    pub inner_max_entries: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaUserspaceLoadReport {
    pub object: PathBuf,
    pub param_global_set: bool,
    pub map_pin_path: Option<PathBuf>,
    pub allow_unsupported_maps: bool,
    pub loaded_map_names: Vec<String>,
    pub loaded_program_names: Vec<String>,
    pub max_entries_overrides: Vec<(String, u32)>,
    pub map_in_map_pins: Vec<AyaMapInMapPinReport>,
    pub missing_catalog_maps: Vec<&'static str>,
    pub pinned_reuse_maps_present: Vec<String>,
    pub listen_socket_map_present: bool,
    pub loader_backend: LoaderBackend,
    pub default_attach_backend: AttachBackend,
    pub c_ebpf_object_fallback_required: bool,
    pub command_fallback_required: bool,
}

pub struct AyaUserspaceLoadedObject {
    pub ebpf: aya::Ebpf,
    pub report: AyaUserspaceLoadReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaTcAttachDetachReport {
    pub backend: AttachBackend,
    pub program_name: String,
    pub iface: String,
    pub netns: Option<String>,
    pub netns_entered: bool,
    pub direction: TcAttachDirection,
    pub priority: u16,
    pub handle: u32,
    pub clsact_added_or_present: bool,
    pub loaded: bool,
    pub attached: bool,
    pub detached: bool,
    pub link_lifetime_owned_by_backend: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaCgroupAttachDetachReport {
    pub role: crate::DaeCgroupAttachRole,
    pub cgroup_path: PathBuf,
    pub program_name: String,
    pub section: String,
    pub program_kind: DaeCgroupProgramKind,
    pub attach_mode: String,
    pub loaded: bool,
    pub attached: bool,
    pub detached: bool,
    pub link_lifetime_owned_by_backend: bool,
}

pub fn load_aya_userspace_object(
    options: AyaUserspaceLoaderOptions<'_>,
) -> Result<AyaUserspaceLoadedObject, String> {
    let map_in_map_pins = if options.prepin_lpm_array_map {
        let map_pin_path = options
            .map_pin_path
            .ok_or_else(|| "aya userspace lpm_array_map prepin requires map_pin_path".to_owned())?;
        vec![
            prepin_lpm_array_map(map_pin_path)
                .map_err(|err| format!("aya userspace lpm_array_map prepin failed: {err}"))?,
        ]
    } else {
        Vec::new()
    };

    let mut loader = aya::EbpfLoader::new();
    if options.allow_unsupported_maps {
        loader.allow_unsupported_maps();
    }
    if let Some(map_pin_path) = options.map_pin_path {
        loader.map_pin_path(map_pin_path);
    }
    if let Some(param) = options.param.as_ref() {
        loader.set_global("PARAM", param, true);
    }
    for (map_name, max_entries) in options.max_entries_overrides {
        loader.set_max_entries(map_name, *max_entries);
    }

    let ebpf = loader
        .load_file(options.object)
        .map_err(|err| format!("aya userspace object load failed: {err:?}"))?;
    let loaded_map_names = ebpf
        .maps()
        .map(|(name, _)| name.to_owned())
        .collect::<Vec<_>>();
    let loaded_program_names = ebpf
        .programs()
        .map(|(name, _)| name.to_owned())
        .collect::<Vec<_>>();
    let report = aya_userspace_load_report(
        options.object,
        options.param.is_some(),
        options.map_pin_path,
        options.allow_unsupported_maps,
        loaded_map_names,
        loaded_program_names,
        options.max_entries_overrides,
        map_in_map_pins,
    );
    Ok(AyaUserspaceLoadedObject { ebpf, report })
}

pub fn load_attach_detach_aya_sched_classifier(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<AyaTcAttachDetachReport, String> {
    if !matches!(backend, AttachBackend::TcNetlink | AttachBackend::Tcx) {
        return Err(format!(
            "aya sched classifier attach requires native backend, got {}",
            backend.as_str()
        ));
    }
    let mut report = with_optional_netns(spec.target.netns.as_deref(), || {
        load_attach_detach_aya_sched_classifier_in_current_netns(loaded, spec, backend)
    })?;
    report.netns = spec.target.netns.clone();
    report.netns_entered = spec.target.netns.is_some();
    Ok(report)
}

pub fn load_attach_aya_sched_classifier(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<AyaTcAttachDetachReport, String> {
    if !matches!(backend, AttachBackend::TcNetlink | AttachBackend::Tcx) {
        return Err(format!(
            "aya sched classifier attach requires native backend, got {}",
            backend.as_str()
        ));
    }
    let (mut report, _link_id) = with_optional_netns(spec.target.netns.as_deref(), || {
        load_attach_aya_sched_classifier_in_current_netns(loaded, spec, backend)
    })?;
    report.netns = spec.target.netns.clone();
    report.netns_entered = spec.target.netns.is_some();
    Ok(report)
}

pub fn load_attach_detach_aya_cgroup_program(
    loaded: &mut AyaUserspaceLoadedObject,
    line: &DaeCgroupAttachLine,
    cgroup_path: &Path,
) -> Result<AyaCgroupAttachDetachReport, String> {
    load_attach_aya_cgroup_program_with_mode(loaded, line, cgroup_path, true)
}

pub fn load_attach_aya_cgroup_program(
    loaded: &mut AyaUserspaceLoadedObject,
    line: &DaeCgroupAttachLine,
    cgroup_path: &Path,
) -> Result<AyaCgroupAttachDetachReport, String> {
    load_attach_aya_cgroup_program_with_mode(loaded, line, cgroup_path, false)
}

fn load_attach_aya_cgroup_program_with_mode(
    loaded: &mut AyaUserspaceLoadedObject,
    line: &DaeCgroupAttachLine,
    cgroup_path: &Path,
    detach_after_attach: bool,
) -> Result<AyaCgroupAttachDetachReport, String> {
    let cgroup = fs::File::open(cgroup_path)
        .map_err(|err| format!("open cgroup path {} failed: {err}", cgroup_path.display()))?;
    match line.aya_program_kind {
        DaeCgroupProgramKind::Sock => {
            let program = loaded.ebpf.program_mut(line.program_name).ok_or_else(|| {
                format!("aya cgroup sock program not found: {}", line.program_name)
            })?;
            let program: &mut CgroupSock = program
                .try_into()
                .map_err(|err| format!("aya program is not a cgroup sock program: {err:?}"))?;
            program
                .load()
                .map_err(|err| format!("aya cgroup sock load failed: {err:?}"))?;
            let link_id = program
                .attach(&cgroup, CgroupAttachMode::Single)
                .map_err(|err| format!("aya cgroup sock attach failed: {err:?}"))?;
            if detach_after_attach {
                program
                    .detach(link_id)
                    .map_err(|err| format!("aya cgroup sock detach failed: {err:?}"))?;
            }
        }
        DaeCgroupProgramKind::SockAddr => {
            let program = loaded.ebpf.program_mut(line.program_name).ok_or_else(|| {
                format!(
                    "aya cgroup sock_addr program not found: {}",
                    line.program_name
                )
            })?;
            let program: &mut CgroupSockAddr = program
                .try_into()
                .map_err(|err| format!("aya program is not a cgroup sock_addr program: {err:?}"))?;
            program
                .load()
                .map_err(|err| format!("aya cgroup sock_addr load failed: {err:?}"))?;
            let link_id = program
                .attach(&cgroup, CgroupAttachMode::Single)
                .map_err(|err| format!("aya cgroup sock_addr attach failed: {err:?}"))?;
            if detach_after_attach {
                program
                    .detach(link_id)
                    .map_err(|err| format!("aya cgroup sock_addr detach failed: {err:?}"))?;
            }
        }
    }
    Ok(AyaCgroupAttachDetachReport {
        role: line.role,
        cgroup_path: cgroup_path.to_owned(),
        program_name: line.program_name.to_owned(),
        section: line.section.to_owned(),
        program_kind: line.aya_program_kind,
        attach_mode: line.attach_mode.to_owned(),
        loaded: true,
        attached: true,
        detached: detach_after_attach,
        link_lifetime_owned_by_backend: line.link_lifetime_owned_by_backend,
    })
}

fn load_attach_detach_aya_sched_classifier_in_current_netns(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<AyaTcAttachDetachReport, String> {
    load_attach_aya_sched_classifier_in_current_netns(loaded, spec, backend).and_then(
        |(mut report, link_id)| {
            let program = loaded.ebpf.program_mut(&spec.program_name).ok_or_else(|| {
                format!(
                    "aya sched classifier program not found for detach: {}",
                    spec.program_name
                )
            })?;
            let classifier: &mut SchedClassifier = program.try_into().map_err(|err| {
                format!("aya program is not a sched classifier for detach: {err:?}")
            })?;
            classifier
                .detach(link_id)
                .map_err(|err| format!("aya sched classifier detach failed: {err:?}"))?;
            report.detached = true;
            Ok(report)
        },
    )
}

fn load_attach_aya_sched_classifier_in_current_netns(
    loaded: &mut AyaUserspaceLoadedObject,
    spec: &TcNativeAttachSpec,
    backend: AttachBackend,
) -> Result<(AyaTcAttachDetachReport, SchedClassifierLinkId), String> {
    if spec.clsact_required {
        add_clsact_or_accept_existing(&spec.target.iface)?;
    }
    let attach_type = match spec.target.direction {
        TcAttachDirection::Ingress => TcAttachType::Ingress,
        TcAttachDirection::Egress => TcAttachType::Egress,
    };
    let program = loaded.ebpf.program_mut(&spec.program_name).ok_or_else(|| {
        format!(
            "aya sched classifier program not found: {}",
            spec.program_name
        )
    })?;
    let classifier: &mut SchedClassifier = program
        .try_into()
        .map_err(|err| format!("aya program is not a sched classifier: {err:?}"))?;
    classifier
        .load()
        .map_err(|err| format!("aya sched classifier load failed: {err:?}"))?;
    let attach_options = match backend {
        AttachBackend::TcNetlink => TcAttachOptions::Netlink(NlOptions {
            priority: spec.priority,
            handle: spec.handle,
        }),
        AttachBackend::Tcx => TcAttachOptions::TcxOrder(LinkOrder::default()),
        _ => unreachable!(),
    };
    let link_id = classifier
        .attach_with_options(&spec.target.iface, attach_type, attach_options)
        .map_err(|err| format!("aya sched classifier attach failed: {err:?}"))?;

    Ok((
        AyaTcAttachDetachReport {
            backend,
            program_name: spec.program_name.clone(),
            iface: spec.target.iface.clone(),
            netns: None,
            netns_entered: false,
            direction: spec.target.direction,
            priority: spec.priority,
            handle: spec.handle,
            clsact_added_or_present: spec.clsact_required,
            loaded: true,
            attached: true,
            detached: false,
            link_lifetime_owned_by_backend: spec.link_lifetime_owned_by_backend,
        },
        link_id,
    ))
}

fn with_optional_netns<T>(
    netns: Option<&str>,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let Some(netns) = netns else {
        return f();
    };
    let mut guard = NetnsGuard::enter(netns)?;
    let result = f();
    let restore_result = guard.restore();
    match (result, restore_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(restore_err)) => Err(format!(
            "{err}; additionally failed to restore original netns after {netns}: {restore_err}"
        )),
    }
}

struct NetnsGuard {
    original: fs::File,
    restored: bool,
}

impl NetnsGuard {
    fn enter(netns: &str) -> Result<Self, String> {
        let original = fs::File::open("/proc/self/ns/net")
            .map_err(|err| format!("open current netns failed: {err}"))?;
        let target_path = netns_path(netns);
        let target = fs::File::open(&target_path)
            .map_err(|err| format!("open target netns {} failed: {err}", target_path.display()))?;
        setns(target.as_raw_fd())
            .map_err(|err| format!("enter target netns {} failed: {err}", target_path.display()))?;
        Ok(Self {
            original,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        if self.restored {
            return Ok(());
        }
        setns(self.original.as_raw_fd())
            .map_err(|err| format!("restore original netns failed: {err}"))?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn netns_path(netns: &str) -> PathBuf {
    let path = Path::new(netns);
    if path.is_absolute() {
        path.to_owned()
    } else {
        Path::new("/var/run/netns").join(netns)
    }
}

fn setns(fd: i32) -> io::Result<()> {
    let status = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn add_clsact_or_accept_existing(iface: &str) -> Result<(), String> {
    match tc::qdisc_add_clsact(iface) {
        Ok(()) => Ok(()),
        Err(err)
            if err.kind() == io::ErrorKind::AlreadyExists
                || err.raw_os_error() == Some(libc::EEXIST) =>
        {
            Ok(())
        }
        Err(err) => Err(format!("aya tc clsact qdisc add failed on {iface}: {err}")),
    }
}

pub fn prepin_lpm_array_map(pin_root: &Path) -> io::Result<AyaMapInMapPinReport> {
    fs::create_dir_all(pin_root)?;
    let pin_path = pin_root.join(LPM_ARRAY_MAP_NAME);
    if pin_path.exists() {
        fs::remove_file(&pin_path)?;
    }
    let inner_max_entries = map_catalog()
        .iter()
        .find(|spec| spec.name == UNUSED_LPM_TYPE_NAME)
        .map(|spec| spec.max_entries)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "unused_lpm_type catalog missing")
        })?;
    let outer_max_entries = map_catalog()
        .iter()
        .find(|spec| spec.name == LPM_ARRAY_MAP_NAME)
        .map(|spec| spec.max_entries)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lpm_array_map catalog missing"))?;
    let inner = create_bpf_map(CreateBpfMapSpec {
        name: UNUSED_LPM_TYPE_NAME,
        map_type: BPF_MAP_TYPE_LPM_TRIE,
        key_size: 20,
        value_size: 4,
        max_entries: inner_max_entries,
        map_flags: BPF_F_NO_PREALLOC,
        inner_map_fd: 0,
    })?;
    let outer = create_bpf_map(CreateBpfMapSpec {
        name: LPM_ARRAY_MAP_NAME,
        map_type: BPF_MAP_TYPE_ARRAY_OF_MAPS,
        key_size: 4,
        value_size: 4,
        max_entries: outer_max_entries,
        map_flags: 0,
        inner_map_fd: inner.as_raw_fd(),
    })?;
    pin_obj(outer.as_raw_fd(), &pin_path)?;
    Ok(AyaMapInMapPinReport {
        outer_map_name: LPM_ARRAY_MAP_NAME,
        inner_template_name: UNUSED_LPM_TYPE_NAME,
        pin_path,
        outer_max_entries,
        inner_max_entries,
    })
}

pub fn aya_userspace_load_report(
    object: &Path,
    param_global_set: bool,
    map_pin_path: Option<&Path>,
    allow_unsupported_maps: bool,
    mut loaded_map_names: Vec<String>,
    mut loaded_program_names: Vec<String>,
    max_entries_overrides: &[(&str, u32)],
    map_in_map_pins: Vec<AyaMapInMapPinReport>,
) -> AyaUserspaceLoadReport {
    loaded_map_names.sort();
    loaded_program_names.sort();
    let missing_catalog_maps = map_catalog()
        .iter()
        .filter(|spec| !loaded_map_names.iter().any(|name| name == spec.name))
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    let pinned_reuse_maps_present = pinned_reuse_maps()
        .iter()
        .filter(|name| loaded_map_names.iter().any(|loaded| loaded == **name))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    AyaUserspaceLoadReport {
        object: object.to_owned(),
        param_global_set,
        map_pin_path: map_pin_path.map(Path::to_owned),
        allow_unsupported_maps,
        max_entries_overrides: max_entries_overrides
            .iter()
            .map(|(name, max_entries)| ((*name).to_owned(), *max_entries))
            .collect(),
        map_in_map_pins,
        listen_socket_map_present: loaded_map_names
            .iter()
            .any(|name| RuntimeMapRole::for_map_name(name) == RuntimeMapRole::SocketHandoff),
        loaded_map_names,
        loaded_program_names,
        missing_catalog_maps,
        pinned_reuse_maps_present,
        loader_backend: LoaderBackend::AyaUserspace,
        default_attach_backend: AttachBackend::TcCommandFallback,
        c_ebpf_object_fallback_required: true,
        command_fallback_required: true,
    }
}

#[derive(Clone, Copy, Debug)]
struct CreateBpfMapSpec {
    name: &'static str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: i32,
}

fn create_bpf_map(spec: CreateBpfMapSpec) -> io::Result<OwnedFd> {
    let mut attr = BpfMapCreateAttr {
        map_type: spec.map_type,
        key_size: spec.key_size,
        value_size: spec.value_size,
        max_entries: spec.max_entries,
        map_flags: spec.map_flags,
        inner_map_fd: spec.inner_map_fd as u32,
        ..BpfMapCreateAttr::default()
    };
    let name = spec.name.as_bytes();
    let copy_len = name.len().min(attr.map_name.len() - 1);
    attr.map_name[..copy_len].copy_from_slice(&name[..copy_len]);
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const BpfMapCreateAttr,
            std::mem::size_of::<BpfMapCreateAttr>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn pin_obj(fd: i32, path: &Path) -> io::Result<()> {
    let path = c_path(path)?;
    let attr = BpfObjAttr {
        pathname: path.as_ptr() as u64,
        bpf_fd: fd as u32,
        file_flags: 0,
    };
    let status = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_PIN,
            &attr as *const BpfObjAttr,
            std::mem::size_of::<BpfObjAttr>(),
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains NUL byte: {err}"),
        )
    })
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
struct BpfObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}
