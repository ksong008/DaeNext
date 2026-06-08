use super::*;
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

#[derive(Clone, Copy, Debug)]
pub(super) struct CreateBpfMapSpec {
    pub(super) name: &'static str,
    pub(super) map_type: u32,
    pub(super) key_size: u32,
    pub(super) value_size: u32,
    pub(super) max_entries: u32,
    pub(super) map_flags: u32,
    pub(super) inner_map_fd: i32,
}

pub(super) fn create_bpf_map(spec: CreateBpfMapSpec) -> io::Result<OwnedFd> {
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

pub(super) fn pin_obj(fd: i32, path: &Path) -> io::Result<()> {
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

pub(super) fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains NUL byte: {err}"),
        )
    })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct BpfMapCreateAttr {
    pub(super) map_type: u32,
    pub(super) key_size: u32,
    pub(super) value_size: u32,
    pub(super) max_entries: u32,
    pub(super) map_flags: u32,
    pub(super) inner_map_fd: u32,
    pub(super) numa_node: u32,
    pub(super) map_name: [u8; 16],
    pub(super) map_ifindex: u32,
    pub(super) btf_fd: u32,
    pub(super) btf_key_type_id: u32,
    pub(super) btf_value_type_id: u32,
    pub(super) btf_vmlinux_value_type_id: u32,
    pub(super) map_extra: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct BpfObjAttr {
    pub(super) pathname: u64,
    pub(super) bpf_fd: u32,
    pub(super) file_flags: u32,
}
