use super::*;
#[cfg(feature = "native-ebpf")]
use std::sync::Mutex;

#[cfg(feature = "native-ebpf")]
static PNAME_CORE_ADMISSION_FAILURE: Mutex<Option<String>> = Mutex::new(None);
impl NativeEbpfRuntimeState {
    #[cfg(not(feature = "native-ebpf"))]
    pub(super) fn try_attach_program(
        &mut self,
        _options: &ProductionRuntimeOwnerOptions,
        _param_object: &Path,
        _role: NativeEbpfAttachRole,
        _backend: AttachBackend,
    ) -> Result<Value, String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn try_attach_program(
        &mut self,
        _options: &ProductionRuntimeOwnerOptions,
        param_object: &Path,
        role: NativeEbpfAttachRole,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let spec = native_attach_spec(role, param_object);
        self.try_attach_spec(param_object, spec, backend)
    }

    #[cfg(not(feature = "native-ebpf"))]
    pub(super) fn try_attach_resident_lan_program(
        &mut self,
        _param_object: &Path,
        _iface: &str,
        _link_layer: TcAttachLayer,
        _backend: AttachBackend,
    ) -> Result<Value, String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn try_attach_resident_lan_program(
        &mut self,
        param_object: &Path,
        iface: &str,
        link_layer: TcAttachLayer,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let object = path_string(param_object);
        let suffix = link_layer.suffix();
        let spec = TcBpfAttachSpec::new(
            TcAttachTarget::host(iface.to_owned(), TcAttachDirection::Ingress),
            ACTIVE_TCP_LAN_FILTER_PREF,
            object,
            format!("classifier/lan_ingress_{suffix}"),
        )
        .native_attach_spec(
            format!("tproxy_lan_ingress_{suffix}"),
            2,
            tc_handle(0x2023, 0b100),
        );
        self.try_attach_spec(param_object, spec, backend)
    }

    #[cfg(not(feature = "native-ebpf"))]
    pub(super) fn try_attach_interface_program(
        &mut self,
        _param_object: &Path,
        _iface: &str,
        _role: NativeInterfaceAttachRole,
        _link_layer: TcAttachLayer,
        _backend: AttachBackend,
    ) -> Result<Value, String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn try_attach_interface_program(
        &mut self,
        param_object: &Path,
        iface: &str,
        role: NativeInterfaceAttachRole,
        link_layer: TcAttachLayer,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let suffix = link_layer.suffix();
        let section_name = format!("{}_{suffix}", role.as_str());
        let spec = TcBpfAttachSpec::new(
            TcAttachTarget::host(iface.to_owned(), role.direction()),
            role.priority().to_string(),
            path_string(param_object),
            format!("classifier/{section_name}"),
        )
        .native_attach_spec(
            format!("tproxy_{section_name}"),
            role.priority(),
            tc_handle(0x2023, role.handle_minor()),
        );
        self.try_attach_spec(param_object, spec, backend)
    }

    #[cfg(not(feature = "native-ebpf"))]
    pub(super) fn try_attach_cgroup_programs(
        &mut self,
        _param_object: &Path,
    ) -> Result<Vec<Value>, String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn try_attach_cgroup_programs(
        &mut self,
        param_object: &Path,
    ) -> Result<Vec<Value>, String> {
        let cgroup_path = detect_cgroup2_mount()
            .map_err(|err| format!("native eBPF cgroup2 mount detection failed: {err}"))?;
        let mut reports = Vec::new();
        for line in dae_cgroup_attach_matrix() {
            let report = load_attach_aya_cgroup_program(
                self.ensure_loaded(param_object)?,
                &line,
                &cgroup_path,
            )?;
            reports.push(json!({
                "role": format!("{:?}", report.role),
                "cgroup_path": path_string(&report.cgroup_path),
                "program_name": report.program_name,
                "section": report.section,
                "program_kind": report.program_kind.as_str(),
                "attach_mode": report.attach_mode,
                "loaded": report.loaded,
                "attached": report.attached,
                "detached": report.detached,
                "link_lifetime_owned_by_backend": report.link_lifetime_owned_by_backend,
            }));
        }
        Ok(reports)
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn try_attach_spec(
        &mut self,
        param_object: &Path,
        spec: TcNativeAttachSpec,
        backend: AttachBackend,
    ) -> Result<Value, String> {
        let loaded = self.ensure_loaded(param_object)?;
        let report = dae_ebpf_support::load_attach_aya_sched_classifier(loaded, &spec, backend)?;
        let tcx_program_order = report
            .tcx_program_order
            .iter()
            .map(|entry| {
                json!({
                    "id": entry.id,
                    "name": entry.name,
                    "tag": entry.tag,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "requested_backend": report.requested_backend.as_str(),
            "backend": report.backend.as_str(),
            "backend_switch_used": report.backend_switch_used,
            "backend_switch_error": report.backend_switch_error,
            "program_id": report.program_id,
            "program_name": report.program_name,
            "iface": report.iface,
            "netns": report.netns,
            "netns_entered": report.netns_entered,
            "direction": report.direction.as_str(),
            "priority": report.priority,
            "handle": report.handle,
            "tcx_order": report.tcx_order.as_str(),
            "tcx_query_revision": report.tcx_query_revision,
            "tcx_program_order": tcx_program_order,
            "tcx_query_error": report.tcx_query_error,
            "tcx_order_verified": report.tcx_order_verified,
            "tcx_order_error": report.tcx_order_error,
            "clsact_added_or_present": report.clsact_added_or_present,
            "loaded": report.loaded,
            "attached": report.attached,
            "detached": report.detached,
            "link_lifetime_owned_by_backend": report.link_lifetime_owned_by_backend,
        }))
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn ensure_loaded(
        &mut self,
        _param_object: &Path,
    ) -> Result<&mut dae_ebpf_support::AyaUserspaceLoadedObject, String> {
        if self.loaded.is_none() {
            let runtime_pin_root = dae_ebpf_support::default_bpffs_mount()
                .map_err(|err| format!("native eBPF bpffs mount detection failed: {err}"))?
                .join(format!(
                    "dae-native-runtime-{}-{}",
                    std::process::id(),
                    self.pin_root.is_some() as u8
                ));
            std::fs::create_dir_all(&runtime_pin_root)
                .map_err(|err| format!("native eBPF pin root create failed: {err}"))?;
            let before_map_ids = dae_ebpf_support::map_ids()
                .map_err(|err| format!("native eBPF before-load map snapshot failed: {err}"))?;
            let input = self.load_input.clone().ok_or_else(|| {
                format!(
                    "native eBPF load input is missing for embedded object {}",
                    EMBEDDED_NATIVE_OBJECT_IDENTITY
                )
            })?;
            let (loaded, pname_report) =
                load_native_object_with_pname_fallback(&input, &runtime_pin_root)?;
            self.loaded_map_ids = collect_loaded_map_ids(&before_map_ids)?;
            self.pin_root = Some(runtime_pin_root);
            self.pname_report = Some(pname_report);
            self.loaded = Some(loaded);
        }
        self.loaded
            .as_mut()
            .ok_or_else(|| "native eBPF loader state was not initialized".to_owned())
    }
}

#[cfg(feature = "native-ebpf")]
fn load_native_object_with_pname_fallback(
    input: &NativeEbpfLoadInput,
    runtime_pin_root: &Path,
) -> Result<(dae_ebpf_support::AyaUserspaceLoadedObject, Value), String> {
    let default_pin_root = runtime_pin_root.join("default");
    let pname_core_pin_root = runtime_pin_root.join("pname-core");

    if let Some(reason) = cached_pname_core_admission_failure() {
        let loaded = load_default_native_object(input, &default_pin_root)?;
        return Ok((
            loaded,
            current_comm_pname_report_with_cached_fallback(reason),
        ));
    }

    match try_load_pname_core_object(input, &pname_core_pin_root) {
        Ok((loaded, report)) => Ok((loaded, report)),
        Err(reason) => {
            let _ = std::fs::remove_dir_all(&pname_core_pin_root);
            remember_pname_core_admission_failure(&reason);
            let loaded = load_default_native_object(input, &default_pin_root)?;
            Ok((
                loaded,
                current_comm_pname_report_with_fallback("fallback_to_current_comm", reason),
            ))
        }
    }
}

#[cfg(feature = "native-ebpf")]
fn try_load_pname_core_object(
    input: &NativeEbpfLoadInput,
    pin_root: &Path,
) -> Result<(dae_ebpf_support::AyaUserspaceLoadedObject, Value), String> {
    let target_btf = dae_ebpf_support::discover_aya_target_btf(true);
    let btf_report = target_btf_report_json(&target_btf.report);
    if target_btf.btf.is_none() {
        return Err(format!(
            "pname core target BTF unavailable: {}",
            target_btf_unavailable_reason(&target_btf.report)
        ));
    }
    let offsets = dae_ebpf_support::resolve_pname_btf_offsets(&target_btf.report)
        .map_err(|err| format!("pname core target BTF offset resolution failed: {err}"))?;
    let mut param = input.param;
    param.has_bpf_get_current_task = 1;
    param.task_struct_mm_offset = offsets.task_struct_mm_offset;
    param.mm_struct_arg_start_offset = offsets.mm_struct_arg_start_offset;
    let mut loaded = load_embedded_native_object(
        EMBEDDED_NATIVE_OBJECT_PNAME_CORE_IDENTITY,
        dae_ebpf_loader::embedded_native_aya_object_pname_core(),
        param,
        pin_root,
        true,
        input.map_profile.profile,
    )
    .map_err(|err| format!("pname core enhanced object load failed: {err}"))?;
    preload_pname_core_cgroup_programs(&mut loaded)
        .map_err(|err| format!("pname core cgroup admission failed: {err}"))?;
    Ok((
        loaded,
        json!({
            "source": "current_task_argv0_basename",
            "fallbackSource": "bpf_get_current_comm",
            "semantics": "argv0_basename",
            "coreEnabled": true,
            "nonCoreTaskCommEnabled": true,
            "currentTaskArgvEnabled": true,
            "officialArgvSemanticsImplemented": true,
            "coreStatus": "enhanced_load_succeeded",
            "pnameCoreTypeSource": "target_btf_offsets",
            "selectedObject": EMBEDDED_NATIVE_OBJECT_PNAME_CORE_IDENTITY,
            "targetBtf": btf_report,
            "offsets": {
                "task_struct_mm_offset": offsets.task_struct_mm_offset,
                "mm_struct_arg_start_offset": offsets.mm_struct_arg_start_offset,
            },
        }),
    ))
}

#[cfg(feature = "native-ebpf")]
fn preload_pname_core_cgroup_programs(
    loaded: &mut dae_ebpf_support::AyaUserspaceLoadedObject,
) -> Result<(), String> {
    for line in dae_ebpf_support::dae_cgroup_attach_matrix() {
        dae_ebpf_support::load_aya_cgroup_program_for_admission(loaded, &line)?;
    }
    Ok(())
}

#[cfg(feature = "native-ebpf")]
fn load_default_native_object(
    input: &NativeEbpfLoadInput,
    default_pin_root: &Path,
) -> Result<dae_ebpf_support::AyaUserspaceLoadedObject, String> {
    load_embedded_native_object(
        EMBEDDED_NATIVE_OBJECT_IDENTITY,
        dae_ebpf_loader::embedded_native_aya_object(),
        default_pname_param(input.param),
        default_pin_root,
        false,
        input.map_profile.profile,
    )
}

#[cfg(feature = "native-ebpf")]
fn load_embedded_native_object(
    object_label: &'static str,
    object_data: &'static [u8],
    param: BpfDaeParam,
    pin_root: &Path,
    target_btf_required: bool,
    map_profile: RuntimeMapProfile,
) -> Result<dae_ebpf_support::AyaUserspaceLoadedObject, String> {
    std::fs::create_dir_all(pin_root)
        .map_err(|err| format!("native eBPF pin root create failed: {err}"))?;
    dae_ebpf_support::load_aya_userspace_object_bytes(
        dae_ebpf_support::AyaUserspaceBytesLoaderOptions {
            object_label,
            object_data,
            param: Some(param),
            map_pin_path: Some(pin_root),
            allow_unsupported_maps: true,
            allowed_unsupported_map_names: dae_ebpf_support::DEFAULT_ALLOWED_UNSUPPORTED_MAP_NAMES,
            max_entries_overrides: map_profile.max_entries_overrides(),
            prepin_lpm_array_map: true,
            target_btf_required,
        },
    )
}

#[cfg(feature = "native-ebpf")]
fn default_pname_param(mut param: BpfDaeParam) -> BpfDaeParam {
    param.has_bpf_get_current_task = 0;
    param.task_struct_mm_offset = 0;
    param.mm_struct_arg_start_offset = 0;
    param
}

#[cfg(feature = "native-ebpf")]
fn current_comm_pname_report_with_fallback(status: &'static str, fallback_reason: String) -> Value {
    let mut value = current_comm_pname_report(status);
    if let Value::Object(map) = &mut value {
        map.insert("fallbackReason".to_owned(), json!(fallback_reason));
        map.insert(
            "selectedObject".to_owned(),
            json!(EMBEDDED_NATIVE_OBJECT_IDENTITY),
        );
    }
    value
}

#[cfg(feature = "native-ebpf")]
fn current_comm_pname_report_with_cached_fallback(fallback_reason: String) -> Value {
    let mut value = current_comm_pname_report("fallback_to_current_comm");
    if let Value::Object(map) = &mut value {
        map.insert(
            "fallbackReason".to_owned(),
            json!(format!(
                "pname core admission retry skipped after previous failure: {fallback_reason}"
            )),
        );
        map.insert("pnameCoreAdmissionFailureCached".to_owned(), json!(true));
        map.insert("pnameCoreAttemptSkipped".to_owned(), json!(true));
        map.insert(
            "selectedObject".to_owned(),
            json!(EMBEDDED_NATIVE_OBJECT_IDENTITY),
        );
    }
    value
}

#[cfg(feature = "native-ebpf")]
fn cached_pname_core_admission_failure() -> Option<String> {
    PNAME_CORE_ADMISSION_FAILURE
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

#[cfg(feature = "native-ebpf")]
fn remember_pname_core_admission_failure(reason: &str) {
    if !reason.contains("pname core cgroup admission failed") {
        return;
    }
    if let Ok(mut cached) = PNAME_CORE_ADMISSION_FAILURE.lock() {
        if cached.is_none() {
            *cached = Some(summarize_pname_core_failure(reason));
        }
    }
}

#[cfg(feature = "native-ebpf")]
fn summarize_pname_core_failure(reason: &str) -> String {
    const MAX_SUMMARY_BYTES: usize = 4096;
    if reason.len() <= MAX_SUMMARY_BYTES {
        return reason.to_owned();
    }
    let head = reason.lines().take(3).collect::<Vec<_>>().join("\n");
    let tail_start = reason
        .char_indices()
        .rev()
        .nth(MAX_SUMMARY_BYTES - 1)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    format!(
        "{head}\n... verifier log truncated for cached retry skip ...\n{}",
        &reason[tail_start..]
    )
}

#[cfg(feature = "native-ebpf")]
fn target_btf_unavailable_reason(report: &dae_ebpf_support::AyaTargetBtfReport) -> String {
    match (report.path.as_ref(), report.parse_error.as_ref()) {
        (Some(path), Some(err)) => format!("parse_failed path={} error={err}", path.display()),
        (Some(path), None) => format!("parse_failed path={}", path.display()),
        (None, _) => "missing_target_btf".to_owned(),
    }
}

#[cfg(feature = "native-ebpf")]
fn target_btf_report_json(report: &dae_ebpf_support::AyaTargetBtfReport) -> Value {
    json!({
        "required": report.required,
        "source": report.source.as_str(),
        "path": report.path.as_ref().map(|path| path_string(path)),
        "canonicalPath": report.canonical_path.as_ref().map(|path| path_string(path)),
        "parseOk": report.parse_ok,
        "parseError": report.parse_error,
        "candidatePaths": report
            .candidate_paths
            .iter()
            .map(|path| path_string(path))
            .collect::<Vec<_>>(),
    })
}
