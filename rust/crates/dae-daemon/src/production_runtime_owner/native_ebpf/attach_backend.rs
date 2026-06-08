use super::*;
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
            "fallback_used": report.fallback_used,
            "fallback_error": report.fallback_error,
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
        param_object: &Path,
    ) -> Result<&mut dae_ebpf_support::AyaUserspaceLoadedObject, String> {
        if self.loaded.is_none() {
            let pin_root = dae_ebpf_support::default_bpffs_mount()
                .map_err(|err| format!("native eBPF bpffs mount detection failed: {err}"))?
                .join(format!(
                    "dae-native-runtime-{}-{}",
                    std::process::id(),
                    self.pin_root.is_some() as u8
                ));
            std::fs::create_dir_all(&pin_root)
                .map_err(|err| format!("native eBPF pin root create failed: {err}"))?;
            let before_map_ids = dae_ebpf_support::map_ids()
                .map_err(|err| format!("native eBPF before-load map snapshot failed: {err}"))?;
            let loaded = dae_ebpf_support::load_aya_userspace_object(
                dae_ebpf_support::AyaUserspaceLoaderOptions {
                    object: param_object,
                    param: None,
                    map_pin_path: Some(&pin_root),
                    allow_unsupported_maps: true,
                    max_entries_overrides: &[],
                    prepin_lpm_array_map: true,
                },
            )?;
            self.loaded_map_ids = collect_loaded_map_ids(&before_map_ids)?;
            self.pin_root = Some(pin_root);
            self.loaded = Some(loaded);
        }
        self.loaded
            .as_mut()
            .ok_or_else(|| "native eBPF loader state was not initialized".to_owned())
    }
}
