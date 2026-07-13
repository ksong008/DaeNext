use super::*;

pub(in crate::production_runtime_owner) fn native_cgroup_attach_preflight() -> Result<Value, String>
{
    #[cfg(feature = "native-ebpf")]
    {
        let cgroup_path = detect_cgroup2_mount()
            .map_err(|error| format!("native eBPF cgroup2 mount detection failed: {error}"))?;
        let report = preflight_aya_cgroup_programs(&cgroup_path)?;
        Ok(cgroup_preflight_value(&report))
    }
    #[cfg(not(feature = "native-ebpf"))]
    {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }
}

#[cfg(feature = "native-ebpf")]
fn cgroup_preflight_value(report: &AyaCgroupAttachPreflightReport) -> Value {
    json!({
        "status": if report.compatible { "pass" } else { "fail" },
        "compatible": report.compatible,
        "cgroupPath": path_string(&report.cgroup_path),
        "requestedAttachMode": report.requested_attach_mode,
        "lines": report.lines.iter().map(|line| json!({
            "role": format!("{:?}", line.role),
            "attachType": line.attach_type,
            "attachFlags": line.attach_flags,
            "revision": line.revision,
            "compatible": line.compatible,
            "existingPrograms": line.existing_programs.iter().map(|program| json!({
                "id": program.id,
                "name": program.name,
                "tag": program.tag,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[cfg(feature = "native-ebpf")]
fn cgroup_incompatibility_error(report: &AyaCgroupAttachPreflightReport) -> String {
    let conflicts = report
        .lines
        .iter()
        .filter(|line| !line.compatible)
        .map(|line| {
            let programs = line
                .existing_programs
                .iter()
                .map(|program| match &program.name {
                    Some(name) => format!("{}({name})", program.id),
                    None => program.id.to_string(),
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "role={:?} attach_type={} attach_flags=0x{:x} programs=[{}]",
                line.role, line.attach_type, line.attach_flags, programs
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "cgroup preflight found an incompatible non-multi attachment at {}: {conflicts}; existing programs were not replaced",
        report.cgroup_path.display()
    )
}

impl NativeEbpfRuntimeState {
    #[cfg(not(feature = "native-ebpf"))]
    pub(super) fn try_attach_cgroup_programs(
        &mut self,
        _param_object: &Path,
    ) -> Result<(Value, Vec<Value>), String> {
        Err("native eBPF runtime feature is not compiled".to_owned())
    }

    #[cfg(feature = "native-ebpf")]
    pub(super) fn try_attach_cgroup_programs(
        &mut self,
        param_object: &Path,
    ) -> Result<(Value, Vec<Value>), String> {
        let cgroup_path = detect_cgroup2_mount()
            .map_err(|error| format!("native eBPF cgroup2 mount detection failed: {error}"))?;
        let preflight = preflight_aya_cgroup_programs(&cgroup_path)?;
        let preflight_value = cgroup_preflight_value(&preflight);
        if !preflight.compatible {
            return Err(cgroup_incompatibility_error(&preflight));
        }

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
                "program_id": report.program_id,
                "program_tag": report.program_tag,
                "section": report.section,
                "attach_type": report.attach_type,
                "program_kind": report.program_kind.as_str(),
                "attach_mode": report.attach_mode,
                "loaded": report.loaded,
                "attached": report.attached,
                "detached": report.detached,
                "link_lifetime_owned_by_backend": report.link_lifetime_owned_by_backend,
            }));
        }
        Ok((preflight_value, reports))
    }
}
