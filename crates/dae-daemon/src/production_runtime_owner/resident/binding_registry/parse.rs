use super::*;

pub(super) fn registry_from_startup_steps(
    generation: u64,
    steps: &[Value],
) -> Result<ResidentDatapathBindingRegistry, String> {
    let mut registry = ResidentDatapathBindingRegistry::empty(generation);
    for step in steps
        .iter()
        .filter(|step| step["status"].as_str() == Some("pass"))
    {
        if let Some(attach) = step.get("native_attach") {
            registry.tc.push(parse_tc_binding(step, attach)?);
        }
        if step["name"].as_str() == Some("attach-native-ebpf-cgroup-programs") {
            registry.cgroup.extend(parse_cgroup_bindings(step)?);
        }
    }
    Ok(registry)
}

fn parse_tc_binding(step: &Value, attach: &Value) -> Result<ResidentTcBinding, String> {
    if attach["attached"].as_bool() != Some(true) || attach["detached"].as_bool() == Some(true) {
        return Err("resident TC binding report is not live after attach".to_owned());
    }
    let role = required_str(step, "role").and_then(ResidentDatapathBindingRole::parse)?;
    let backend = required_str(attach, "backend").and_then(ResidentTcBindingBackend::parse)?;
    let direction = match required_str(attach, "direction")? {
        "ingress" => dae_ebpf_support::TcAttachDirection::Ingress,
        "egress" => dae_ebpf_support::TcAttachDirection::Egress,
        other => return Err(format!("invalid resident TC binding direction {other:?}")),
    };
    let program_id = required_u32(attach, "program_id")?;
    let tcx_anchor = attach.get("tcx_anchor").filter(|value| !value.is_null());
    let foreign_program_order_before = attach["tcx_pre_program_order"]
        .as_array()
        .map(|programs| {
            programs
                .iter()
                .filter_map(|program| program["id"].as_u64().map(|id| id as u32))
                .filter(|id| *id != program_id)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(ResidentTcBinding {
        role,
        backend,
        interface: required_str(attach, "iface")?.to_owned(),
        ifindex: required_u32(attach, "ifindex")?,
        netns: attach["netns"].as_str().map(str::to_owned),
        direction,
        program_id,
        program_name: required_str(attach, "program_name")?.to_owned(),
        program_tag: required_str(attach, "program_tag")?.to_owned(),
        priority: required_u16(attach, "priority")?,
        handle: required_u32(attach, "handle")?,
        tcx_order: required_str(attach, "tcx_order")?.to_owned(),
        tcx_anchor_relation: tcx_anchor
            .and_then(|anchor| anchor["relation"].as_str())
            .map(str::to_owned),
        tcx_anchor_program_id: tcx_anchor
            .and_then(|anchor| anchor["program_id"].as_u64())
            .map(|id| id as u32),
        foreign_program_order_before,
    })
}

fn parse_cgroup_bindings(step: &Value) -> Result<Vec<ResidentCgroupBinding>, String> {
    let programs = step["programs"]
        .as_array()
        .ok_or_else(|| "resident cgroup attach report has no program rows".to_owned())?;
    let preflight_lines = step
        .pointer("/preflight/lines")
        .and_then(Value::as_array)
        .ok_or_else(|| "resident cgroup attach report has no preflight rows".to_owned())?;
    programs
        .iter()
        .map(|program| {
            if program["attached"].as_bool() != Some(true)
                || program["detached"].as_bool() == Some(true)
            {
                return Err("resident cgroup binding report is not live after attach".to_owned());
            }
            let role = required_str(program, "role")?.to_owned();
            let attach_type = required_u32(program, "attach_type")?;
            let foreign_program_ids_before = preflight_lines
                .iter()
                .find(|line| {
                    line["role"].as_str() == Some(role.as_str())
                        && line["attachType"].as_u64() == Some(u64::from(attach_type))
                })
                .and_then(|line| line["existingPrograms"].as_array())
                .map(|programs| {
                    programs
                        .iter()
                        .filter_map(|program| program["id"].as_u64().map(|id| id as u32))
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
            Ok(ResidentCgroupBinding {
                role,
                cgroup_path: PathBuf::from(required_str(program, "cgroup_path")?),
                attach_type,
                program_id: required_u32(program, "program_id")?,
                program_name: required_str(program, "program_name")?.to_owned(),
                program_tag: required_str(program, "program_tag")?.to_owned(),
                attach_mode: required_str(program, "attach_mode")?.to_owned(),
                foreign_program_ids_before,
            })
        })
        .collect()
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("resident binding field {field} is missing or empty"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("resident binding field {field} is missing or invalid"))
}

fn required_u32(value: &Value, field: &str) -> Result<u32, String> {
    u32::try_from(required_u64(value, field)?)
        .map_err(|_| format!("resident binding field {field} exceeds u32"))
}

fn required_u16(value: &Value, field: &str) -> Result<u16, String> {
    u16::try_from(required_u64(value, field)?)
        .map_err(|_| format!("resident binding field {field} exceeds u16"))
}
