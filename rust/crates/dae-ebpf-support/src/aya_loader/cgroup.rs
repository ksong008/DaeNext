use super::*;
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

pub(super) fn load_attach_aya_cgroup_program_with_mode(
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
