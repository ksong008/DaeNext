use std::collections::{BTreeMap, BTreeSet};

use aya::programs::loaded_programs;

use super::*;
use crate::{dae_cgroup_attach_matrix, query_cgroup_attachments};

pub fn preflight_aya_cgroup_programs(
    cgroup_path: &Path,
) -> Result<AyaCgroupAttachPreflightReport, String> {
    let snapshot = query_cgroup_attachments(cgroup_path, &dae_cgroup_attach_matrix())
        .map_err(|error| format!("query existing cgroup programs failed: {error}"))?;
    let requested_ids = snapshot
        .queries
        .iter()
        .flat_map(|query| query.program_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    let identities = loaded_programs()
        .filter_map(Result::ok)
        .filter(|info| requested_ids.contains(&info.id()))
        .map(|info| {
            (
                info.id(),
                AyaCgroupProgramIdentity {
                    id: info.id(),
                    name: info.name_as_str().map(str::to_owned),
                    tag: Some(format!("{:016x}", info.tag())),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let lines = snapshot
        .queries
        .into_iter()
        .map(|query| {
            let existing_programs = query
                .program_ids
                .iter()
                .map(|id| {
                    identities
                        .get(id)
                        .cloned()
                        .unwrap_or(AyaCgroupProgramIdentity {
                            id: *id,
                            name: None,
                            tag: None,
                        })
                })
                .collect::<Vec<_>>();
            AyaCgroupAttachPreflightLine {
                role: query.role,
                attach_type: query.attach_type,
                attach_flags: query.attach_flags,
                revision: query.revision,
                compatible: query.compatible_with_multiple_attach(),
                existing_programs,
            }
        })
        .collect::<Vec<_>>();
    Ok(AyaCgroupAttachPreflightReport {
        cgroup_path: snapshot.cgroup_path,
        requested_attach_mode: crate::CGROUP_ATTACH_MODE_MULTI_COMPATIBLE,
        compatible: lines.iter().all(|line| line.compatible),
        lines,
    })
}
