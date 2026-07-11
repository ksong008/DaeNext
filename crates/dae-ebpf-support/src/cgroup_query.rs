use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::{DaeCgroupAttachLine, DaeCgroupAttachRole};

const BPF_PROG_QUERY: u32 = 16;
pub const CGROUP_ATTACH_FLAG_ALLOW_MULTIPLE: u32 = 2;
const INITIAL_PROGRAM_ID_CAPACITY: usize = 64;
const MAX_PROGRAM_ID_CAPACITY: usize = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupAttachmentQuery {
    pub role: DaeCgroupAttachRole,
    pub attach_type: u32,
    pub attach_flags: u32,
    pub revision: u64,
    pub program_ids: Vec<u32>,
}

impl CgroupAttachmentQuery {
    pub fn compatible_with_multiple_attach(&self) -> bool {
        self.program_ids.is_empty() || self.attach_flags & CGROUP_ATTACH_FLAG_ALLOW_MULTIPLE != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupAttachmentSnapshot {
    pub cgroup_path: PathBuf,
    pub queries: Vec<CgroupAttachmentQuery>,
}

impl CgroupAttachmentSnapshot {
    pub fn compatible_with_multiple_attach(&self) -> bool {
        self.queries
            .iter()
            .all(CgroupAttachmentQuery::compatible_with_multiple_attach)
    }
}

pub fn query_cgroup_attachments(
    cgroup_path: &Path,
    lines: &[DaeCgroupAttachLine],
) -> io::Result<CgroupAttachmentSnapshot> {
    let cgroup = fs::File::open(cgroup_path)?;
    let mut queries = Vec::with_capacity(lines.len());
    for line in lines {
        queries.push(query_cgroup_attachment(&cgroup, line)?);
    }
    Ok(CgroupAttachmentSnapshot {
        cgroup_path: cgroup_path.to_owned(),
        queries,
    })
}

fn query_cgroup_attachment(
    cgroup: &fs::File,
    line: &DaeCgroupAttachLine,
) -> io::Result<CgroupAttachmentQuery> {
    let mut program_ids = vec![0_u32; INITIAL_PROGRAM_ID_CAPACITY];
    loop {
        let mut attr = BpfAttrProgQuery {
            target_fd: cgroup.as_raw_fd() as u32,
            attach_type: line.role.bpf_attach_type(),
            query_flags: 0,
            attach_flags: 0,
            prog_ids: program_ids.as_mut_ptr() as u64,
            prog_cnt: program_ids.len() as u32,
            padding: 0,
            prog_attach_flags: 0,
            link_ids: 0,
            link_attach_flags: 0,
            revision: 0,
        };
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_QUERY,
                &mut attr as *mut BpfAttrProgQuery,
                std::mem::size_of::<BpfAttrProgQuery>(),
            )
        };
        if ret >= 0 {
            program_ids.truncate(attr.prog_cnt as usize);
            return Ok(CgroupAttachmentQuery {
                role: line.role,
                attach_type: line.role.bpf_attach_type(),
                attach_flags: attr.attach_flags,
                revision: attr.revision,
                program_ids,
            });
        }

        let error = io::Error::last_os_error();
        let required = attr.prog_cnt as usize;
        if error.raw_os_error() == Some(libc::ENOSPC)
            && required > program_ids.len()
            && required <= MAX_PROGRAM_ID_CAPACITY
        {
            program_ids.resize(required, 0);
            continue;
        }
        return Err(io::Error::new(
            error.kind(),
            format!(
                "query cgroup attach type {} for {:?}: {error}",
                line.role.bpf_attach_type(),
                line.role
            ),
        ));
    }
}

#[repr(C)]
#[derive(Default)]
struct BpfAttrProgQuery {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    padding: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_query_layout_matches_the_kernel_uapi() {
        assert_eq!(std::mem::size_of::<BpfAttrProgQuery>(), 64);
        assert_eq!(std::mem::align_of::<BpfAttrProgQuery>(), 8);
    }

    #[test]
    fn only_empty_or_multi_attachment_sets_are_compatible() {
        let mut query = CgroupAttachmentQuery {
            role: DaeCgroupAttachRole::SockCreate,
            attach_type: DaeCgroupAttachRole::SockCreate.bpf_attach_type(),
            attach_flags: 0,
            revision: 0,
            program_ids: Vec::new(),
        };
        assert!(query.compatible_with_multiple_attach());

        query.program_ids.push(7);
        assert!(!query.compatible_with_multiple_attach());

        query.attach_flags = CGROUP_ATTACH_FLAG_ALLOW_MULTIPLE;
        assert!(query.compatible_with_multiple_attach());
    }
}
