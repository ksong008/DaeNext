//! Physical attachment ownership, independent of Aya's consuming detach API.
use super::*;
use aya::programs::{
    ProgramFd,
    cgroup_sock::CgroupSockLink,
    cgroup_sock_addr::CgroupSockAddrLink,
    links::Link,
    tc::{SchedClassifierLink, TcHandle},
};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;

pub(super) enum RetainedCgroupLink {
    Sock(CgroupSockLink, ProgramFd),
    SockAddr(CgroupSockAddrLink, ProgramFd),
}

enum Attachment {
    Tc {
        link: Option<SchedClassifierLink>,
        netns: fs::File,
        location: Option<super::tc_netlink_query::FilterLocation>,
        _program: ProgramFd,
        program_id: u32,
    },
    Cgroup {
        link: Option<RetainedCgroupLink>,
        target: fs::File,
        program: Option<ProgramFd>,
        attach_type: u32,
    },
}

pub(super) struct RetainedLink {
    name: String,
    attachment: Attachment,
}

impl RetainedLink {
    pub(super) fn cgroup(
        line: &DaeCgroupAttachLine,
        target: fs::File,
        link: RetainedCgroupLink,
    ) -> Self {
        Self {
            name: line.program_name.to_owned(),
            attachment: Attachment::Cgroup {
                link: Some(link),
                target,
                program: None,
                attach_type: line.role.bpf_attach_type(),
            },
        }
    }

    fn detach(&mut self) -> Result<(), String> {
        match &mut self.attachment {
            Attachment::Tc {
                link,
                netns,
                location,
                program_id,
                ..
            } => {
                // FD links are namespace independent and closing our sole link
                // reference cannot detach a replacement owned by someone else.
                if location.is_none() {
                    return link.take().map_or(Ok(()), |l| {
                        l.detach().map_err(|e| format!("detach TCX link: {e}"))
                    });
                }
                let path = format!("/proc/thread-self/fd/{}", netns.as_raw_fd());
                with_optional_netns(Some(&path), || {
                    let location = location.as_ref().unwrap();
                    let id = *program_id;
                    match super::tc_netlink_query::filter_program_id(location)? {
                        None => {
                            // Do not let a stale Aya link delete a later replacement.
                            if let Some(stale) = link.take() {
                                mem::forget(stale);
                            }
                            return Ok(());
                        }
                        Some(observed) if observed != id => {
                            return Err(format!(
                                "foreign filter at {location:?}: expected program {id}, observed {observed}"
                            ));
                        }
                        Some(_) => {}
                    }
                    let owned = match link.take() {
                        Some(link) => link,
                        None => SchedClassifierLink::attached(
                            location.ifindex,
                            TcHandle::from(location.parent),
                            location.priority,
                            TcHandle::from(location.handle),
                            None,
                        )
                        .map_err(|e| format!("recover netlink link: {e}"))?,
                    };
                    // detach consumes the link even on error. The namespace,
                    // exact location and program FD remain available for retry.
                    owned
                        .detach()
                        .map_err(|e| format!("detach netlink {location:?}: {e}"))
                })
            }
            Attachment::Cgroup {
                link,
                target,
                program,
                attach_type,
            } => {
                if let Some(owned) = link.take() {
                    let (fd, result) = match owned {
                        RetainedCgroupLink::Sock(l, fd) => (fd, l.detach()),
                        RetainedCgroupLink::SockAddr(l, fd) => (fd, l.detach()),
                    };
                    *program = Some(fd);
                    return result.map_err(|e| format!("detach cgroup link: {e}"));
                }
                // Legacy kernels use BPF_PROG_DETACH, whose consumed link can
                // be recovered by the original program and cgroup FDs. It never
                // targets a different program at the same attach point.
                let fd = program.as_ref().ok_or("missing cgroup recovery program")?;
                let attr = [
                    target.as_raw_fd() as u32,
                    fd.as_fd().as_raw_fd() as u32,
                    *attach_type,
                    0,
                ];
                // SAFETY: attr is the initialized BPF_PROG_DETACH UAPI prefix.
                let result = unsafe {
                    libc::syscall(libc::SYS_bpf, 9, attr.as_ptr(), mem::size_of_val(&attr))
                };
                if result >= 0 {
                    return Ok(());
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOENT) {
                    Ok(())
                } else {
                    Err(format!("retry cgroup detach: {error}"))
                }
            }
        }
    }
}

pub(super) fn retain_tc_link(
    loaded: &mut AyaUserspaceLoadedObject,
    report: &mut AyaTcAttachDetachReport,
    link_id: SchedClassifierLinkId,
    program: ProgramFd,
    netns: fs::File,
) -> Result<(), String> {
    let classifier: &mut SchedClassifier = loaded
        .ebpf
        .program_mut(&report.program_name)
        .ok_or("retained classifier missing")?
        .try_into()
        .map_err(|e| format!("retained classifier type: {e}"))?;
    let link = classifier
        .take_link(link_id)
        .map_err(|e| format!("take classifier link: {e}"))?;
    let location = if report.backend == AttachBackend::TcNetlink {
        let priority = link.priority().map_err(|e| e.to_string())?;
        let handle = u32::from(link.handle().map_err(|e| e.to_string())?);
        report.priority = priority;
        report.handle = handle;
        Some(super::tc_netlink_query::FilterLocation {
            ifindex: report.ifindex,
            parent: link.parent().map_err(|e| e.to_string())?.into(),
            priority,
            handle,
        })
    } else {
        None
    };
    loaded.attachments.push(RetainedLink {
        name: report.program_name.clone(),
        attachment: Attachment::Tc {
            link: Some(link),
            netns,
            location,
            _program: program,
            program_id: report
                .program_id
                .ok_or("retained classifier identity missing")?,
        },
    });
    Ok(())
}

impl AyaUserspaceLoadedObject {
    /// One bounded pass, aggregating failures while preserving every pending
    /// physical attachment. Call again to retry; successful links are removed.
    pub fn cleanup_retained_links(&mut self, program_name: Option<&str>) -> Result<(), String> {
        let mut errors = Vec::new();
        let started = std::time::Instant::now();
        self.attachments.retain_mut(|link| {
            if program_name.is_some_and(|name| name != link.name) {
                return true;
            }
            if started.elapsed() >= std::time::Duration::from_secs(2) {
                errors.push(format!("{}: cleanup pass budget exhausted", link.name));
                return true;
            }
            match link.detach() {
                Ok(()) => false,
                Err(error) => {
                    errors.push(format!("{}: {error}", link.name));
                    true
                }
            }
        });
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn pending_attachment_evidence(&self) -> Vec<String> {
        self.attachments
            .iter()
            .map(|item| match &item.attachment {
                Attachment::Tc {
                    netns,
                    location,
                    program_id,
                    ..
                } => format!(
                    "{}: program_id={program_id} netns_inode={:?} location={location:?}",
                    item.name,
                    netns.metadata().map(|m| m.ino())
                ),
                Attachment::Cgroup {
                    target,
                    attach_type,
                    ..
                } => format!(
                    "{}: cgroup_inode={:?} attach_type={attach_type}",
                    item.name,
                    target.metadata().map(|m| m.ino())
                ),
            })
            .collect()
    }

    pub fn pending_attachment_count(&self) -> usize {
        self.attachments.len()
    }
}

impl Drop for AyaUserspaceLoadedObject {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup_retained_links(None) {
            eprintln!("native eBPF attachment cleanup pending: {error}");
        }
        for pending in &mut self.attachments {
            // A remaining netlink link must never fall through Aya Drop in the
            // caller's namespace. Its identity is included in the error above.
            if let Attachment::Tc {
                link,
                location: Some(_),
                ..
            } = &mut pending.attachment
                && let Some(link) = link.take()
            {
                mem::forget(link);
            }
        }
    }
}

#[cfg(test)]
mod tests;
