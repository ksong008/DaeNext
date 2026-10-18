use std::fmt::Debug;
use std::sync::OnceLock;
use std::time::Instant;

use aya::maps::MapType;
use aya::programs::ProgramType;
use aya::sys::{BpfHelper, is_helper_supported, is_map_supported, is_program_supported};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AyaProbeOutcome {
    Supported,
    Unsupported,
    ProbeError(String),
}

impl AyaProbeOutcome {
    pub const fn status(&self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::ProbeError(_) => "probe-error",
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Self::ProbeError(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaCapabilityProbeEntry {
    pub kind: &'static str,
    pub name: String,
    pub program_type: Option<String>,
    pub outcome: AyaProbeOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaCapabilityProbeReport {
    pub entries: Vec<AyaCapabilityProbeEntry>,
    pub elapsed_micros: u128,
}

/// Supplemental startup diagnostics. Real verifier/load/attach admission remains
/// authoritative. Call only while initializing the native loader, before any
/// privilege reduction; reloads reuse the process-local snapshot.
pub fn cached_aya_capability_probes() -> &'static AyaCapabilityProbeReport {
    static CACHE: OnceLock<AyaCapabilityProbeReport> = OnceLock::new();
    cached_probe_report(&CACHE, probe_kernel)
}

fn cached_probe_report(
    cache: &OnceLock<AyaCapabilityProbeReport>,
    probe: impl FnOnce() -> AyaCapabilityProbeReport,
) -> &AyaCapabilityProbeReport {
    cache.get_or_init(probe)
}

fn outcome(result: Result<bool, impl Debug>) -> AyaProbeOutcome {
    match result {
        Ok(true) => AyaProbeOutcome::Supported,
        Ok(false) => AyaProbeOutcome::Unsupported,
        Err(error) => AyaProbeOutcome::ProbeError(format!("{error:?}")),
    }
}

fn probe_kernel() -> AyaCapabilityProbeReport {
    let start = Instant::now();
    let mut entries = Vec::new();
    for program in [
        ProgramType::SchedClassifier,
        ProgramType::CgroupSock,
        ProgramType::CgroupSockAddr,
    ] {
        entries.push(AyaCapabilityProbeEntry {
            kind: "program",
            name: format!("{program:?}"),
            program_type: None,
            outcome: outcome(is_program_supported(program)),
        });
    }
    for map in [
        MapType::Array,
        MapType::Hash,
        MapType::LruHash,
        MapType::PerCpuArray,
        MapType::LpmTrie,
        MapType::ArrayOfMaps,
        MapType::SockMap,
    ] {
        entries.push(AyaCapabilityProbeEntry {
            kind: "map",
            name: format!("{map:?}"),
            program_type: None,
            outcome: outcome(is_map_supported(map)),
        });
    }
    // These helpers are used by the TC socket handoff and cgroup pname paths.
    for (program, helpers) in [
        (
            ProgramType::SchedClassifier,
            &[
                BpfHelper::BPF_FUNC_sk_assign,
                BpfHelper::BPF_FUNC_skc_lookup_tcp,
                BpfHelper::BPF_FUNC_sk_release,
                BpfHelper::BPF_FUNC_redirect_peer,
            ][..],
        ),
        (
            ProgramType::CgroupSock,
            &[
                BpfHelper::BPF_FUNC_get_socket_cookie,
                BpfHelper::BPF_FUNC_get_current_comm,
                BpfHelper::BPF_FUNC_get_current_task,
                BpfHelper::BPF_FUNC_probe_read_kernel,
                BpfHelper::BPF_FUNC_probe_read_user_str,
                BpfHelper::BPF_FUNC_loop,
            ][..],
        ),
        (
            ProgramType::CgroupSockAddr,
            &[
                BpfHelper::BPF_FUNC_get_socket_cookie,
                BpfHelper::BPF_FUNC_get_current_comm,
                BpfHelper::BPF_FUNC_get_current_task,
                BpfHelper::BPF_FUNC_probe_read_kernel,
                BpfHelper::BPF_FUNC_probe_read_user_str,
                BpfHelper::BPF_FUNC_loop,
            ][..],
        ),
    ] {
        for helper in helpers {
            entries.push(AyaCapabilityProbeEntry {
                kind: "helper",
                name: format!("{helper:?}"),
                program_type: Some(format!("{program:?}")),
                outcome: outcome(is_helper_supported(program, *helper)),
            });
        }
    }
    AyaCapabilityProbeReport {
        entries,
        elapsed_micros: start.elapsed().as_micros(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn permission_errors_remain_distinct_from_missing_kernel_support() {
        assert_eq!(
            outcome(Ok::<_, std::io::Error>(true)),
            AyaProbeOutcome::Supported
        );
        assert_eq!(
            outcome(Ok::<_, std::io::Error>(false)),
            AyaProbeOutcome::Unsupported
        );
        let result = outcome(Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        assert_eq!(result.status(), "probe-error");
        assert!(result.error().unwrap().contains("PermissionDenied"));
    }

    #[test]
    fn repeated_and_concurrent_initialization_runs_probes_once() {
        let cache = OnceLock::new();
        let calls = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let report = cached_probe_report(&cache, || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        AyaCapabilityProbeReport {
                            entries: Vec::new(),
                            elapsed_micros: 7,
                        }
                    });
                    assert_eq!(report.elapsed_micros, 7);
                });
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
