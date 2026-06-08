use super::*;
pub fn tproxy_kernel_program_coverage() -> Vec<KernelProgramCoverageLine> {
    TPROXY_CLASSIFIER_COVERAGE
        .iter()
        .chain(TPROXY_CGROUP_COVERAGE.iter())
        .copied()
        .collect()
}

pub fn trace_kernel_program_coverage() -> Vec<KernelProgramCoverageLine> {
    TRACE_KPROBE_COVERAGE.to_vec()
}

pub(super) const TPROXY_CLASSIFIER_COVERAGE: [KernelProgramCoverageLine; 10] = [
    tproxy_classifier(
        "tc/lan_ingress_l2",
        "classifier/lan_ingress_l2",
        "tproxy_lan_ingress_l2",
    ),
    tproxy_classifier(
        "tc/lan_ingress_l3",
        "classifier/lan_ingress_l3",
        "tproxy_lan_ingress_l3",
    ),
    tproxy_classifier(
        "tc/lan_egress_l2",
        "classifier/lan_egress_l2",
        "tproxy_lan_egress_l2",
    ),
    tproxy_classifier(
        "tc/lan_egress_l3",
        "classifier/lan_egress_l3",
        "tproxy_lan_egress_l3",
    ),
    tproxy_classifier(
        "tc/wan_ingress_l2",
        "classifier/wan_ingress_l2",
        "tproxy_wan_ingress_l2",
    ),
    tproxy_classifier(
        "tc/wan_ingress_l3",
        "classifier/wan_ingress_l3",
        "tproxy_wan_ingress_l3",
    ),
    tproxy_classifier(
        "tc/wan_egress_l2",
        "classifier/wan_egress_l2",
        "tproxy_wan_egress_l2",
    ),
    tproxy_classifier(
        "tc/wan_egress_l3",
        "classifier/wan_egress_l3",
        "tproxy_wan_egress_l3",
    ),
    tproxy_classifier(
        "tc/dae0peer_ingress",
        "classifier/dae0peer_ingress",
        "tproxy_dae0peer_ingress",
    ),
    tproxy_classifier(
        "tc/dae0_ingress",
        "classifier/dae0_ingress",
        "tproxy_dae0_ingress",
    ),
];

pub(super) const TPROXY_CGROUP_COVERAGE: [KernelProgramCoverageLine; 6] = [
    tproxy_cgroup("cgroup/sock_create", "tproxy_wan_cg_sock_create"),
    tproxy_cgroup("cgroup/sock_release", "tproxy_wan_cg_sock_release"),
    tproxy_cgroup("cgroup/connect4", "tproxy_wan_cg_connect4"),
    tproxy_cgroup("cgroup/connect6", "tproxy_wan_cg_connect6"),
    tproxy_cgroup("cgroup/sendmsg4", "tproxy_wan_cg_sendmsg4"),
    tproxy_cgroup("cgroup/sendmsg6", "tproxy_wan_cg_sendmsg6"),
];

pub(super) const TRACE_KPROBE_COVERAGE: [KernelProgramCoverageLine; 6] = [
    trace_kprobe("kprobe/skb-1", "kprobe_skb_1"),
    trace_kprobe("kprobe/skb-2", "kprobe_skb_2"),
    trace_kprobe("kprobe/skb-3", "kprobe_skb_3"),
    trace_kprobe("kprobe/skb-4", "kprobe_skb_4"),
    trace_kprobe("kprobe/skb-5", "kprobe_skb_5"),
    trace_kprobe(
        "kprobe/skb_lifetime_termination",
        "kprobe_skb_lifetime_termination",
    ),
];

pub(super) const fn tproxy_classifier(
    c_section: &'static str,
    rust_section: &'static str,
    program_name: &'static str,
) -> KernelProgramCoverageLine {
    KernelProgramCoverageLine {
        surface: KernelProgramSurface::TproxyClassifier,
        c_section,
        rust_section: Some(rust_section),
        program_name,
        status: KernelProgramCoverageStatus::RustNativeAdmitted,
    }
}

pub(super) const fn tproxy_cgroup(
    section: &'static str,
    program_name: &'static str,
) -> KernelProgramCoverageLine {
    KernelProgramCoverageLine {
        surface: KernelProgramSurface::TproxyCgroup,
        c_section: section,
        rust_section: Some(section),
        program_name,
        status: KernelProgramCoverageStatus::RustNativeAdmitted,
    }
}

pub(super) const fn trace_kprobe(
    c_section: &'static str,
    program_name: &'static str,
) -> KernelProgramCoverageLine {
    KernelProgramCoverageLine {
        surface: KernelProgramSurface::TraceKprobe,
        c_section,
        rust_section: None,
        program_name,
        status: KernelProgramCoverageStatus::COracleRequired,
    }
}
