use std::path::Path;

use dae_ebpf_support::{
    AttachBackend, EbpfBackendCapabilityReport, KernelProgramFallbackRetirementEvidence,
    KernelProgramFallbackRetirementGateReport, KernelProgramParityAdmissionReport,
    KernelProgramParityEvidence, LiveLoadedTproxyListenSocketMap, LoaderBackend,
    NativeBackendAdmissionEvidence, NativeBackendAdmissionReport, TproxyDataplaneAdmissionReport,
    TproxySocketOptions, TraceDiagnosticGateReport, dae_cgroup_attach_matrix,
    kernel_program_fallback_retirement_gate_report, kernel_program_feasibility_report,
    kernel_program_parity_admission_report, native_backend_admission_report,
    report_only_ebpf_backend_capability, tproxy_dataplane_admission_report,
    trace_core_sideload_gate_report, trace_diagnostic_gate_report,
};
use serde_json::{Map, Value, json};

use super::command::path_string;
use super::deep_area;
use super::native_assets;
use super::native_ebpf::{native_backend_opt_in_decision_json, native_backend_runtime_decision};
use super::udp_dns_datapath_contract::udp_dns_datapath_contract_json;
use super::{
    ExecutionEvidence, FILTER_PREF, PRODUCTION_HOST_IFACE, PRODUCTION_NETNS, PRODUCTION_PEER_IFACE,
    ProductionRuntimeOwnerOptions,
};

mod typed_report;
use self::typed_report::*;
mod report_value;
pub(super) use self::report_value::*;
mod ebpf_backend;
use self::ebpf_backend::*;
mod admission_json;
use self::admission_json::*;
mod live_handoff;
pub(super) use self::live_handoff::*;
