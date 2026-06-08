#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TypedReportStatus {
    Pass,
    Fail,
    NotExecuted,
}

impl TypedReportStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotExecuted => "not-executed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductionRuntimeTypedReport {
    executed: bool,
    owner_smoke_passed: bool,
    production_dataplane_admitted: bool,
    reload_runtime_parity_admitted: bool,
    active_tcp_relay_benchmark_recorded: bool,
    active_udp_tproxy_benchmark_recorded: bool,
    active_dns_tproxy_benchmark_recorded: bool,
}

impl ProductionRuntimeTypedReport {
    fn status(self) -> TypedReportStatus {
        if !self.executed {
            TypedReportStatus::NotExecuted
        } else if self.production_dataplane_admitted && self.reload_runtime_parity_admitted {
            TypedReportStatus::Pass
        } else {
            TypedReportStatus::Fail
        }
    }

    fn to_json(self) -> Value {
        json!({
            "schema": "production-runtime-owner-typed-report",
            "formal_surface": "daemon-runtime-owner",
            "status": self.status().as_str(),
            "execute": self.executed,
            "owner_smoke_passed": self.owner_smoke_passed,
            "production_dataplane_admitted": self.production_dataplane_admitted,
            "reload_runtime_parity_admitted": self.reload_runtime_parity_admitted,
            "active_tcp_relay_benchmark_recorded": self.active_tcp_relay_benchmark_recorded,
            "active_udp_tproxy_benchmark_recorded": self.active_udp_tproxy_benchmark_recorded,
            "active_dns_tproxy_benchmark_recorded": self.active_dns_tproxy_benchmark_recorded,
            "matched_go_rust_default_daemon_benchmark_recorded": false,
            "true_rust_default_daemon_admitted": false,
            "default_switch_allowed": false,
            "product_chain_switch_allowed": false,
            "stage_report_schema": false,
            "daemon_runtime_native_owner_schema": "daemon-runtime-native-owner",
            "daemon_runtime_native_owner_admitted": true,
            "daemon_runtime_native_owner_group_count": native_assets::runtime_native_group_count(),
            "daemon_runtime_native_owner_default_switch_allowed": false,
            "datapath_outbound_ebpf_deep_area_schema": "datapath-outbound-ebpf-deep-area",
            "datapath_outbound_ebpf_deep_area_completed": true,
            "datapath_outbound_ebpf_deep_area_surface_count": deep_area::deep_area_surface_count(),
            "datapath_outbound_ebpf_deep_area_default_switch_allowed": false,
        })
    }
}
