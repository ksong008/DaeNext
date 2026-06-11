use super::*;
pub(crate) struct ProductRunLogFields<'a> {
    pub(super) options: &'a RunOptions,
    pub(super) config_len: usize,
    pub(super) listener_smoke_passed: bool,
    pub(super) reload_smoke_passed: bool,
    pub(super) production_runtime_owner_executed: bool,
    pub(super) production_runtime_owner_passed: bool,
    pub(super) production_runtime_active_tcp_executed: bool,
    pub(super) production_runtime_active_tcp_passed: bool,
    pub(super) active_tcp_relay_executed: bool,
    pub(super) active_tcp_relay_passed: bool,
    pub(super) active_tcp_relay_benchmark_recorded: bool,
    pub(super) production_runtime_active_udp_executed: bool,
    pub(super) active_udp_admitted: bool,
    pub(super) production_runtime_active_dns_executed: bool,
    pub(super) active_dns_admitted: bool,
    pub(super) reload_runtime_parity_executed: bool,
    pub(super) reload_runtime_parity_passed: bool,
    pub(super) production_dataplane_admitted: bool,
    pub(super) production_dataplane_harness_executed: bool,
    pub(super) production_dataplane_harness_passed: bool,
    pub(super) production_daemon_admitted: bool,
}

pub(crate) fn write_product_run_log(fields: ProductRunLogFields<'_>) -> Result<(), String> {
    fs::write(
        &fields.options.logfile,
        format!(
            "daed run: config={} bytes={} listener_smoke_passed={} reload_smoke_passed={} production_runtime_owner_executed={} production_runtime_owner_passed={} production_runtime_active_tcp_executed={} production_runtime_active_tcp_passed={} active_tcp_relay_executed={} active_tcp_relay_passed={} active_tcp_relay_benchmark_recorded={} production_runtime_active_udp_executed={} active_udp_admitted={} production_runtime_active_dns_executed={} active_dns_admitted={} reload_runtime_parity_executed={} reload_runtime_parity_passed={} production_dataplane_admitted={} production_dataplane_harness_executed={} production_dataplane_harness_passed={} production_daemon_admitted={}\n",
            path_string(&fields.options.config),
            fields.config_len,
            fields.listener_smoke_passed,
            fields.reload_smoke_passed,
            fields.production_runtime_owner_executed,
            fields.production_runtime_owner_passed,
            fields.production_runtime_active_tcp_executed,
            fields.production_runtime_active_tcp_passed,
            fields.active_tcp_relay_executed,
            fields.active_tcp_relay_passed,
            fields.active_tcp_relay_benchmark_recorded,
            fields.production_runtime_active_udp_executed,
            fields.active_udp_admitted,
            fields.production_runtime_active_dns_executed,
            fields.active_dns_admitted,
            fields.reload_runtime_parity_executed,
            fields.reload_runtime_parity_passed,
            fields.production_dataplane_admitted,
            fields.production_dataplane_harness_executed,
            fields.production_dataplane_harness_passed,
            fields.production_daemon_admitted
        ),
    )
    .map_err(|err| format!("failed to write run log file: {err}"))
}
