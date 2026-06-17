use super::*;
#[cfg(feature = "native-ebpf")]
pub(crate) fn run_trace_load_pin(options: TraceLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{AyaTraceLoaderOptions, load_pin_aya_trace_object};

    let report = match load_pin_aya_trace_object(AyaTraceLoaderOptions {
        object: &options.object,
        pin_root: &options.pin_root,
        port: options.port,
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        ringbuf_size: options.ringbuf_size,
    }) {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(err),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "object": report.object,
            "pin_root": report.pin_root,
            "map_pin_root": report.map_pin_root,
            "program_pin_root": report.program_pin_root,
            "maps": report.maps.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "programs": report.programs.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "trace_config": {
                "port": report.port,
                "l4_proto": report.l4_proto,
                "ip_version": report.ip_version,
                "ringbuf_size": report.ringbuf_size,
            },
            "native_trace_pinning_ready": true,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
pub(crate) fn run_trace_load_pin(_options: TraceLoaderLoadPinOptions) -> LoaderOutput {
    LoaderOutput::error(dae_ebpf_support::trace_core_sideload_gate_report().disabled_reason)
}

#[cfg(feature = "native-ebpf")]
pub(crate) fn run_trace_attach_ringbuf_smoke(
    options: TraceLoaderAttachRingbufSmokeOptions,
) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaTraceAttachRingbufSmokeOptions, AyaTraceAttachSmokeTrigger,
        attach_ringbuf_smoke_aya_trace_object,
    };

    let trigger = match options.trigger {
        TraceLoaderAttachSmokeTrigger::LoopbackUdp => AyaTraceAttachSmokeTrigger::LoopbackUdp,
        TraceLoaderAttachSmokeTrigger::OpenProcSelfStat => {
            AyaTraceAttachSmokeTrigger::OpenProcSelfStat
        }
    };
    let report = match attach_ringbuf_smoke_aya_trace_object(AyaTraceAttachRingbufSmokeOptions {
        object: &options.object,
        target: &options.target,
        program_name: &options.program_name,
        port: options.port,
        l4_proto: options.l4_proto,
        ip_version: options.ip_version,
        ringbuf_size: options.ringbuf_size,
        trigger,
        trigger_count: options.trigger_count,
        poll_attempts: options.poll_attempts,
    }) {
        Ok(report) => report,
        Err(err) => return LoaderOutput::error(err),
    };
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "scope": "trace-attach-ringbuf-smoke",
            "object": report.object,
            "target": report.target,
            "program_name": report.program_name,
            "trigger": report.trigger.as_str(),
            "trigger_count": report.trigger_count,
            "poll_attempts": report.poll_attempts,
            "events_seen": report.events_seen,
            "first_event_len": report.first_event_len,
            "first_event_pc_nonzero": report.first_event_pc_nonzero,
            "first_event_skb_nonzero": report.first_event_skb_nonzero,
            "sk_buff_core_semantics": false,
            "production_daemon_path": false,
        })
    ))
}

#[cfg(not(feature = "native-ebpf"))]
pub(crate) fn run_trace_attach_ringbuf_smoke(
    _options: TraceLoaderAttachRingbufSmokeOptions,
) -> LoaderOutput {
    LoaderOutput::error(dae_ebpf_support::trace_core_sideload_gate_report().disabled_reason)
}
