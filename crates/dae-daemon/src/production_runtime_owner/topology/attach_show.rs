use super::*;
pub(crate) fn attach_peer_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
) -> bool {
    let param_object = path_string(param_object);
    let target = production_peer_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        FILTER_PREF,
        param_object,
        options.peer_section.clone(),
    );
    if let Some(native_ok) = native_runtime.attach_program(
        steps,
        options,
        native_param_object,
        NativeEbpfAttachRole::PeerIngress,
    ) {
        return native_ok;
    }
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-peer-clsact-qdisc",
        command_spec(target.clsact_qdisc_add_command()),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0peer-param-aware-ebpf-program",
        command_spec(attach.filter_add_command()),
    );
    ok
}

pub(crate) fn attach_host_program(
    steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
    native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
) -> bool {
    let param_object = path_string(param_object);
    let target = production_host_attach_target();
    let attach = TcBpfAttachSpec::new(
        target.clone(),
        FILTER_PREF,
        param_object,
        options.host_section.clone(),
    );
    if let Some(native_ok) = native_runtime.attach_program(
        steps,
        options,
        native_param_object,
        NativeEbpfAttachRole::HostIngress,
    ) {
        return native_ok;
    }
    let mut ok = true;
    ok &= run_step(
        steps,
        "attach-production-host-clsact-qdisc",
        command_spec(target.clsact_qdisc_add_command()),
    );
    ok &= run_step(
        steps,
        "attach-production-dae0-param-aware-ebpf-program",
        command_spec(attach.filter_add_command()),
    );
    ok
}

pub(crate) fn show_peer_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0peer-param-aware-ebpf-program-filter",
        command_spec(production_peer_attach_target().filter_show_command(false)),
    )
}

pub(crate) fn show_host_program(steps: &mut Vec<Value>) -> Value {
    run_observation_step(
        steps,
        "show-production-dae0-param-aware-ebpf-program-filter",
        command_spec(production_host_attach_target().filter_show_command(false)),
    )
}
