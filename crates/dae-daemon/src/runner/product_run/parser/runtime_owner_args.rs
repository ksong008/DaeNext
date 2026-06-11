use super::*;
pub(crate) fn parse_runtime_owner_arg<'a>(
    arg: &str,
    iter: &mut std::slice::Iter<'a, String>,
    state: &mut ProductRunParsedArgs,
) -> Result<bool, DaemonOutput> {
    macro_rules! usage {
        ($($arg:tt)*) => {
            return Err(DaemonOutput::usage($($arg)*))
        };
    }
    match arg {
        "--execute-production-runtime-owner" => state.production_runtime_owner = true,
        "--execute-production-runtime-active-tcp" => state.production_runtime_active_tcp = true,
        "--execute-production-dataplane-smoke" => state.production_dataplane_smoke = true,
        "--ack-root-gate" => state.ack_root_gate = true,
        "--production-runtime-tproxy-port" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-tproxy-port value",);
            };
            state.production_runtime_tproxy_port = match value.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --production-runtime-tproxy-port value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-tproxy-port=") => {
            state.production_runtime_tproxy_port = match arg.split_once('=').unwrap().1.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --production-runtime-tproxy-port value",);
                }
            };
        }
        "--production-runtime-dae-netns-id" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-dae-netns-id value",);
            };
            state.production_runtime_dae_netns_id = match value.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --production-runtime-dae-netns-id value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-dae-netns-id=") => {
            state.production_runtime_dae_netns_id = match arg.split_once('=').unwrap().1.parse() {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --production-runtime-dae-netns-id value",);
                }
            };
        }
        "--production-runtime-netns-link" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-netns-link value",);
            };
            state.production_runtime_netns_link_mode = match parse_netns_link_mode(value) {
                Ok(value) => value,
                Err(_) => {
                    usage!("invalid run --production-runtime-netns-link value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-netns-link=") => {
            state.production_runtime_netns_link_mode =
                match parse_netns_link_mode(arg.split_once('=').unwrap().1) {
                    Ok(value) => value,
                    Err(_) => {
                        usage!("invalid run --production-runtime-netns-link value",);
                    }
                };
        }
        "--production-runtime-object" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-object value");
            };
            state.production_runtime_object = Some(value.into());
        }
        _ if arg.starts_with("--production-runtime-object=") => {
            state.production_runtime_object = arg.split_once('=').map(|(_, value)| value.into());
        }
        "--production-runtime-native-ebpf-object" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-native-ebpf-object value",);
            };
            state.production_runtime_native_ebpf_object = Some(value.into());
        }
        _ if arg.starts_with("--production-runtime-native-ebpf-object=") => {
            state.production_runtime_native_ebpf_object =
                arg.split_once('=').map(|(_, value)| value.into());
        }
        "--production-runtime-native-ebpf" => {
            state.production_runtime_native_ebpf_requested = true;
        }
        "--production-runtime-native-ebpf-backend" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-native-ebpf-backend value",);
            };
            state.production_runtime_native_ebpf_backend = match parse_attach_backend(value) {
                Some(value) => value,
                None => {
                    usage!("invalid run --production-runtime-native-ebpf-backend value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-native-ebpf-backend=") => {
            state.production_runtime_native_ebpf_backend =
                match parse_attach_backend(arg.split_once('=').unwrap().1) {
                    Some(value) => value,
                    None => {
                        usage!("invalid run --production-runtime-native-ebpf-backend value",);
                    }
                };
        }
        "--production-runtime-native-ebpf-completed-a3-local" => {
            state.production_runtime_native_ebpf_completed_a3_admission = true;
        }
        _ => return Ok(false),
    }
    Ok(true)
}
