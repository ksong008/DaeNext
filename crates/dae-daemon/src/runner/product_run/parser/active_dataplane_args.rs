use super::*;
pub(crate) fn parse_active_dataplane_arg<'a>(
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
        "--production-runtime-active-tcp-target-ip" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-tcp-target-ip value",);
            };
            state.production_runtime_active_tcp_target_ip = Some(value.to_owned());
        }
        _ if arg.starts_with("--production-runtime-active-tcp-target-ip=") => {
            state.production_runtime_active_tcp_target_ip =
                arg.split_once('=').map(|(_, value)| value.to_owned());
        }
        "--production-runtime-active-tcp-client-ip" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-tcp-client-ip value",);
            };
            state.production_runtime_active_tcp_client_ip = Some(value.to_owned());
        }
        _ if arg.starts_with("--production-runtime-active-tcp-client-ip=") => {
            state.production_runtime_active_tcp_client_ip =
                arg.split_once('=').map(|(_, value)| value.to_owned());
        }
        "--production-runtime-active-tcp-target-port" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-tcp-target-port value",);
            };
            state.production_runtime_active_tcp_target_port = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-tcp-target-port value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-tcp-target-port=") => {
            state.production_runtime_active_tcp_target_port =
                match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!("invalid run --production-runtime-active-tcp-target-port value",);
                    }
                };
        }
        "--production-runtime-active-tcp-so-mark" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-tcp-so-mark value",);
            };
            state.production_runtime_active_tcp_so_mark = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-tcp-so-mark value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-tcp-so-mark=") => {
            state.production_runtime_active_tcp_so_mark =
                match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!("invalid run --production-runtime-active-tcp-so-mark value",);
                    }
                };
        }
        "--production-runtime-active-tcp-mptcp" => {
            state.production_runtime_active_tcp_mptcp = Some(true);
        }
        "--production-runtime-active-tcp-no-mptcp" | "--no-production-runtime-active-tcp-mptcp" => {
            state.production_runtime_active_tcp_mptcp = Some(false);
        }
        "--execute-production-runtime-active-tcp-relay" => {
            state.production_runtime_active_tcp_relay = true;
        }
        "--execute-production-runtime-active-udp" => {
            state.production_runtime_active_udp = true;
        }
        "--production-runtime-active-udp-target-ip" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-udp-target-ip value",);
            };
            state.production_runtime_active_udp_target_ip = Some(value.to_owned());
        }
        _ if arg.starts_with("--production-runtime-active-udp-target-ip=") => {
            state.production_runtime_active_udp_target_ip =
                arg.split_once('=').map(|(_, value)| value.to_owned());
        }
        "--production-runtime-active-udp-target-port" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-udp-target-port value",);
            };
            state.production_runtime_active_udp_target_port = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-udp-target-port value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-udp-target-port=") => {
            state.production_runtime_active_udp_target_port =
                match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!("invalid run --production-runtime-active-udp-target-port value",);
                    }
                };
        }
        "--production-runtime-active-udp-benchmark-iters" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-udp-benchmark-iters value",);
            };
            state.production_runtime_active_udp_benchmark_iters = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-udp-benchmark-iters value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-udp-benchmark-iters=") => {
            state.production_runtime_active_udp_benchmark_iters = match arg
                .split_once('=')
                .unwrap()
                .1
                .parse()
            {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-udp-benchmark-iters value",);
                }
            };
        }
        "--execute-production-runtime-active-dns" => {
            state.production_runtime_active_dns = true;
        }
        "--production-runtime-active-dns-target-ip" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-dns-target-ip value",);
            };
            state.production_runtime_active_dns_target_ip = Some(value.to_owned());
        }
        _ if arg.starts_with("--production-runtime-active-dns-target-ip=") => {
            state.production_runtime_active_dns_target_ip =
                arg.split_once('=').map(|(_, value)| value.to_owned());
        }
        "--production-runtime-active-dns-target-port" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-dns-target-port value",);
            };
            state.production_runtime_active_dns_target_port = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-dns-target-port value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-dns-target-port=") => {
            state.production_runtime_active_dns_target_port =
                match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!("invalid run --production-runtime-active-dns-target-port value",);
                    }
                };
        }
        "--production-runtime-active-dns-upstream-ip" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-dns-upstream-ip value",);
            };
            state.production_runtime_active_dns_upstream_ip = Some(value.to_owned());
        }
        _ if arg.starts_with("--production-runtime-active-dns-upstream-ip=") => {
            state.production_runtime_active_dns_upstream_ip =
                arg.split_once('=').map(|(_, value)| value.to_owned());
        }
        "--production-runtime-active-dns-upstream-port" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-dns-upstream-port value",);
            };
            state.production_runtime_active_dns_upstream_port = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-dns-upstream-port value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-dns-upstream-port=") => {
            state.production_runtime_active_dns_upstream_port =
                match arg.split_once('=').unwrap().1.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        usage!("invalid run --production-runtime-active-dns-upstream-port value",);
                    }
                };
        }
        "--production-runtime-active-dns-qname" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-dns-qname value",);
            };
            state.production_runtime_active_dns_qname = Some(value.to_owned());
        }
        _ if arg.starts_with("--production-runtime-active-dns-qname=") => {
            state.production_runtime_active_dns_qname =
                arg.split_once('=').map(|(_, value)| value.to_owned());
        }
        "--production-runtime-active-dns-benchmark-iters" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-dns-benchmark-iters value",);
            };
            state.production_runtime_active_dns_benchmark_iters = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-dns-benchmark-iters value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-dns-benchmark-iters=") => {
            state.production_runtime_active_dns_benchmark_iters = match arg
                .split_once('=')
                .unwrap()
                .1
                .parse()
            {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-dns-benchmark-iters value",);
                }
            };
        }
        "--execute-production-runtime-reload-parity" => {
            state.production_runtime_reload_parity = true;
        }
        "--production-runtime-active-tcp-upstream-mptcp" => {
            state.production_runtime_active_tcp_upstream_mptcp = Some(true);
        }
        "--production-runtime-active-tcp-upstream-plain-tcp" => {
            state.production_runtime_active_tcp_upstream_mptcp = Some(false);
        }
        "--production-runtime-active-tcp-benchmark-iters" => {
            let Some(value) = iter.next() else {
                usage!("missing run --production-runtime-active-tcp-benchmark-iters value",);
            };
            state.production_runtime_active_tcp_benchmark_iters = match value.parse() {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-tcp-benchmark-iters value",);
                }
            };
        }
        _ if arg.starts_with("--production-runtime-active-tcp-benchmark-iters=") => {
            state.production_runtime_active_tcp_benchmark_iters = match arg
                .split_once('=')
                .unwrap()
                .1
                .parse()
            {
                Ok(value) => Some(value),
                Err(_) => {
                    usage!("invalid run --production-runtime-active-tcp-benchmark-iters value",);
                }
            };
        }
        _ => return Ok(false),
    }
    Ok(true)
}
