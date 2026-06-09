use super::*;
#[derive(Default)]
pub(super) struct ExecutionEvidence {
    pub(super) executed_steps: Vec<Value>,
    pub(super) cleanup_steps: Vec<Value>,
    pub(super) topology_values: Value,
    pub(super) param_image: Value,
    pub(super) peer_attach_show: Value,
    pub(super) host_attach_show: Value,
    pub(super) native_param_image: Value,
    pub(super) loaded_map_handoff: Value,
    pub(super) before_map_ids: Vec<u32>,
    pub(super) after_map_ids: Vec<u32>,
    pub(super) discovered_map_id: Option<u32>,
    pub(super) discovered_routing_map_id: Option<u32>,
    pub(super) loaded_map_cleaned: bool,
    pub(super) leftovers_after_cleanup: Vec<String>,
    pub(super) sys_fs_bpf_dae_mutated: bool,
    pub(super) socket_options_verified: bool,
    pub(super) active_tcp: ActiveTcpEvidence,
    pub(super) active_udp: ActiveUdpEvidence,
    pub(super) active_dns: ActiveDnsEvidence,
    pub(super) reload_runtime: ReloadRuntimeEvidence,
    pub(super) owner_smoke_passed: bool,
}

pub(super) fn execute_owner_smoke(
    options: &ProductionRuntimeOwnerOptions,
    param_object: &Path,
) -> Result<ExecutionEvidence, String> {
    let before_pin_snapshot = bpf_dae_snapshot();
    let before_map_ids = map_ids()
        .map_err(|err| format!("production runtime owner cannot snapshot BPF map ids: {err}"))?;
    let mut evidence = ExecutionEvidence {
        before_map_ids: before_map_ids.clone(),
        ..ExecutionEvidence::default()
    };
    let mut native_runtime = NativeEbpfRuntimeState::new();

    let mut ok = true;
    ok &= setup_production_topology(&mut evidence.executed_steps, options);
    if options.execute_active_tcp {
        ok &= setup_client_topology(&mut evidence.executed_steps, options);
    }
    let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac, dae_netns_id) =
        read_topology_values(&mut evidence.executed_steps, options);
    evidence.topology_values = topology_values;
    ok &= dae0_ifindex.is_some() && dae0peer_mac.is_some();
    if options.execute_active_tcp {
        if let Some(dae0_mac) = dae0_mac {
            ok &= setup_production_ipv4_datapath(&mut evidence.executed_steps, dae0_mac);
        } else {
            ok = false;
        }
    }

    evidence.param_image = match (dae0_ifindex, dae0peer_mac) {
        (Some(dae0_ifindex), Some(dae0peer_mac)) => write_param_image(
            options,
            param_object,
            dae0_ifindex,
            dae0peer_mac,
            dae_netns_id,
        ),
        _ => json!({
            "status": "skipped",
            "path": path_string(param_object),
            "reason": "topology runtime PARAM values were not available",
        }),
    };
    ok &= evidence.param_image["status"].as_str() == Some("pass")
        && evidence.param_image["rewritten_param_matches"]
            .as_bool()
            .unwrap_or(false);
    let native_param_object = param_object.with_file_name("bpf_bpfel.native-param.o");
    let native_param_object = match (ok, dae0_ifindex, dae0peer_mac) {
        (true, Some(dae0_ifindex), Some(dae0peer_mac)) => {
            let (path, image) = native_ebpf::prepare_native_param_object(
                options,
                param_object,
                &native_param_object,
                dae0_ifindex,
                dae0peer_mac,
                dae_netns_id,
            );
            evidence.native_param_image = image;
            path
        }
        _ => {
            evidence.native_param_image = json!({
                "status": "skipped",
                "reason": "topology runtime PARAM values were not available",
            });
            param_object.to_path_buf()
        }
    };

    if ok {
        ok &= attach_peer_program(
            &mut evidence.executed_steps,
            options,
            param_object,
            &native_param_object,
            &mut native_runtime,
        );
    }
    evidence.peer_attach_show = show_peer_program(&mut evidence.executed_steps);

    let mut live_handoff = None;
    if ok {
        match open_live_loaded_tproxy_listen_socket_map_in_netns(
            &before_map_ids,
            options.tproxy_port,
            PRODUCTION_NETNS,
        ) {
            Ok(handoff) => {
                evidence.socket_options_verified =
                    socket_options_verified(&handoff.tcp_options, &handoff.udp_options);
                evidence.discovered_map_id = Some(handoff.map.id);
                evidence.loaded_map_handoff = live_handoff_json(&handoff);
                live_handoff = Some(handoff);
            }
            Err(err) => {
                ok = false;
                evidence.loaded_map_handoff = json!({
                    "status": "fail",
                    "error": err.to_string(),
                });
            }
        }
    } else {
        evidence.loaded_map_handoff = json!({
            "status": "skipped",
            "reason": "peer PARAM-aware attach did not pass",
        });
    }
    ok &= evidence.socket_options_verified;

    if options.execute_active_tcp && ok {
        let before_lan_map_ids = map_ids().unwrap_or_default();
        ok &= attach_lan_program(
            &mut evidence.executed_steps,
            options,
            param_object,
            &native_param_object,
            &mut native_runtime,
        );
        evidence.active_tcp.lan_attach_show = show_lan_program(&mut evidence.executed_steps);
        let routing_map_update = if native_runtime.lan_attached() {
            native_runtime
                .loaded_map_id("routing_map")
                .ok_or_else(|| "native loaded routing_map id is unavailable".to_owned())
                .and_then(|id| update_existing_routing_map(id, options.active_tcp_so_mark))
        } else {
            update_routing_map(&before_lan_map_ids, options.active_tcp_so_mark)
        };
        match routing_map_update {
            Ok((value, id)) => {
                evidence.active_tcp.route_map_update = value;
                evidence.active_tcp.discovered_routing_map_id = Some(id);
                evidence.discovered_routing_map_id = Some(id);
            }
            Err(err) => {
                ok = false;
                evidence.active_tcp.route_map_update = json!({"status": "fail", "error": err});
            }
        }
    }

    if ok {
        ok &= attach_host_program(
            &mut evidence.executed_steps,
            options,
            param_object,
            &native_param_object,
            &mut native_runtime,
        );
    }
    evidence.host_attach_show = show_host_program(&mut evidence.executed_steps);

    if options.execute_active_tcp {
        evidence.active_tcp.enabled = true;
        if ok {
            let listener = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.tcp_listener.try_clone().ok());
            match listener {
                Some(listener) => {
                    let relay_listener = if options.execute_active_tcp_relay {
                        listener.try_clone().ok()
                    } else {
                        None
                    };
                    let (
                        tcp_accept,
                        client_traffic,
                        original_destination_observed,
                        tcp_reply_path_succeeded,
                    ) = run_active_tcp_probe(listener, options);
                    evidence.active_tcp.tcp_accept = tcp_accept;
                    evidence.active_tcp.client_traffic = client_traffic;
                    evidence.active_tcp.original_destination_observed =
                        original_destination_observed;
                    evidence.active_tcp.tcp_reply_path_succeeded = tcp_reply_path_succeeded;
                    evidence.active_tcp.passed = evidence.active_tcp.tcp_accept["status"].as_str()
                        == Some("pass")
                        && evidence.active_tcp.client_traffic["status"].as_str() == Some("pass")
                        && original_destination_observed
                        && tcp_reply_path_succeeded;
                    if let Some(relay_listener) = relay_listener {
                        let (
                            relay_accept,
                            upstream,
                            relay_client_traffic,
                            outbound_dial,
                            benchmark,
                            relay_original_destination_observed,
                            outbound_relay_succeeded,
                            so_mark_observed,
                            mptcp_observed,
                        ) = active_tcp::run_active_tcp_relay_probe(relay_listener, options);
                        evidence.active_tcp.relay_accept = relay_accept;
                        evidence.active_tcp.upstream = upstream;
                        evidence.active_tcp.relay_client_traffic = relay_client_traffic;
                        evidence.active_tcp.outbound_dial = outbound_dial;
                        evidence.active_tcp.relay_benchmark = benchmark;
                        evidence.active_tcp.relay_original_destination_observed =
                            relay_original_destination_observed;
                        evidence.active_tcp.outbound_relay_succeeded = outbound_relay_succeeded;
                        evidence.active_tcp.so_mark_observed = so_mark_observed;
                        evidence.active_tcp.mptcp_observed = mptcp_observed;
                        evidence.active_tcp.relay_passed =
                            evidence.active_tcp.relay_accept["status"].as_str() == Some("pass")
                                && evidence.active_tcp.upstream["status"].as_str() == Some("pass")
                                && evidence.active_tcp.relay_client_traffic["status"].as_str()
                                    == Some("pass")
                                && relay_original_destination_observed
                                && outbound_relay_succeeded
                                && so_mark_observed
                                && (!options.active_tcp_mptcp || mptcp_observed);
                        evidence.active_tcp.passed &=
                            !options.execute_active_tcp_relay || evidence.active_tcp.relay_passed;
                    } else if options.execute_active_tcp_relay {
                        evidence.active_tcp.relay_accept = json!({
                            "status": "fail",
                            "error": "failed to clone tproxy TCP listener for relay",
                        });
                        evidence.active_tcp.passed = false;
                    }
                }
                None => {
                    evidence.active_tcp.tcp_accept =
                        json!({"status": "fail", "error": "failed to clone tproxy TCP listener"});
                }
            }
        } else {
            evidence.active_tcp.tcp_accept = json!({
                "status": "skipped",
                "reason": "BPF attach or routing map update did not pass",
            });
        }
        evidence.active_tcp.post_traffic_peer_stats =
            show_peer_program_stats(&mut evidence.executed_steps);
        evidence.active_tcp.post_traffic_lan_stats =
            show_lan_program_stats(&mut evidence.executed_steps);
        evidence.active_tcp.post_traffic_host_stats =
            show_host_program_stats(&mut evidence.executed_steps);
        ok &= evidence.active_tcp.passed;
    }

    if options.execute_active_udp {
        if ok {
            ok &= add_active_udp_loopback_target(&mut evidence.executed_steps, options);
            let udp_socket = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
            match udp_socket {
                Some(udp_socket) => {
                    evidence.active_udp = run_active_udp_probe(udp_socket, options);
                    ok &= evidence.active_udp.passed;
                }
                None => {
                    evidence.active_udp = ActiveUdpEvidence {
                        enabled: true,
                        udp_receive: json!({
                            "status": "fail",
                            "error": "failed to clone tproxy UDP socket for active UDP",
                        }),
                        ..ActiveUdpEvidence::default()
                    };
                    ok = false;
                }
            }
        } else {
            evidence.active_udp = ActiveUdpEvidence {
                enabled: true,
                udp_receive: json!({
                    "status": "skipped",
                    "reason": "production owner or active TCP evidence did not pass before active UDP",
                }),
                ..ActiveUdpEvidence::default()
            };
        }
        evidence.active_udp.post_traffic_peer_stats =
            show_peer_program_stats(&mut evidence.executed_steps);
        evidence.active_udp.post_traffic_lan_stats =
            show_lan_program_stats(&mut evidence.executed_steps);
        evidence.active_udp.post_traffic_host_stats =
            show_host_program_stats(&mut evidence.executed_steps);
    }

    if options.execute_active_dns {
        if ok {
            let udp_socket = live_handoff
                .as_ref()
                .and_then(|handoff| handoff.listeners.udp_socket.try_clone().ok());
            match udp_socket {
                Some(udp_socket) => {
                    evidence.active_dns = run_active_dns_probe(udp_socket, options);
                    ok &= evidence.active_dns.passed;
                }
                None => {
                    evidence.active_dns = ActiveDnsEvidence {
                        enabled: true,
                        dns_receive: json!({
                            "status": "fail",
                            "error": "failed to clone tproxy UDP socket for active DNS",
                        }),
                        ..ActiveDnsEvidence::default()
                    };
                    ok = false;
                }
            }
        } else {
            evidence.active_dns = ActiveDnsEvidence {
                enabled: true,
                dns_receive: json!({
                    "status": "skipped",
                    "reason": "production owner, active TCP, or active UDP evidence did not pass before active DNS",
                }),
                ..ActiveDnsEvidence::default()
            };
        }
        evidence.active_dns.post_traffic_peer_stats =
            show_peer_program_stats(&mut evidence.executed_steps);
        evidence.active_dns.post_traffic_lan_stats =
            show_lan_program_stats(&mut evidence.executed_steps);
        evidence.active_dns.post_traffic_host_stats =
            show_host_program_stats(&mut evidence.executed_steps);
    }

    if options.execute_reload_runtime_parity {
        if ok {
            match live_handoff.as_ref() {
                Some(handoff) => {
                    let post_reload_tcp_listener = handoff.listeners.tcp_listener.try_clone().ok();
                    let artifact_dir = param_object.parent().unwrap_or_else(|| Path::new("/tmp"));
                    evidence.reload_runtime = run_reload_runtime_parity_probe(
                        handoff,
                        options,
                        artifact_dir,
                        post_reload_tcp_listener,
                    );
                    ok &= evidence.reload_runtime.passed;
                }
                None => {
                    evidence.reload_runtime = ReloadRuntimeEvidence {
                        enabled: true,
                        listener_reuse: json!({
                            "status": "fail",
                            "error": "live production listener/sockmap handoff was unavailable",
                        }),
                        ..ReloadRuntimeEvidence::default()
                    };
                    ok = false;
                }
            }
        } else {
            evidence.reload_runtime = ReloadRuntimeEvidence {
                enabled: true,
                listener_reuse: json!({
                    "status": "skipped",
                    "reason": "production owner or active TCP evidence did not pass before reload/runtime parity",
                }),
                ..ReloadRuntimeEvidence::default()
            };
        }
    }

    let peer_output = evidence.peer_attach_show["stdout"]
        .as_str()
        .unwrap_or_default();
    let host_output = evidence.host_attach_show["stdout"]
        .as_str()
        .unwrap_or_default();
    let attach_outputs_passed = evidence.peer_attach_show["status"].as_str() == Some("pass")
        && peer_output.contains(&options.peer_section)
        && peer_output.contains("tproxy_dae0peer")
        && evidence.host_attach_show["status"].as_str() == Some("pass")
        && host_output.contains(&options.host_section)
        && host_output.contains("tproxy_dae0_ing");
    let attach_outputs_passed =
        attach_outputs_passed || (native_runtime.peer_attached() && native_runtime.host_attached());

    let native_peer_attached = native_runtime.peer_attached();
    let native_lan_attached = native_runtime.lan_attached();
    let native_host_attached = native_runtime.host_attached();
    drop(live_handoff);
    native_runtime.reset();
    if options.execute_active_udp {
        delete_active_udp_loopback_target(&mut evidence.cleanup_steps, options);
    }
    if options.execute_active_tcp {
        cleanup_active_tcp_resources(&mut evidence.cleanup_steps, native_lan_attached);
    }
    cleanup_production_topology(
        &mut evidence.cleanup_steps,
        native_peer_attached,
        native_host_attached,
    );
    let after_pin_snapshot = bpf_dae_snapshot();
    let (after_map_ids, loaded_map_cleaned) = wait_for_loaded_map_cleanup(&[
        evidence.discovered_map_id,
        evidence.discovered_routing_map_id,
    ]);
    evidence.after_map_ids = after_map_ids;
    evidence.loaded_map_cleaned = loaded_map_cleaned;
    evidence.leftovers_after_cleanup = runtime_resource_leftovers(options.execute_active_tcp);
    if options.execute_active_udp
        && active_udp_loopback_target_present(&options.active_udp_target_ip)
    {
        let target = active_udp_loopback_target_cidr(&options.active_udp_target_ip)
            .unwrap_or_else(|_| options.active_udp_target_ip.clone());
        evidence
            .leftovers_after_cleanup
            .push(format!("loopback-target:{target}"));
    }
    evidence.sys_fs_bpf_dae_mutated = before_pin_snapshot != after_pin_snapshot;
    evidence.owner_smoke_passed = ok
        && attach_outputs_passed
        && loaded_map_cleaned
        && evidence.leftovers_after_cleanup.is_empty()
        && !evidence.sys_fs_bpf_dae_mutated;
    Ok(evidence)
}
