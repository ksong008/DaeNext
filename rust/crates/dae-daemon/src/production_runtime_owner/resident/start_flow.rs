fn start_with_options(
    options: ProductionRuntimeOwnerOptions,
    artifact_dir: PathBuf,
    start_file: PathBuf,
    cleanup_file: PathBuf,
    config: &Config,
    lan_ifaces: Vec<String>,
    wan_ifaces: Vec<String>,
) -> Result<ResidentProductionRuntime, String> {
    let checks = preflight_checks(&options);
    let blockers = checks
        .iter()
        .filter(|check| check["status"].as_str() != Some("pass"))
        .filter_map(|check| check["blocker"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if !blockers.is_empty() {
        return Err(format!(
            "resident production runtime preflight failed: {}",
            blockers.join("; ")
        ));
    }

    let before_pin_snapshot = bpf_dae_snapshot();
    let before_map_ids = map_ids()
        .map_err(|err| format!("resident production runtime cannot snapshot BPF map ids: {err}"))?;
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let param_object = artifact_dir.join("bpf_bpfel.param.o");
    let native_param_object = artifact_dir.join("bpf_bpfel.native-param.o");
    let mut live_handoff = None;
    let mut dataplane = None;
    let mut native_runtime = NativeEbpfRuntimeState::new();
    let mut discovered_map_id = None;
    let mut discovered_routing_map_ids = Vec::new();
    let mut native_lan_ifaces = Vec::new();
    let mut start_report_for_runtime = Value::Null;
    let (interface_attach_options, resident_interface_backend_policy) =
        resident_interface_attach_options(&options, &lan_ifaces, &wan_ifaces);

    let result = (|| {
        let mut ok = true;
        executed_steps.push(resident_interface_backend_policy.clone());
        ok &= setup_runtime_topology(&mut executed_steps, &options);
        let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac, dae_netns_id) =
            read_topology_values(&mut executed_steps, &options);
        ok &= dae0_ifindex.is_some() && dae0_mac.is_some() && dae0peer_mac.is_some();
        if let (true, Some(dae0_mac)) = (ok, dae0_mac) {
            ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
        }
        let param_image = if options.native_ebpf_opt_in {
            json!({
                "status": "skipped",
                "path": path_string(&param_object),
                "reason": "native Aya object is selected; legacy C eBPF PARAM image is not used by Rust resident",
                "source_object": path_string(&options.source_object),
            })
        } else {
            match (dae0_ifindex, dae0peer_mac) {
                (Some(dae0_ifindex), Some(dae0peer_mac)) => write_param_image(
                    &options,
                    &param_object,
                    dae0_ifindex,
                    dae0peer_mac,
                    dae_netns_id,
                ),
                _ => json!({
                    "status": "skipped",
                    "path": path_string(&param_object),
                    "reason": "topology runtime PARAM values were not available",
                }),
            }
        };
        if !options.native_ebpf_opt_in {
            ok &= param_image["status"].as_str() == Some("pass")
                && param_image["rewritten_param_matches"]
                    .as_bool()
                    .unwrap_or(false);
        }
        let (selected_native_param_object, native_param_image) = match (dae0_ifindex, dae0peer_mac)
        {
            (Some(dae0_ifindex), Some(dae0peer_mac)) => prepare_native_param_object(
                &options,
                &param_object,
                &native_param_object,
                dae0_ifindex,
                dae0peer_mac,
                dae_netns_id,
            ),
            _ => (
                param_object.clone(),
                json!({
                    "status": "skipped",
                    "path": path_string(&native_param_object),
                    "reason": "topology runtime PARAM values were not available",
                    "selected_param_object": path_string(&param_object),
                    "fallback_param_object": path_string(&param_object),
                }),
            ),
        };
        if options.native_ebpf_opt_in {
            ok &= native_param_image["status"].as_str() == Some("pass")
                && native_param_image["rewritten_param_matches"]
                    .as_bool()
                    .unwrap_or(false);
        }

        if ok {
            ok &= attach_peer_program(
                &mut executed_steps,
                &interface_attach_options,
                &param_object,
                &selected_native_param_object,
                &mut native_runtime,
            );
        }
        let peer_attach_show = show_peer_program(&mut executed_steps);

        let loaded_map_handoff = if ok {
            match open_live_loaded_tproxy_listen_socket_map_in_netns(
                &before_map_ids,
                options.tproxy_port,
                PRODUCTION_NETNS,
            ) {
                Ok(handoff) => {
                    let socket_options_verified =
                        socket_options_verified(&handoff.tcp_options, &handoff.udp_options);
                    discovered_map_id = Some(handoff.map.id);
                    let value = live_handoff_json(&handoff);
                    if socket_options_verified {
                        live_handoff = Some(handoff);
                    } else {
                        ok = false;
                    }
                    value
                }
                Err(err) => {
                    ok = false;
                    json!({
                        "status": "fail",
                        "error": err.to_string(),
                    })
                }
            }
        } else {
            json!({
                "status": "skipped",
                "reason": "peer PARAM-aware attach did not pass",
            })
        };

        let resident_cgroup_attach = if wan_ifaces.is_empty() {
            json!({
                "status": "skipped",
                "reason": "wan_interface is not configured; pname cgroup monitor is not required",
                "wan_interfaces": wan_ifaces,
            })
        } else if ok {
            match native_runtime.attach_cgroup_programs(
                &mut executed_steps,
                &interface_attach_options,
                &selected_native_param_object,
            ) {
                Some(true) => json!({
                    "status": "pass",
                    "backend": "aya",
                    "wan_interfaces": wan_ifaces,
                    "native_attached": true,
                }),
                Some(false) => {
                    ok = false;
                    json!({
                        "status": "fail",
                        "backend": "aya",
                        "wan_interfaces": wan_ifaces,
                        "native_attached": false,
                        "error": "native Aya cgroup attach failed; Go BPF cgroup fallback is not used by Rust resident",
                    })
                }
                None => {
                    ok = false;
                    json!({
                        "status": "fail",
                        "backend": Value::Null,
                        "wan_interfaces": wan_ifaces,
                        "native_attached": false,
                        "error": "wan_interface/pname requires native Aya cgroup attach; Go BPF cgroup fallback is not used by Rust resident",
                    })
                }
            }
        } else {
            json!({
                "status": "skipped",
                "reason": "previous resident runtime step did not pass",
                "wan_interfaces": wan_ifaces,
            })
        };

        let (wan_ok, resident_wan_attach) = attach_resident_wan_programs(
            &mut executed_steps,
            &interface_attach_options,
            &selected_native_param_object,
            &mut native_runtime,
            &wan_ifaces,
            ok,
        );
        ok = wan_ok;

        let mut resident_lan_attach = Vec::new();
        let mut resident_lan_routing = Vec::new();
        for iface in &lan_ifaces {
            if ok {
                let lan_kernel_parameters =
                    configure_resident_lan_kernel_parameters(&mut executed_steps, iface);
                let link_layer = match interface_link_layer(iface) {
                    Ok(layer) => layer,
                    Err(err) => {
                        ok = false;
                        resident_lan_attach.push(json!({
                            "interface": iface,
                            "status": "fail",
                            "error": err,
                        }));
                        resident_lan_routing.push(json!({
                            "interface": iface,
                            "routing_map_update": {
                                "status": "skipped",
                                "reason": "resident LAN interface link-layer detection did not pass"
                            },
                        }));
                        continue;
                    }
                };
                let before_lan_map_ids = map_ids().unwrap_or_default();
                let lan_attach = attach_resident_lan_program(
                    &mut executed_steps,
                    &interface_attach_options,
                    iface,
                    link_layer,
                    &param_object,
                    &selected_native_param_object,
                    &mut native_runtime,
                );
                ok &= lan_attach.ok;
                if lan_attach.native_attached {
                    native_lan_ifaces.push(iface.clone());
                }
                let lan_egress_attach = if lan_attach.native_attached && lan_attach.ok {
                    let (egress_ok, egress_report) = attach_resident_lan_egress_program(
                        &mut executed_steps,
                        &interface_attach_options,
                        &selected_native_param_object,
                        &mut native_runtime,
                        iface,
                        link_layer,
                    );
                    ok &= egress_ok;
                    egress_report
                } else {
                    json!({
                        "status": "skipped",
                        "reason": "LAN egress Aya attach is required only for native resident mode after native ingress passes",
                    })
                };
                let show = show_resident_lan_program(&mut executed_steps, iface);
                let routing = if ok {
                    let routing_update = if lan_attach.native_attached {
                        native_runtime
                            .loaded_map_id("routing_map")
                            .ok_or_else(|| {
                                "resident LAN native attach did not expose routing_map".to_owned()
                            })
                            .and_then(|routing_map_id| {
                                update_existing_resident_routing_map(
                                    routing_map_id,
                                    native_runtime.loaded_map_id("lpm_array_map"),
                                    config,
                                )
                            })
                    } else {
                        update_new_resident_routing_map(&before_lan_map_ids, config)
                    };
                    match routing_update {
                        Ok((value, id)) => {
                            discovered_routing_map_ids.push(Some(id));
                            value
                        }
                        Err(err) => {
                            ok = false;
                            json!({
                                "status": "fail",
                                "interface": iface,
                                "error": err,
                            })
                        }
                    }
                } else {
                    json!({
                        "status": "skipped",
                        "interface": iface,
                        "reason": "resident LAN ingress attach did not pass",
                    })
                };
                resident_lan_attach.push(json!({
                    "interface": iface,
                    "status": if lan_attach.ok { "pass" } else { "fail" },
                    "backend": lan_attach.backend,
                    "fallback_used": lan_attach.fallback_used,
                    "native_backend_attempted": lan_attach.native_backend_attempted,
                    "native_backend": lan_attach.native_backend,
                    "native_attached": lan_attach.native_attached,
                    "link_layer": lan_attach.link_layer.suffix(),
                    "kernel_parameters": lan_kernel_parameters,
                    "egress": lan_egress_attach,
                    "show": show,
                }));
                resident_lan_routing.push(json!({
                    "interface": iface,
                    "routing_map_update": routing,
                }));
            } else {
                resident_lan_attach.push(json!({
                    "interface": iface,
                    "backend": Value::Null,
                    "fallback_used": Value::Null,
                    "native_backend_attempted": false,
                    "native_backend": Value::Null,
                    "native_attached": false,
                    "link_layer": Value::Null,
                    "kernel_parameters": Value::Null,
                    "egress": Value::Null,
                    "show": Value::Null,
                    "status": "skipped",
                    "reason": "previous resident runtime step did not pass",
                }));
                resident_lan_routing.push(json!({
                    "interface": iface,
                    "routing_map_update": {
                        "status": "skipped",
                        "reason": "previous resident runtime step did not pass"
                    },
                }));
            }
        }

        let resident_dataplane = if ok {
            if !resident_dataplane_enabled() {
                json!({
                    "status": "pass",
                    "enabled": false,
                    "reason": "resident Rust userspace protocol dataplane is disabled by default; current production goal is native Aya/eBPF loader and attach parity while Go userspace outbound remains authoritative",
                    "opt_in_env": DEFAULT_RESIDENT_DATAPLANE_ENV,
                    "scope": "loader-only admission boundary; set DAE_RUST_RESIDENT_DATAPLANE=1 only for explicit Rust protocol dataplane experiments",
                })
            } else {
                match live_handoff.as_ref() {
                    Some(handoff) => match discover_routing_tuple_map(&native_runtime, handoff) {
                        Ok(discovery) => {
                            let (mut value, runtime) = start_resident_dataplane_workers(
                                handoff,
                                config,
                                &artifact_dir,
                                discovery.id,
                            );
                            if let Value::Object(map) = &mut value {
                                map.insert(
                                    "routing_tuple_map_source".to_owned(),
                                    json!(discovery.source),
                                );
                                map.insert(
                                    "routing_tuple_candidate_map_ids".to_owned(),
                                    json!(discovery.candidate_map_ids),
                                );
                            }
                            ok &= value["status"].as_str() == Some("pass");
                            dataplane = runtime;
                            value
                        }
                        Err(err) => {
                            ok = false;
                            json!({
                                "status": "fail",
                                "enabled": true,
                                "error": err,
                                "routing_tuple_map_source": "discovery-error",
                            })
                        }
                    },
                    None => {
                        ok = false;
                        json!({
                            "status": "fail",
                            "error": "resident tproxy listener handoff is unavailable",
                        })
                    }
                }
            }
        } else {
            json!({
                "status": "skipped",
                "reason": "previous resident runtime step did not pass",
            })
        };

        if ok {
            ok &= attach_host_program(
                &mut executed_steps,
                &interface_attach_options,
                &param_object,
                &selected_native_param_object,
                &mut native_runtime,
            );
        }
        let host_attach_show = show_host_program(&mut executed_steps);
        let resident_outbound_connectivity = if ok {
            match seed_resident_outbound_connectivity_maps(config) {
                Ok(value) => value,
                Err(err) => {
                    ok = false;
                    json!({
                        "status": "fail",
                        "error": err,
                    })
                }
            }
        } else {
            json!({
                "status": "skipped",
                "reason": "previous resident runtime step did not pass",
            })
        };
        let peer_output = peer_attach_show["stdout"].as_str().unwrap_or_default();
        let host_output = host_attach_show["stdout"].as_str().unwrap_or_default();
        let attach_outputs_passed = peer_attach_show["status"].as_str() == Some("pass")
            && peer_output.contains(&options.peer_section)
            && peer_output.contains("tproxy_dae0peer")
            && host_attach_show["status"].as_str() == Some("pass")
            && host_output.contains(&options.host_section)
            && host_output.contains("tproxy_dae0_ing");
        let attach_outputs_passed = attach_outputs_passed
            || (native_runtime.peer_attached() && native_runtime.host_attached());
        ok &= attach_outputs_passed;

        let start_report = json!({
            "name": "resident-production-runtime",
            "status": if ok { "pass" } else { "fail" },
            "artifact_dir": path_string(&artifact_dir),
            "start_file": path_string(&start_file),
            "cleanup_file": path_string(&cleanup_file),
            "source_object": path_string(&options.source_object),
            "native_object": options.native_ebpf_object.as_ref().map(|path| path_string(path)),
            "param_object": path_string(&param_object),
            "native_param_object": path_string(&selected_native_param_object),
            "tproxy_port": options.tproxy_port,
            "requested_dae_netns_id": options.dae_netns_id,
            "dae_netns_id": dae_netns_id,
            "preflight_checks": checks,
            "before_map_ids": before_map_ids,
            "executed_steps": executed_steps,
            "topology_values": topology_values,
            "param_image": param_image,
            "native_param_image": native_param_image,
            "peer_attach_show": peer_attach_show,
            "resident_cgroup_attach": resident_cgroup_attach,
            "resident_wan_attach": resident_wan_attach,
            "resident_interface_backend_policy": resident_interface_backend_policy,
            "resident_lan_plan": lan_start_plan_json(&lan_ifaces, options.native_ebpf_opt_in, &resident_lan_attach),
            "resident_native_cgroup_attached": native_runtime.cgroup_attached(),
            "resident_native_lan_ifaces": native_lan_ifaces.clone(),
            "resident_lan_attach": resident_lan_attach,
            "resident_lan_routing": resident_lan_routing,
            "resident_dataplane": resident_dataplane,
            "host_attach_show": host_attach_show,
            "resident_outbound_connectivity": resident_outbound_connectivity,
            "loaded_map_handoff": loaded_map_handoff,
            "discovered_map_id": discovered_map_id,
            "discovered_routing_map_ids": discovered_routing_map_ids.clone(),
            "resident_runtime_started": ok,
        });
        write_json_file(
            &start_file,
            "resident-production-runtime-start",
            start_report.clone(),
        )?;
        start_report_for_runtime = compact_start_report_for_runtime(&start_report);
        if ok {
            Ok(())
        } else {
            Err(format!(
                "resident production runtime start failed; start_file={}",
                path_string(&start_file)
            ))
        }
    })();

    if let Err(err) = result {
        if let Some(dataplane) = dataplane.as_mut() {
            dataplane.shutdown(&mut cleanup_steps);
        }
        drop(live_handoff.take());
        let native_peer_attached = native_runtime.peer_attached();
        let native_host_attached = native_runtime.host_attached();
        native_runtime.reset();
        cleanup_resident_lan_programs(&mut cleanup_steps, &lan_ifaces, &native_lan_ifaces);
        cleanup_production_topology(
            &mut cleanup_steps,
            native_peer_attached,
            native_host_attached,
        );
        return Err(err);
    }

    Ok(ResidentProductionRuntime {
        live_handoff,
        native_runtime,
        dataplane,
        start_report: start_report_for_runtime,
        lan_ifaces,
        native_lan_ifaces,
        cleanup_steps,
        discovered_map_id,
        discovered_routing_map_ids,
        before_pin_snapshot,
        cleanup_file,
        cleaned: false,
    })
}
