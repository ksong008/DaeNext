use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dae_config::Config;
use dae_ebpf_support::{
    AttachBackend, LiveLoadedTproxyListenSocketMap, map_ids,
    open_live_loaded_tproxy_listen_socket_map_in_netns,
};
use serde_json::{Value, json};

use super::command::{
    bpf_dae_snapshot, path_string, runtime_resource_leftovers, wait_for_loaded_map_cleanup,
};
use super::native_ebpf::{NativeEbpfRuntimeState, prepare_native_param_object};
use super::netns_link::resolve_netns_link_mode_from_env;
use super::report::{live_handoff_json, socket_options_verified};
use super::resident_dataplane::{ResidentDataplaneRuntime, start_resident_dataplane_workers};
use super::resident_interfaces::{
    attach_resident_lan_egress_program, attach_resident_wan_programs,
    configure_resident_lan_kernel_parameters, configured_wan_ifaces, interface_link_layer,
};
use super::resident_lan::{
    attach_resident_lan_program, cleanup_resident_lan_programs, configured_lan_ifaces,
    lan_start_plan_json, show_resident_lan_program,
};
use super::resident_routing::{
    seed_resident_outbound_connectivity_maps, update_existing_resident_routing_map,
    update_new_resident_routing_map,
};
use super::topology::{
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_checks,
    read_topology_values, setup_production_ipv4_datapath, show_host_program, show_peer_program,
    write_param_image,
};
use super::{
    DEFAULT_DAE_NETNS_ID, DEFAULT_HOST_SECTION, DEFAULT_PEER_SECTION, PRODUCTION_NETNS,
    ProductionRuntimeOwnerOptions,
};

const EMBEDDED_SOURCE_OBJECT: &[u8] = include_bytes!("../../../../../control/bpf_bpfel.o");
#[cfg(feature = "native-ebpf")]
const EMBEDDED_NATIVE_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o"));
const DEFAULT_SOURCE_OBJECT_ENV: &str = "DAE_RUST_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
const DEFAULT_NATIVE_OBJECT_ENV: &str = "DAE_RUST_NATIVE_BPF_OBJECT";
#[cfg(feature = "native-ebpf")]
const DEFAULT_NATIVE_EBPF_ENV: &str = "DAE_RUST_NATIVE_EBPF";
#[cfg(feature = "native-ebpf")]
const DEFAULT_NATIVE_BACKEND_ENV: &str = "DAE_RUST_NATIVE_EBPF_BACKEND";

#[derive(Debug)]
pub struct ResidentProductionRuntime {
    live_handoff: Option<LiveLoadedTproxyListenSocketMap>,
    native_runtime: NativeEbpfRuntimeState,
    dataplane: Option<ResidentDataplaneRuntime>,
    lan_ifaces: Vec<String>,
    native_lan_ifaces: Vec<String>,
    cleanup_steps: Vec<Value>,
    discovered_map_id: Option<u32>,
    discovered_routing_map_ids: Vec<Option<u32>>,
    before_pin_snapshot: Vec<String>,
    cleanup_file: PathBuf,
    cleaned: bool,
}

impl ResidentProductionRuntime {
    pub fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        if let Some(dataplane) = self.dataplane.as_mut() {
            dataplane.shutdown(&mut self.cleanup_steps);
        }
        self.dataplane = None;
        self.live_handoff.take();
        let native_peer_attached = self.native_runtime.peer_attached();
        let native_host_attached = self.native_runtime.host_attached();
        self.native_runtime.reset();
        cleanup_resident_lan_programs(
            &mut self.cleanup_steps,
            &self.lan_ifaces,
            &self.native_lan_ifaces,
        );
        cleanup_production_topology(
            &mut self.cleanup_steps,
            native_peer_attached,
            native_host_attached,
        );
        let mut discovered_map_ids = Vec::with_capacity(1 + self.discovered_routing_map_ids.len());
        discovered_map_ids.push(self.discovered_map_id);
        discovered_map_ids.extend(self.discovered_routing_map_ids.iter().copied());
        let (after_map_ids, loaded_map_cleaned) = wait_for_loaded_map_cleanup(&discovered_map_ids);
        let after_pin_snapshot = bpf_dae_snapshot();
        let cleanup_report = json!({
            "status": if loaded_map_cleaned && runtime_resource_leftovers(false).is_empty() && self.before_pin_snapshot == after_pin_snapshot {
                "pass"
            } else {
                "fail"
            },
            "cleanup_steps": self.cleanup_steps,
            "after_map_ids": after_map_ids,
            "loaded_map_cleaned": loaded_map_cleaned,
            "leftovers_after_cleanup": runtime_resource_leftovers(false),
            "sys_fs_bpf_dae_mutated": self.before_pin_snapshot != after_pin_snapshot,
        });
        let _ = write_json_file(
            &self.cleanup_file,
            "resident-production-runtime-cleanup",
            cleanup_report,
        );
        self.cleaned = true;
    }
}

impl Drop for ResidentProductionRuntime {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn start_resident_production_runtime(
    config: &Config,
) -> Result<ResidentProductionRuntime, String> {
    let artifact_dir = PathBuf::from(format!(
        "/tmp/dae-daemon-resident-runtime-{}",
        std::process::id()
    ));
    if artifact_dir.exists() {
        fs::remove_dir_all(&artifact_dir).map_err(|err| {
            format!(
                "failed to remove resident production runtime artifact dir {}: {err}",
                path_string(&artifact_dir)
            )
        })?;
    }
    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create resident production runtime artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;

    let source_object = resolve_source_object(&artifact_dir)?;
    let native_object = resolve_native_object(&artifact_dir)?;
    let native_ebpf_opt_in = native_object.is_some();
    let native_ebpf_backend = resolve_native_backend()?;
    let netns_link_mode = resolve_netns_link_mode_from_env()?;
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        source_object,
        tproxy_port: config.global.tproxy_port,
        dae_netns_id: DEFAULT_DAE_NETNS_ID,
        netns_link_mode,
        peer_section: DEFAULT_PEER_SECTION.to_owned(),
        host_section: DEFAULT_HOST_SECTION.to_owned(),
        native_ebpf_opt_in,
        native_ebpf_backend,
        native_ebpf_completed_a3_admission: native_ebpf_opt_in,
        native_ebpf_object: native_object,
        ..ProductionRuntimeOwnerOptions::default()
    };

    let start_file = artifact_dir.join("resident-production-runtime-start.json");
    let cleanup_file = artifact_dir.join("resident-production-runtime-cleanup.json");
    let lan_ifaces = configured_lan_ifaces(config);
    let wan_ifaces = configured_wan_ifaces(config);
    start_with_options(
        options,
        artifact_dir,
        start_file,
        cleanup_file,
        config,
        lan_ifaces,
        wan_ifaces,
    )
}

fn resident_interface_attach_options(
    options: &ProductionRuntimeOwnerOptions,
    lan_ifaces: &[String],
    wan_ifaces: &[String],
) -> (ProductionRuntimeOwnerOptions, Value) {
    let overlapping_ifaces = overlapping_interfaces(lan_ifaces, wan_ifaces);
    let same_interface_multi_role = !overlapping_ifaces.is_empty();
    let effective = options.clone();
    let auto_tcx_multi_role_admitted = same_interface_multi_role
        && options.native_ebpf_opt_in
        && options.native_ebpf_backend == AttachBackend::Auto;
    let explicit_tcx_same_interface = !overlapping_ifaces.is_empty()
        && options.native_ebpf_opt_in
        && options.native_ebpf_backend == AttachBackend::Tcx;
    let effective_backend = effective.native_ebpf_backend;
    (
        effective,
        json!({
            "name": "resident-interface-backend-policy",
            "status": "pass",
            "scope": "resident physical LAN/WAN interface attach backend selection",
            "lan_interfaces": lan_ifaces,
            "wan_interfaces": wan_ifaces,
            "overlapping_interfaces": overlapping_ifaces,
            "requested_backend": options.native_ebpf_backend.as_str(),
            "effective_backend": effective_backend.as_str(),
            "same_interface_multi_role": same_interface_multi_role,
            "auto_tcx_multi_role_admitted": auto_tcx_multi_role_admitted,
            "auto_same_interface_tc_netlink_required": false,
            "auto_downgraded": false,
            "explicit_tcx_same_interface": explicit_tcx_same_interface,
            "reason": if auto_tcx_multi_role_admitted {
                "LAN and WAN share a physical interface; auto keeps TCX candidate and relies on per-filter TCX order plus tc-netlink fallback to preserve Go TC priority semantics"
            } else if explicit_tcx_same_interface {
                "explicit tcx was requested while LAN and WAN share a physical interface; honoring explicit backend with per-filter TCX order"
            } else {
                "no resident interface backend adjustment required"
            },
            "same_interface_tc_netlink_applies_to_all_tc_roles": false,
            "same_interface_tcx_order_policy": "ingress: wan_ingress before lan_ingress; egress: lan_egress before wan_egress; tc-netlink fallback keeps Go priority/handle",
            "dae0_dae0peer_link_layer_unchanged": true,
            "dae0_dae0peer_attach_backend_unchanged": true,
        }),
    )
}

fn overlapping_interfaces(lan_ifaces: &[String], wan_ifaces: &[String]) -> Vec<String> {
    let mut overlaps = Vec::new();
    for lan in lan_ifaces {
        let lan = lan.trim();
        if lan.is_empty() || overlaps.iter().any(|seen| seen == lan) {
            continue;
        }
        if wan_ifaces.iter().any(|wan| wan.trim() == lan) {
            overlaps.push(lan.to_owned());
        }
    }
    overlaps
}

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
    let (interface_attach_options, resident_interface_backend_policy) =
        resident_interface_attach_options(&options, &lan_ifaces, &wan_ifaces);

    let result = (|| {
        let mut ok = true;
        executed_steps.push(resident_interface_backend_policy.clone());
        ok &= setup_runtime_topology(&mut executed_steps, &options);
        let (topology_values, dae0_ifindex, dae0_mac, dae0peer_mac) =
            read_topology_values(&mut executed_steps, &options);
        ok &= dae0_ifindex.is_some() && dae0_mac.is_some() && dae0peer_mac.is_some();
        if let (true, Some(dae0_mac)) = (ok, dae0_mac) {
            ok &= setup_production_ipv4_datapath(&mut executed_steps, dae0_mac);
        }
        let param_image = match (dae0_ifindex, dae0peer_mac) {
            (Some(dae0_ifindex), Some(dae0peer_mac)) => {
                write_param_image(&options, &param_object, dae0_ifindex, dae0peer_mac)
            }
            _ => json!({
                "status": "skipped",
                "path": path_string(&param_object),
                "reason": "topology runtime PARAM values were not available",
            }),
        };
        ok &= param_image["status"].as_str() == Some("pass")
            && param_image["rewritten_param_matches"]
                .as_bool()
                .unwrap_or(false);
        let (selected_native_param_object, native_param_image) = match (dae0_ifindex, dae0peer_mac)
        {
            (Some(dae0_ifindex), Some(dae0peer_mac)) => prepare_native_param_object(
                &options,
                &param_object,
                &native_param_object,
                dae0_ifindex,
                dae0peer_mac,
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
            match live_handoff.as_ref() {
                Some(handoff) => {
                    let (value, runtime) =
                        start_resident_dataplane_workers(handoff, config, &artifact_dir);
                    ok &= value["status"].as_str() == Some("pass");
                    dataplane = runtime;
                    value
                }
                None => {
                    ok = false;
                    json!({
                        "status": "fail",
                        "error": "resident tproxy listener handoff is unavailable",
                    })
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
            "dae_netns_id": options.dae_netns_id,
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
            start_report,
        )?;
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

fn setup_runtime_topology(
    executed_steps: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) -> bool {
    super::topology::setup_production_topology(executed_steps, options)
}

fn resolve_source_object(artifact_dir: &Path) -> Result<PathBuf, String> {
    if let Ok(path) = env::var(DEFAULT_SOURCE_OBJECT_ENV) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "{DEFAULT_SOURCE_OBJECT_ENV} points to a missing source object: {}",
            path_string(&path)
        ));
    }
    let repo_relative = PathBuf::from("control/bpf_bpfel.o");
    if repo_relative.is_file() {
        return Ok(repo_relative);
    }
    let embedded = artifact_dir.join("bpf_bpfel.embedded.o");
    fs::write(&embedded, EMBEDDED_SOURCE_OBJECT).map_err(|err| {
        format!(
            "failed to write embedded resident source object {}: {err}",
            path_string(&embedded)
        )
    })?;
    fs::set_permissions(&embedded, fs::Permissions::from_mode(0o644)).map_err(|err| {
        format!(
            "failed to chmod embedded resident source object {}: {err}",
            path_string(&embedded)
        )
    })?;
    Ok(embedded)
}

#[cfg(feature = "native-ebpf")]
fn resolve_native_object(artifact_dir: &Path) -> Result<Option<PathBuf>, String> {
    if !resident_native_ebpf_enabled() {
        return Ok(None);
    }
    if let Ok(path) = env::var(DEFAULT_NATIVE_OBJECT_ENV) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(Some(path));
        }
        return Err(format!(
            "{DEFAULT_NATIVE_OBJECT_ENV} points to a missing native object: {}",
            path_string(&path)
        ));
    }
    let embedded = artifact_dir.join("bpf_bpfel.native-embedded.o");
    fs::write(&embedded, EMBEDDED_NATIVE_OBJECT).map_err(|err| {
        format!(
            "failed to write embedded resident native object {}: {err}",
            path_string(&embedded)
        )
    })?;
    fs::set_permissions(&embedded, fs::Permissions::from_mode(0o644)).map_err(|err| {
        format!(
            "failed to chmod embedded resident native object {}: {err}",
            path_string(&embedded)
        )
    })?;
    Ok(Some(embedded))
}

#[cfg(not(feature = "native-ebpf"))]
fn resolve_native_object(_artifact_dir: &Path) -> Result<Option<PathBuf>, String> {
    Ok(None)
}

#[cfg(feature = "native-ebpf")]
fn resident_native_ebpf_enabled() -> bool {
    env::var(DEFAULT_NATIVE_EBPF_ENV)
        .map(|value| {
            !matches!(
                value.as_str(),
                "0" | "false" | "FALSE" | "off" | "OFF" | "no" | "NO"
            )
        })
        .unwrap_or(true)
}

#[cfg(feature = "native-ebpf")]
fn resolve_native_backend() -> Result<AttachBackend, String> {
    let Ok(raw) = env::var(DEFAULT_NATIVE_BACKEND_ENV) else {
        return Ok(AttachBackend::TcNetlink);
    };
    parse_native_backend(&raw).ok_or_else(|| {
        format!(
            "{DEFAULT_NATIVE_BACKEND_ENV} must be one of auto, tcx, tc-netlink, tc_netlink, tc-command-fallback, tc_command_fallback; got {raw}"
        )
    })
}

#[cfg(not(feature = "native-ebpf"))]
fn resolve_native_backend() -> Result<AttachBackend, String> {
    Ok(AttachBackend::TcNetlink)
}

#[cfg(feature = "native-ebpf")]
fn parse_native_backend(value: &str) -> Option<AttachBackend> {
    match value {
        "auto" => Some(AttachBackend::Auto),
        "tcx" => Some(AttachBackend::Tcx),
        "tc-netlink" | "tc_netlink" => Some(AttachBackend::TcNetlink),
        "tc-command-fallback" | "tc_command_fallback" => Some(AttachBackend::TcCommandFallback),
        _ => None,
    }
}

fn write_json_file(path: &Path, label: &str, value: Value) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(&value)
        .map_err(|err| format!("failed to encode {label}: {err}"))?;
    fs::write(path, encoded).map_err(|err| format!("failed to write {}: {err}", path_string(path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resident_interface_attach_auto_keeps_tcx_candidate_for_same_lan_wan_iface() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_opt_in: true,
            native_ebpf_backend: AttachBackend::Auto,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let (effective, policy) = resident_interface_attach_options(
            &options,
            &["enp1s0".to_owned()],
            &["enp1s0".to_owned()],
        );
        assert_eq!(effective.native_ebpf_backend, AttachBackend::Auto);
        assert_eq!(policy["effective_backend"], json!("auto"));
        assert_eq!(policy["auto_downgraded"], json!(false));
        assert_eq!(policy["same_interface_multi_role"], json!(true));
        assert_eq!(policy["auto_tcx_multi_role_admitted"], json!(true));
        assert_eq!(
            policy["auto_same_interface_tc_netlink_required"],
            json!(false)
        );
        assert_eq!(policy["overlapping_interfaces"], json!(["enp1s0"]));
        assert_eq!(
            policy["dae0_dae0peer_attach_backend_unchanged"],
            json!(true)
        );
        assert_eq!(
            policy["same_interface_tc_netlink_applies_to_all_tc_roles"],
            json!(false)
        );
        assert_eq!(policy["dae0_dae0peer_link_layer_unchanged"], json!(true));
        assert_eq!(
            policy["same_interface_tcx_order_policy"],
            json!(
                "ingress: wan_ingress before lan_ingress; egress: lan_egress before wan_egress; tc-netlink fallback keeps Go priority/handle"
            )
        );
    }

    #[test]
    fn resident_interface_attach_auto_keeps_backend_for_split_lan_wan_ifaces() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_opt_in: true,
            native_ebpf_backend: AttachBackend::Auto,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let (effective, policy) = resident_interface_attach_options(
            &options,
            &["daerust0".to_owned()],
            &["ens3".to_owned()],
        );
        assert_eq!(effective.native_ebpf_backend, AttachBackend::Auto);
        assert_eq!(policy["auto_downgraded"], json!(false));
        assert_eq!(
            policy["auto_same_interface_tc_netlink_required"],
            json!(false)
        );
        assert_eq!(
            policy["same_interface_tc_netlink_applies_to_all_tc_roles"],
            json!(false)
        );
        assert_eq!(policy["overlapping_interfaces"], json!([]));
    }

    #[test]
    fn resident_interface_attach_honors_explicit_tcx_on_same_lan_wan_iface() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_opt_in: true,
            native_ebpf_backend: AttachBackend::Tcx,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let (effective, policy) = resident_interface_attach_options(
            &options,
            &["enp1s0".to_owned()],
            &["enp1s0".to_owned()],
        );
        assert_eq!(effective.native_ebpf_backend, AttachBackend::Tcx);
        assert_eq!(policy["auto_downgraded"], json!(false));
        assert_eq!(policy["auto_tcx_multi_role_admitted"], json!(false));
        assert_eq!(
            policy["same_interface_tc_netlink_applies_to_all_tc_roles"],
            json!(false)
        );
        assert_eq!(policy["explicit_tcx_same_interface"], json!(true));
    }
}
