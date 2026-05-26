use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use dae_config::Config;
use dae_ebpf_support::{
    LiveLoadedTproxyListenSocketMap, map_ids, open_live_loaded_tproxy_listen_socket_map_in_netns,
};
use serde_json::{Value, json};

use super::command::{
    bpf_dae_snapshot, path_string, runtime_resource_leftovers, wait_for_loaded_map_cleanup,
};
use super::native_ebpf::NativeEbpfRuntimeState;
use super::report::{live_handoff_json, socket_options_verified};
use super::topology::{
    attach_host_program, attach_peer_program, cleanup_production_topology, preflight_checks,
    read_topology_values, show_host_program, show_peer_program, write_param_image,
};
use super::{
    DEFAULT_DAE_NETNS_ID, DEFAULT_HOST_SECTION, DEFAULT_PEER_SECTION, PRODUCTION_NETNS,
    ProductionRuntimeOwnerOptions,
};

const EMBEDDED_SOURCE_OBJECT: &[u8] = include_bytes!("../../../../../control/bpf_bpfel.o");
const DEFAULT_SOURCE_OBJECT_ENV: &str = "DAE_RUST_BPF_OBJECT";

#[derive(Debug)]
pub struct ResidentProductionRuntime {
    live_handoff: Option<LiveLoadedTproxyListenSocketMap>,
    native_runtime: NativeEbpfRuntimeState,
    cleanup_steps: Vec<Value>,
    discovered_map_id: Option<u32>,
    before_pin_snapshot: Vec<String>,
    cleanup_file: PathBuf,
    cleaned: bool,
}

impl ResidentProductionRuntime {
    pub fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.live_handoff.take();
        let native_peer_attached = self.native_runtime.peer_attached();
        let native_host_attached = self.native_runtime.host_attached();
        self.native_runtime.reset();
        cleanup_production_topology(
            &mut self.cleanup_steps,
            native_peer_attached,
            native_host_attached,
        );
        let (after_map_ids, loaded_map_cleaned) =
            wait_for_loaded_map_cleanup(&[self.discovered_map_id]);
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
    let options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: true,
        source_object,
        tproxy_port: config.global.tproxy_port,
        dae_netns_id: DEFAULT_DAE_NETNS_ID,
        peer_section: DEFAULT_PEER_SECTION.to_owned(),
        host_section: DEFAULT_HOST_SECTION.to_owned(),
        ..ProductionRuntimeOwnerOptions::default()
    };

    let start_file = artifact_dir.join("resident-production-runtime-start.json");
    let cleanup_file = artifact_dir.join("resident-production-runtime-cleanup.json");
    start_with_options(options, artifact_dir, start_file, cleanup_file)
}

fn start_with_options(
    options: ProductionRuntimeOwnerOptions,
    artifact_dir: PathBuf,
    start_file: PathBuf,
    cleanup_file: PathBuf,
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
    let mut live_handoff = None;
    let mut native_runtime = NativeEbpfRuntimeState::new();
    let mut discovered_map_id = None;

    let result = (|| {
        let mut ok = true;
        ok &= setup_runtime_topology(&mut executed_steps, &options);
        let (topology_values, dae0_ifindex, _dae0_mac, dae0peer_mac) =
            read_topology_values(&mut executed_steps, &options);
        ok &= dae0_ifindex.is_some() && dae0peer_mac.is_some();
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

        if ok {
            ok &= attach_peer_program(
                &mut executed_steps,
                &options,
                &param_object,
                &param_object,
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

        if ok {
            ok &= attach_host_program(
                &mut executed_steps,
                &options,
                &param_object,
                &param_object,
                &mut native_runtime,
            );
        }
        let host_attach_show = show_host_program(&mut executed_steps);
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
            "param_object": path_string(&param_object),
            "tproxy_port": options.tproxy_port,
            "dae_netns_id": options.dae_netns_id,
            "preflight_checks": checks,
            "before_map_ids": before_map_ids,
            "executed_steps": executed_steps,
            "topology_values": topology_values,
            "param_image": param_image,
            "peer_attach_show": peer_attach_show,
            "host_attach_show": host_attach_show,
            "loaded_map_handoff": loaded_map_handoff,
            "discovered_map_id": discovered_map_id,
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
        drop(live_handoff.take());
        let native_peer_attached = native_runtime.peer_attached();
        let native_host_attached = native_runtime.host_attached();
        native_runtime.reset();
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
        cleanup_steps,
        discovered_map_id,
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

fn write_json_file(path: &Path, label: &str, value: Value) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(&value)
        .map_err(|err| format!("failed to encode {label}: {err}"))?;
    fs::write(path, encoded).map_err(|err| format!("failed to write {}: {err}", path_string(path)))
}
