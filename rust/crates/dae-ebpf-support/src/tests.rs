use std::mem::{align_of, offset_of, size_of};
use std::path::PathBuf;

use serde_json::Value;

use crate::*;

#[test]
fn bpf_abi_layout_matches_golden_fixture() {
    let fixture = load("ebpf/abi/layout.json");
    assert_eq!(
        TASK_COMM_LEN,
        fixture["task_comm_len"].as_u64().unwrap() as usize
    );
    assert_eq!(
        MAX_MATCH_SET_LEN,
        fixture["max_match_set_len"]["value"].as_u64().unwrap() as usize
    );
    assert_eq!(TPROXY_MARK, fixture["tproxy_mark"].as_u64().unwrap() as u32);

    assert_layout::<BpfDaeParam>(&fixture, "bpfDaeParam", 24, 4);
    assert_offset::<BpfDaeParam>(
        &fixture,
        "bpfDaeParam",
        "tproxy_port",
        offset_of!(BpfDaeParam, tproxy_port),
    );
    assert_offset::<BpfDaeParam>(
        &fixture,
        "bpfDaeParam",
        "dae0peer_mac",
        offset_of!(BpfDaeParam, dae0peer_mac),
    );
    assert_offset::<BpfDaeParam>(
        &fixture,
        "bpfDaeParam",
        "has_bpf_get_current_task",
        offset_of!(BpfDaeParam, has_bpf_get_current_task),
    );

    assert_layout::<BpfDomainRouting>(&fixture, "bpfDomainRouting", 128, 4);
    assert_layout::<BpfMatchSet>(&fixture, "bpfMatchSet", 24, 4);
    assert_offset::<BpfMatchSet>(
        &fixture,
        "bpfMatchSet",
        "mark",
        offset_of!(BpfMatchSet, mark),
    );
    assert_layout::<BpfOutboundConnectivityQuery>(&fixture, "bpfOutboundConnectivityQuery", 3, 1);
    assert_layout::<BpfPidPname>(&fixture, "bpfPidPname", 20, 4);
    assert_layout::<BpfRedirectEntry>(&fixture, "bpfRedirectEntry", 20, 4);
    assert_layout::<BpfRedirectTuple>(&fixture, "bpfRedirectTuple", 32, 1);
    assert_layout::<BpfRoutingResult>(&fixture, "bpfRoutingResult", 36, 4);
    assert_offset::<BpfRoutingResult>(
        &fixture,
        "bpfRoutingResult",
        "outbound",
        offset_of!(BpfRoutingResult, outbound),
    );
    assert_layout::<BpfTuplesKey>(&fixture, "bpfTuplesKey", 40, 2);
    assert_layout::<BpfUdpConnState>(&fixture, "bpfUdpConnState", 24, 8);
}

#[test]
fn map_catalog_matches_golden_fixture() {
    let fixture = load("ebpf/maps/catalog.json");
    let maps = fixture["maps"].as_array().unwrap();
    assert_eq!(map_catalog().len(), maps.len());
    for (got, expected) in map_catalog().iter().zip(maps) {
        assert_eq!(got.name, expected["name"].as_str().unwrap());
        assert_eq!(got.map_type, expected["type"].as_str().unwrap());
        assert_eq!(got.key_size, expected["key_size"].as_u64().unwrap() as u32);
        assert_eq!(
            got.value_size,
            expected["value_size"].as_u64().unwrap() as u32
        );
        assert_eq!(
            got.max_entries,
            expected["max_entries"].as_u64().unwrap() as u32
        );
        assert_eq!(got.flags, expected["flags"].as_u64().unwrap() as u32);
        assert_eq!(got.pinning, expected["pinning"].as_str().unwrap());
    }
    let pinned = fixture["pinned_reuse"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(pinned_reuse_maps(), pinned.as_slice());
    assert_eq!(
        pinned_map_action("use pinned map routing_tuples_map: field mismatch"),
        PinnedMapAction::DeleteAndRetry {
            map_name: "routing_tuples_map".to_owned()
        }
    );
    assert_eq!(
        pinned_map_action("other loader error"),
        PinnedMapAction::ReturnError
    );
}

#[test]
fn ebpf_runtime_contracts_keep_abi_maps_and_loader_boundaries_explicit() {
    let abi = bpf_abi_contract();
    assert_eq!(abi.dae_param_size, size_of::<BpfDaeParam>());
    assert_eq!(abi.task_comm_len, TASK_COMM_LEN);
    assert_eq!(abi.max_match_set_len, MAX_MATCH_SET_LEN);
    assert_eq!(abi.tproxy_mark, TPROXY_MARK);

    let loader = loader_contract();
    assert_eq!(loader.default_object_loader, LoaderBackend::TcCommandObject);
    assert_eq!(loader.runtime_map_backend, LoaderBackend::RustSyscallMaps);
    assert!(loader.aya_userspace_loader_planned);
    assert!(loader.c_ebpf_object_fallback_required);
    assert!(!loader.go_fallback_preserved);
    assert!(loader.go_bpf_loader_fallback_retired);
    assert!(loader.param_rewrite_required_before_attach);

    let maps = runtime_map_contract();
    assert_eq!(maps.len(), map_catalog().len());
    let listen = maps
        .iter()
        .find(|entry| entry.spec.name == "listen_socket_map")
        .unwrap();
    assert_eq!(listen.role, RuntimeMapRole::SocketHandoff);
    assert!(!listen.reusable_pin);

    for name in pinned_reuse_maps() {
        let entry = maps.iter().find(|entry| entry.spec.name == *name).unwrap();
        assert_eq!(entry.role, RuntimeMapRole::PinnedReuse);
        assert!(entry.reusable_pin);
        assert!(entry.spec.pinned_by_name());
    }
}

#[test]
fn attach_backend_plan_keeps_command_fallback_until_native_attach_is_available() {
    let fallback = plan_attach_backend(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability::command_fallback_only(),
    );
    assert!(fallback.tcx_supported);
    assert_eq!(
        fallback.attempt_order,
        vec![
            AttachBackend::Tcx,
            AttachBackend::TcNetlink,
            AttachBackend::TcCommandFallback,
        ]
    );
    assert_eq!(fallback.selected, Some(AttachBackend::TcCommandFallback));
    assert!(fallback.command_fallback_used);

    let native_tcx = plan_attach_backend(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability {
            tcx: true,
            tc_netlink: true,
            tc_command_fallback: true,
        },
    );
    assert_eq!(native_tcx.selected, Some(AttachBackend::Tcx));
    assert!(!native_tcx.command_fallback_used);
}

#[test]
fn report_only_backend_capability_keeps_default_command_fallback() {
    let report = report_only_ebpf_backend_capability(Some(Version::new(6, 6, 0)));
    assert!(report.report_only);
    assert_eq!(report.aya_userspace_available, cfg!(feature = "aya-loader"));
    assert!(!report.tc_netlink_available);
    assert!(report.tcx_supported);
    assert!(!report.tcx_available);
    assert_eq!(
        report.selected_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert!(report.command_fallback_used);
    assert_eq!(report.fallback_reason, Some("native_backends_report_only"));
    assert_eq!(
        report.attach_plan.attempt_order,
        vec![
            AttachBackend::Tcx,
            AttachBackend::TcNetlink,
            AttachBackend::TcCommandFallback,
        ]
    );
    assert_eq!(
        report.loader_contract.default_object_loader.as_str(),
        "tc_command_object"
    );
    assert_eq!(
        report.loader_contract.runtime_map_backend.as_str(),
        "rust_syscall_maps"
    );
    assert_eq!(AttachBackend::Tcx.as_str(), "tcx");
}

#[cfg(feature = "aya-loader")]
#[test]
fn aya_userspace_load_report_records_catalog_and_fallback_boundaries() {
    let object = PathBuf::from("/tmp/bpf_bpfel.param.o");
    let pin_path = PathBuf::from("/sys/fs/bpf/dae");
    let loaded_maps = map_catalog()
        .iter()
        .map(|spec| spec.name.to_owned())
        .collect::<Vec<_>>();
    let report = aya_userspace_load_report(
        &object,
        true,
        Some(&pin_path),
        true,
        loaded_maps,
        vec![
            "tc/dae0peer_ingress".to_owned(),
            "tc/dae0_ingress".to_owned(),
        ],
        &[],
        Vec::new(),
    );

    assert_eq!(report.object, object);
    assert!(report.param_global_set);
    assert_eq!(report.map_pin_path, Some(pin_path));
    assert!(report.allow_unsupported_maps);
    assert!(report.missing_catalog_maps.is_empty());
    assert_eq!(report.pinned_reuse_maps_present, pinned_reuse_maps());
    assert!(report.listen_socket_map_present);
    assert_eq!(report.loader_backend, LoaderBackend::AyaUserspace);
    assert_eq!(
        report.default_attach_backend,
        AttachBackend::TcCommandFallback
    );
    assert!(report.c_ebpf_object_fallback_required);
    assert!(report.command_fallback_required);
    assert_eq!(
        report.loaded_program_names,
        vec!["tc/dae0_ingress", "tc/dae0peer_ingress"]
    );
}

#[cfg(feature = "aya-loader")]
#[test]
fn aya_userspace_real_object_load_smoke_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_LOAD_SMOKE").is_none() {
        return;
    }

    let root = dae_golden::repo_root_from_manifest().unwrap();
    let aya_object = temp_path("dae-aya-compatible-bpf_bpfel.o");
    build_aya_compatible_bpf_object(&root, &aya_object);
    let pin_root = match default_bpffs_mount() {
        Ok(bpffs) => bpffs.join(format!("dae-aya-load-smoke-{}", std::process::id())),
        Err(err) => {
            eprintln!("skip aya userspace real object load smoke: {err}");
            return;
        }
    };
    std::fs::create_dir_all(&pin_root).unwrap();
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: std::process::id(),
        dae0_ifindex: 1,
        dae_netns_id: 49,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    let loaded = load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object: &aya_object,
        param: Some(param),
        map_pin_path: Some(&pin_root),
        allow_unsupported_maps: true,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
    });
    let _ = std::fs::remove_dir_all(&pin_root);
    let _ = std::fs::remove_file(&aya_object);
    match loaded {
        Ok(loaded) => {
            assert!(loaded.report.param_global_set);
            assert!(loaded.report.missing_catalog_maps.is_empty());
            assert!(loaded.report.listen_socket_map_present);
            assert_eq!(loaded.report.loader_backend, LoaderBackend::AyaUserspace);
            assert_eq!(loaded.report.map_in_map_pins.len(), 1);
            assert_eq!(
                loaded.report.map_in_map_pins[0].outer_map_name,
                "lpm_array_map"
            );
            assert_eq!(
                loaded.report.default_attach_backend,
                AttachBackend::TcCommandFallback
            );
        }
        Err(err) => {
            panic!("aya userspace real object load smoke failed: {err}");
        }
    }
}

#[cfg(feature = "aya-loader")]
#[test]
fn aya_tc_attach_detach_smoke_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_TC_ATTACH_SMOKE").is_none() {
        return;
    }

    run_aya_host_veth_attach_detach_smoke(
        AttachBackend::TcNetlink,
        "dae-aya-attach-bpf_bpfel.o",
        "dae-aya-attach-smoke",
        "daya",
    )
    .unwrap();
}

#[cfg(feature = "aya-loader")]
#[test]
fn aya_tcx_attach_detach_smoke_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_TCX_ATTACH_SMOKE").is_none() {
        return;
    }
    if !kernel_supports_tcx_optional_smoke() {
        eprintln!("skip aya tcx attach smoke: kernel is older than 6.6");
        return;
    }

    match run_aya_host_veth_attach_detach_smoke(
        AttachBackend::Tcx,
        "dae-aya-tcx-attach-bpf_bpfel.o",
        "dae-aya-tcx-attach-smoke",
        "dayx",
    ) {
        Ok(()) => {}
        Err(err) if tcx_optional_attach_unsupported(&err) => {
            eprintln!("skip aya tcx attach smoke: {err}");
        }
        Err(err) => panic!("aya tcx attach/detach smoke failed: {err}"),
    }
}

#[cfg(feature = "aya-loader")]
#[test]
fn aya_tc_netns_attach_detach_smoke_is_env_gated() {
    if std::env::var_os("DAE_RUN_AYA_TC_NETNS_ATTACH_SMOKE").is_none() {
        return;
    }

    let root = dae_golden::repo_root_from_manifest().unwrap();
    let aya_object = temp_path("dae-aya-netns-attach-bpf_bpfel.o");
    build_aya_compatible_bpf_object(&root, &aya_object);
    let suffix = std::process::id() % 10000;
    let netns = format!("dayans{suffix}");
    let host_iface = format!("dayn{suffix}a");
    let peer_iface = format!("dayn{suffix}b");
    cleanup_host_iface(&host_iface);
    cleanup_host_iface(&peer_iface);
    cleanup_netns(&netns);
    run_host_command("ip", ["netns", "add", netns.as_str()]);
    run_host_command(
        "ip",
        [
            "link",
            "add",
            host_iface.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            peer_iface.as_str(),
        ],
    );
    run_host_command(
        "ip",
        ["link", "set", peer_iface.as_str(), "netns", netns.as_str()],
    );
    run_host_command("ip", ["link", "set", host_iface.as_str(), "up"]);
    run_host_command(
        "ip",
        [
            "netns",
            "exec",
            netns.as_str(),
            "ip",
            "link",
            "set",
            peer_iface.as_str(),
            "up",
        ],
    );

    let pin_root = default_bpffs_mount()
        .unwrap()
        .join(format!("dae-aya-netns-attach-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&pin_root).unwrap();
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: std::process::id(),
        dae0_ifindex: iface_index(&host_iface),
        dae_netns_id: 49,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    let mut loaded = load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object: &aya_object,
        param: Some(param),
        map_pin_path: Some(&pin_root),
        allow_unsupported_maps: true,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
    })
    .unwrap();

    let peer_attach = TcBpfAttachSpec::new(
        TcAttachTarget::netns(
            netns.as_str(),
            peer_iface.as_str(),
            TcAttachDirection::Ingress,
        ),
        "51",
        aya_object.display().to_string(),
        "classifier/dae0peer_ingress",
    )
    .native_attach_spec("tproxy_dae0peer_ingress", 1, tc_handle(0x2022, 0b011));
    let peer_report = load_attach_detach_aya_sched_classifier(
        &mut loaded,
        &peer_attach,
        AttachBackend::TcNetlink,
    )
    .unwrap();

    assert_eq!(peer_report.backend, AttachBackend::TcNetlink);
    assert_eq!(peer_report.program_name, "tproxy_dae0peer_ingress");
    assert_eq!(peer_report.iface, peer_iface);
    assert_eq!(peer_report.netns, Some(netns.clone()));
    assert!(peer_report.netns_entered);
    assert!(peer_report.loaded);
    assert!(peer_report.attached);
    assert!(peer_report.detached);

    let _ = std::fs::remove_dir_all(&pin_root);
    let _ = std::fs::remove_file(&aya_object);
    cleanup_host_iface(&host_iface);
    cleanup_netns(&netns);
}

#[cfg(feature = "aya-loader")]
fn run_aya_host_veth_attach_detach_smoke(
    backend: AttachBackend,
    object_name: &str,
    pin_stem: &str,
    iface_prefix: &str,
) -> Result<(), String> {
    let root = dae_golden::repo_root_from_manifest().unwrap();
    let aya_object = temp_path(object_name);
    build_aya_compatible_bpf_object(&root, &aya_object);
    let suffix = std::process::id() % 10000;
    let host_iface = format!("{iface_prefix}{suffix}a");
    let peer_iface = format!("{iface_prefix}{suffix}b");
    cleanup_host_iface(&host_iface);
    cleanup_host_iface(&peer_iface);
    run_host_command(
        "ip",
        [
            "link",
            "add",
            host_iface.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            peer_iface.as_str(),
        ],
    );
    run_host_command("ip", ["link", "set", host_iface.as_str(), "up"]);
    run_host_command("ip", ["link", "set", peer_iface.as_str(), "up"]);

    let pin_root = default_bpffs_mount()
        .unwrap()
        .join(format!("{pin_stem}-{}", std::process::id()));
    std::fs::create_dir_all(&pin_root).unwrap();
    let result = (|| -> Result<_, String> {
        let param = build_dae_param(DaeParamInput {
            tproxy_port: 12345,
            control_plane_pid: std::process::id(),
            dae0_ifindex: iface_index(&host_iface),
            dae_netns_id: 49,
            dae0peer_mac: [1, 2, 3, 4, 5, 6],
            has_bpf_get_current_task: true,
        });
        let mut loaded = load_aya_userspace_object(AyaUserspaceLoaderOptions {
            object: &aya_object,
            param: Some(param),
            map_pin_path: Some(&pin_root),
            allow_unsupported_maps: true,
            max_entries_overrides: &[],
            prepin_lpm_array_map: true,
        })?;

        let host_attach = TcBpfAttachSpec::new(
            TcAttachTarget::host(host_iface.as_str(), TcAttachDirection::Ingress),
            "50",
            aya_object.display().to_string(),
            "classifier/dae0_ingress",
        )
        .native_attach_spec("tproxy_dae0_ingress", 1, tc_handle(0x2022, 0b010));
        let peer_attach = TcBpfAttachSpec::new(
            TcAttachTarget::host(peer_iface.as_str(), TcAttachDirection::Ingress),
            "51",
            aya_object.display().to_string(),
            "classifier/dae0peer_ingress",
        )
        .native_attach_spec("tproxy_dae0peer_ingress", 1, tc_handle(0x2022, 0b011));

        let host_report =
            load_attach_detach_aya_sched_classifier(&mut loaded, &host_attach, backend)?;
        let peer_report =
            load_attach_detach_aya_sched_classifier(&mut loaded, &peer_attach, backend)?;
        Ok((host_report, peer_report))
    })();

    let _ = std::fs::remove_dir_all(&pin_root);
    let _ = std::fs::remove_file(&aya_object);
    cleanup_host_iface(&host_iface);

    let (host_report, peer_report) = result?;
    assert_eq!(host_report.backend, backend);
    assert_eq!(host_report.program_name, "tproxy_dae0_ingress");
    assert_eq!(host_report.iface, host_iface);
    assert_eq!(host_report.netns, None);
    assert!(!host_report.netns_entered);
    assert!(host_report.loaded);
    assert!(host_report.attached);
    assert!(host_report.detached);
    assert_eq!(peer_report.backend, backend);
    assert_eq!(peer_report.program_name, "tproxy_dae0peer_ingress");
    assert_eq!(peer_report.iface, peer_iface);
    assert_eq!(peer_report.netns, None);
    assert!(!peer_report.netns_entered);
    assert!(peer_report.loaded);
    assert!(peer_report.attached);
    assert!(peer_report.detached);
    Ok(())
}

#[cfg(feature = "aya-loader")]
fn kernel_supports_tcx_optional_smoke() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let mut parts = release
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u32>().ok());
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => major > 6 || (major == 6 && minor >= 6),
        _ => false,
    }
}

#[cfg(feature = "aya-loader")]
fn tcx_optional_attach_unsupported(err: &str) -> bool {
    let err = err.to_ascii_lowercase();
    err.contains("operation not supported")
        || err.contains("not supported")
        || err.contains("not implemented")
}

#[cfg(feature = "aya-loader")]
fn build_aya_compatible_bpf_object(root: &std::path::Path, output: &std::path::Path) {
    let clang = std::env::var("DAE_BPF_CLANG").unwrap_or_else(|_| "clang".to_owned());
    let include_dir = root.join("control/kern/headers");
    let source = root.join("control/kern/tproxy.c");
    let output = std::process::Command::new(&clang)
        .args([
            "-g",
            "-O2",
            "-Wall",
            "-Werror",
            "-DMAX_MATCH_SET_LEN=1024",
            "-DDAE_AYA_EBPF_OBJECT",
            "-target",
            "bpfel",
            "-c",
        ])
        .arg(&source)
        .arg("-I")
        .arg(&include_dir)
        .arg("-o")
        .arg(output)
        .output()
        .unwrap_or_else(|err| panic!("failed to execute {clang}: {err}"));
    if !output.status.success() {
        panic!(
            "failed to build Aya-compatible eBPF object: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(feature = "aya-loader")]
fn run_host_command<const N: usize>(program: &str, args: [&str; N]) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to execute {program}: {err}"));
    if !output.status.success() {
        panic!(
            "host command failed: {} status={} stdout={} stderr={}",
            program,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(feature = "aya-loader")]
fn cleanup_host_iface(iface: &str) {
    let _ = std::process::Command::new("ip")
        .args(["link", "del", iface])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(feature = "aya-loader")]
fn cleanup_netns(netns: &str) {
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", netns])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(feature = "aya-loader")]
fn iface_index(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn tc_attach_backend_report_keeps_native_attach_non_default() {
    let peer = TcBpfAttachSpec::new(
        TcAttachTarget::netns("daens", "dae0peer", TcAttachDirection::Ingress),
        "49491",
        "/tmp/bpf_bpfel.param.o",
        "tc/dae0peer_ingress",
    );
    let native = peer.native_attach_spec("dae_dae0peer_ingress", 0, tc_handle(0x2022, 0b010));
    let report = peer.attach_backend_report(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability {
            tcx: true,
            tc_netlink: true,
            tc_command_fallback: true,
        },
        false,
        native,
    );

    assert_eq!(report.plan.selected, Some(AttachBackend::Tcx));
    assert_eq!(
        report.effective_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert!(report.native_backend_capable);
    assert!(!report.default_native_backend_enabled);
    assert!(report.command_fallback_required);
    assert!(report.tcx_attempted);
    assert!(report.tc_netlink_attempted);
    assert!(report.command_fallback_attempted);
    assert_eq!(report.native_spec.priority, 0);
    assert_eq!(report.native_spec.handle, 0x2022_0002);
    assert_eq!(report.native_spec.tcx_order, TcxAttachOrder::First);
    assert_eq!(report.native_spec.protocol, ETH_P_ALL);
    assert!(report.native_spec.direct_action);
    assert!(report.native_spec.clsact_required);
    assert!(report.native_spec.netns_enter_required);
    assert_eq!(report.command_fallback_spec, peer.filter_add_command());
    assert_eq!(report.cleanup_fallback_spec, peer.filter_del_command());
    assert_eq!(report.show_fallback_spec, peer.filter_show_command(true));
}

#[test]
fn dae_tc_attach_matrix_matches_go_control_plane_core_values() {
    let matrix = dae_tc_attach_matrix(DaeTcAttachMatrixInput {
        object: "/tmp/bpf_bpfel.param.o".to_owned(),
        lan_iface: "lan0".to_owned(),
        wan_iface: "wan0".to_owned(),
        host_iface: "dae0".to_owned(),
        peer_iface: "dae0peer".to_owned(),
        peer_netns: "daens".to_owned(),
        section_prefix: TcAttachSectionPrefix::Tc,
        link_layer: TcAttachLayer::L2,
        flip: 0,
        is_reload: false,
    });
    assert_eq!(matrix.len(), 6);

    let lan_ingress = attach_line(&matrix, DaeTcAttachRole::LanIngress);
    assert_eq!(lan_ingress.go_filter_name, "dae_lan_ingress_l2");
    assert_eq!(lan_ingress.native.program_name, "tproxy_lan_ingress_l2");
    assert_eq!(lan_ingress.native.section, "tc/lan_ingress_l2");
    assert_eq!(lan_ingress.native.target.iface, "lan0");
    assert_eq!(
        lan_ingress.native.target.direction,
        TcAttachDirection::Ingress
    );
    assert_eq!(lan_ingress.native.priority, 2);
    assert_eq!(lan_ingress.native.handle, tc_handle(0x2023, 0b100));
    assert_eq!(lan_ingress.native.tcx_order, TcxAttachOrder::Last);
    assert_eq!(
        lan_ingress.stale_cleanup_handle_on_fresh_start,
        Some(tc_handle(0x2023, 0b101))
    );

    let lan_egress = attach_line(&matrix, DaeTcAttachRole::LanEgress);
    assert_eq!(lan_egress.go_filter_name, "dae_lan_egress_l2");
    assert_eq!(lan_egress.native.program_name, "tproxy_lan_egress_l2");
    assert_eq!(lan_egress.native.section, "tc/lan_egress_l2");
    assert_eq!(
        lan_egress.native.target.direction,
        TcAttachDirection::Egress
    );
    assert_eq!(lan_egress.native.priority, 1);
    assert_eq!(lan_egress.native.handle, tc_handle(0x2023, 0b010));
    assert_eq!(lan_egress.native.tcx_order, TcxAttachOrder::First);

    let wan_ingress = attach_line(&matrix, DaeTcAttachRole::WanIngress);
    assert_eq!(wan_ingress.go_filter_name, "dae_wan_ingress_l2");
    assert_eq!(wan_ingress.native.program_name, "tproxy_wan_ingress_l2");
    assert_eq!(wan_ingress.native.section, "tc/wan_ingress_l2");
    assert_eq!(wan_ingress.native.target.iface, "wan0");
    assert_eq!(
        wan_ingress.native.target.direction,
        TcAttachDirection::Ingress
    );
    assert_eq!(wan_ingress.native.priority, 1);
    assert_eq!(wan_ingress.native.handle, tc_handle(0x2023, 0b010));
    assert_eq!(wan_ingress.native.tcx_order, TcxAttachOrder::First);

    let wan_egress = attach_line(&matrix, DaeTcAttachRole::WanEgress);
    assert_eq!(wan_egress.go_filter_name, "dae_wan_egress_l2");
    assert_eq!(wan_egress.native.program_name, "tproxy_wan_egress_l2");
    assert_eq!(wan_egress.native.section, "tc/wan_egress_l2");
    assert_eq!(
        wan_egress.native.target.direction,
        TcAttachDirection::Egress
    );
    assert_eq!(wan_egress.native.priority, 2);
    assert_eq!(wan_egress.native.handle, tc_handle(0x2023, 0b100));
    assert_eq!(wan_egress.native.tcx_order, TcxAttachOrder::Last);

    let peer = attach_line(&matrix, DaeTcAttachRole::Dae0peerIngress);
    assert_eq!(peer.go_filter_name, "dae_dae0peer_ingress");
    assert_eq!(peer.native.program_name, "tproxy_dae0peer_ingress");
    assert_eq!(peer.native.section, "tc/dae0peer_ingress");
    assert_eq!(peer.native.target.iface, "dae0peer");
    assert_eq!(peer.native.target.netns.as_deref(), Some("daens"));
    assert_eq!(peer.native.priority, 0);
    assert_eq!(peer.native.handle, tc_handle(0x2022, 0b010));
    assert_eq!(peer.native.tcx_order, TcxAttachOrder::First);
    assert_eq!(peer.stale_cleanup_handle_on_fresh_start, None);

    let host = attach_line(&matrix, DaeTcAttachRole::Dae0Ingress);
    assert_eq!(host.go_filter_name, "dae_dae0_ingress");
    assert_eq!(host.native.program_name, "tproxy_dae0_ingress");
    assert_eq!(host.native.section, "tc/dae0_ingress");
    assert_eq!(host.native.target.iface, "dae0");
    assert_eq!(host.native.target.netns, None);
    assert_eq!(host.native.priority, 0);
    assert_eq!(host.native.handle, tc_handle(0x2022, 0b010));
    assert_eq!(host.native.tcx_order, TcxAttachOrder::First);
    assert_eq!(
        host.stale_cleanup_handle_on_fresh_start,
        Some(tc_handle(0x2022, 0b011))
    );
}

#[test]
fn dae_tc_attach_matrix_supports_l3_and_aya_classifier_sections() {
    let matrix = dae_tc_attach_matrix(DaeTcAttachMatrixInput {
        object: "/tmp/dae-aya-bpf_bpfel.o".to_owned(),
        lan_iface: "lan0".to_owned(),
        wan_iface: "wan0".to_owned(),
        host_iface: "dae0".to_owned(),
        peer_iface: "dae0peer".to_owned(),
        peer_netns: "daens".to_owned(),
        section_prefix: TcAttachSectionPrefix::Classifier,
        link_layer: TcAttachLayer::L3,
        flip: 1,
        is_reload: true,
    });

    let lan_ingress = attach_line(&matrix, DaeTcAttachRole::LanIngress);
    assert_eq!(lan_ingress.native.section, "classifier/lan_ingress_l3");
    assert_eq!(lan_ingress.native.program_name, "tproxy_lan_ingress_l3");
    assert_eq!(lan_ingress.native.handle, tc_handle(0x2023, 0b101));
    assert_eq!(lan_ingress.stale_cleanup_handle_on_fresh_start, None);

    let wan_ingress = attach_line(&matrix, DaeTcAttachRole::WanIngress);
    assert_eq!(wan_ingress.native.section, "classifier/wan_ingress_l3");
    assert_eq!(wan_ingress.native.program_name, "tproxy_wan_ingress_l3");
    assert_eq!(wan_ingress.native.handle, tc_handle(0x2023, 0b011));

    let peer = attach_line(&matrix, DaeTcAttachRole::Dae0peerIngress);
    assert_eq!(peer.native.section, "classifier/dae0peer_ingress");
    assert_eq!(peer.native.program_name, "tproxy_dae0peer_ingress");
    assert_eq!(peer.native.handle, tc_handle(0x2022, 0b011));
    assert!(
        matrix
            .iter()
            .all(|line| line.stale_cleanup_handle_on_fresh_start.is_none())
    );
}

fn attach_line(matrix: &[DaeTcAttachLine], role: DaeTcAttachRole) -> &DaeTcAttachLine {
    matrix
        .iter()
        .find(|line| line.role == role)
        .unwrap_or_else(|| panic!("missing attach line: {role:?}"))
}

#[test]
fn tc_attach_contract_generates_existing_command_fallback_shape() {
    let peer = TcBpfAttachSpec::new(
        TcAttachTarget::netns("daens", "dae0peer", TcAttachDirection::Ingress),
        "49491",
        "/tmp/bpf_bpfel.param.o",
        "tc/dae0peer_ingress",
    );
    let add = peer.filter_add_command();
    assert_eq!(add.program, "ip");
    assert_eq!(
        add.args,
        vec![
            "netns",
            "exec",
            "daens",
            "tc",
            "filter",
            "add",
            "dev",
            "dae0peer",
            "ingress",
            "pref",
            "49491",
            "bpf",
            "da",
            "obj",
            "/tmp/bpf_bpfel.param.o",
            "sec",
            "tc/dae0peer_ingress",
        ]
    );
    assert_eq!(
        peer.filter_show_command(true).args,
        vec![
            "netns", "exec", "daens", "tc", "-s", "filter", "show", "dev", "dae0peer", "ingress",
        ]
    );
    assert_eq!(
        peer.filter_del_command().args,
        vec![
            "netns", "exec", "daens", "tc", "filter", "del", "dev", "dae0peer", "ingress", "pref",
            "49491",
        ]
    );

    let host = TcAttachTarget::host("dae0", TcAttachDirection::Ingress);
    assert_eq!(host.clsact_qdisc_add_command().program, "tc");
    assert_eq!(
        host.clsact_qdisc_add_command().args,
        vec!["qdisc", "add", "dev", "dae0", "clsact"]
    );
}

#[test]
fn kernel_feature_gates_match_golden_fixture() {
    let fixture = load("ebpf/kernel_features/basic.json");
    for feature in fixture["features"].as_array().unwrap() {
        let version = match feature["name"].as_str().unwrap() {
            "basic" => BASIC_FEATURE_VERSION,
            "checksum" => CHECKSUM_FEATURE_VERSION,
            "sk_assign" => SK_ASSIGN_FEATURE_VERSION,
            "bpf_timer" => BPF_TIMER_FEATURE_VERSION,
            "bpf_loop" => BPF_LOOP_FEATURE_VERSION,
            other => panic!("unexpected feature {other}"),
        };
        assert_eq!(version.go_string(), feature["version"].as_str().unwrap());
        assert_eq!(
            version.kernel_code(),
            feature["kernel_code"].as_u64().unwrap() as u32
        );
    }

    for scenario in fixture["scenarios"].as_array().unwrap() {
        let version = parse_go_version(scenario["version"].as_str().unwrap());
        let report = FeatureGateReport::new(
            version,
            scenario["lan_configured"].as_bool().unwrap(),
            scenario["wan_configured"].as_bool().unwrap(),
        );
        let expected_missing = scenario["missing"]
            .as_array()
            .map(|items| items.iter().map(|value| value.as_str().unwrap()).collect())
            .unwrap_or_else(Vec::new);
        assert_eq!(report.missing, expected_missing);
        assert_eq!(report.allowed(), scenario["allowed"].as_bool().unwrap());
    }
}

#[test]
fn connectivity_dryrun_matches_golden_fixture() {
    let fixture = load("control/outbound_connectivity/dryrun.json");
    let mut map = ConnectivityMap::default();
    for event in fixture["events"].as_array().unwrap() {
        let key = ConnectivityKey {
            outbound: event["key"]["outbound"].as_u64().unwrap() as u8,
            l4proto: event["key"]["l4proto"].as_u64().unwrap() as u8,
            ipversion: event["key"]["ipversion"].as_u64().unwrap() as u8,
        };
        let written = map.record(ConnectivityEvent {
            key,
            alive: event["value"].as_u64().unwrap() == 1,
            is_init: event["name"].as_str().unwrap().contains("_init_"),
            dryrun: event["name"].as_str().unwrap().starts_with("dryrun_"),
        });
        let plan = connectivity_write_plan(ConnectivityEvent {
            key,
            alive: event["value"].as_u64().unwrap() == 1,
            is_init: event["name"].as_str().unwrap().contains("_init_"),
            dryrun: event["name"].as_str().unwrap().starts_with("dryrun_"),
        });
        assert_eq!(written, event["written"].as_bool().unwrap());
        assert_eq!(plan.written, written);
        assert_eq!(plan.key, key);
        assert_eq!(plan.value, event["value"].as_u64().unwrap() as u32);
        assert_eq!(map.len(), event["state_len"].as_u64().unwrap() as usize);
        if written {
            assert_eq!(map.get(key), Some(event["value"].as_u64().unwrap() as u32));
        }
    }
}

#[test]
fn connectivity_fd_cache_skips_dryrun_without_opening_map() {
    let mut cache = ConnectivityMapFdCache::default();
    let plan = cache
        .update_by_id(
            0,
            ConnectivityEvent {
                key: ConnectivityKey {
                    outbound: 2,
                    l4proto: 6,
                    ipversion: 4,
                },
                alive: true,
                is_init: false,
                dryrun: true,
            },
        )
        .unwrap();
    assert!(!plan.written);
    assert!(cache.is_empty());
}

#[test]
fn routing_map_apply_models_report_counts() {
    let routing = [RoutingMapEntry {
        index: 0,
        value: BpfMatchSet {
            kind: 1,
            outbound: 2,
            ..BpfMatchSet::default()
        },
    }];
    let lpm = [LpmArrayMapEntry {
        index: 3,
        map_id: 9,
    }];
    let lpm_build = LpmMapBuildSpec {
        index: 4,
        flags: 1,
        max_entries: 2048,
        key_size: std::mem::size_of::<BpfLpmKey>() as u32,
        value_size: std::mem::size_of::<u32>() as u32,
        entries: vec![LpmMapEntry {
            key: BpfLpmKey {
                prefix_len: 128,
                data: [0, 0, 0xffff, 1],
            },
            value: 1,
        }],
    };
    assert_eq!(routing.len(), 1);
    assert_eq!(lpm.len(), 1);
    assert_eq!(lpm_build.entries[0].key.prefix_len, 128);
    assert_eq!(lpm_build.entries[0].value, 1);
}

#[test]
fn domain_routing_map_apply_models_bitmap_shape() {
    let entry = DomainRoutingMapEntry {
        key: [0, 0, 0, 1],
        value: BpfDomainRouting { bitmap: [0x40; 32] },
    };
    assert_eq!(entry.key, [0, 0, 0, 1]);
    assert_eq!(entry.value.bitmap.len(), 32);
}

#[test]
fn dae_param_packs_big_endian_tproxy_port() {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    assert_eq!(param.tproxy_port, u32::from(12345u16.to_be()));
    assert_eq!(param.control_plane_pid, 77);
    assert_eq!(param.dae0peer_mac, [1, 2, 3, 4, 5, 6]);
    assert_eq!(param.has_bpf_get_current_task, 1);
}

#[test]
fn param_aware_loader_gate_requires_real_loader_and_runtime_values() {
    let input = DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    };
    let payload = build_dae_param_payload(input);
    assert_eq!(payload.symbol, DAE_PARAM_SYMBOL);
    assert_eq!(payload.rust_layout_size, size_of::<BpfDaeParam>());
    assert_eq!(payload.tproxy_port_big_endian, u32::from(12345u16.to_be()));
    assert!(dae_param_runtime_values_present(&payload));
    assert!(!direct_tc_object_loader_rewrites_param());
    assert!(!param_aware_load_admitted(
        false,
        true,
        Some(DAE_PARAM_SYMBOL_SIZE),
        &payload
    ));
    assert!(param_aware_load_admitted(
        true,
        true,
        Some(DAE_PARAM_SYMBOL_SIZE),
        &payload
    ));

    let zero_netns = build_dae_param_payload(DaeParamInput {
        dae_netns_id: 0,
        ..input
    });
    assert!(!dae_param_runtime_values_present(&zero_netns));
}

#[test]
fn dae_param_requirements_match_memo_fields() {
    let fields = dae_param_requirements()
        .iter()
        .map(|requirement| requirement.field)
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            "tproxy_port",
            "control_plane_pid",
            "dae0_ifindex",
            "dae_netns_id",
            "dae0peer_mac",
            "has_bpf_get_current_task",
        ]
    );
}

#[test]
fn param_object_rewriter_updates_real_dae_object_param_symbol() {
    let root = dae_golden::repo_root_from_manifest().unwrap();
    let source = root.join("control/bpf_bpfel.o");
    let output = temp_path("dae-stage41-param-object-test.o");
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });

    let location = locate_param_symbol_in_object(&source).unwrap();
    assert_eq!(location.symbol, DAE_PARAM_SYMBOL);
    assert_eq!(location.section, ".rodata");
    assert_eq!(location.symbol_size, DAE_PARAM_SYMBOL_SIZE as u64);
    assert_eq!(
        read_param_from_object(&source).unwrap(),
        BpfDaeParam::default()
    );

    let report = write_param_aware_object(&source, &output, param).unwrap();
    assert_eq!(report.location, location);
    assert_eq!(report.source_len, report.output_len);
    assert!(report.previous_param_was_zero);
    assert!(report.rewritten_param_matches);
    assert_eq!(read_param_from_object(&output).unwrap(), param);
    let _ = std::fs::remove_file(output);
}

#[test]
fn param_object_bytes_roundtrip_layout() {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    let bytes = param_to_object_bytes(param);
    assert_eq!(&bytes[0..4], &u32::from(12345u16.to_be()).to_le_bytes());
    assert_eq!(&bytes[16..22], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(bytes[22], 1);
    assert_eq!(param_from_object_bytes(&bytes).unwrap(), param);
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}-{name}", std::process::id()))
}

fn assert_layout<T>(fixture: &Value, name: &str, expected_size: usize, expected_align: usize) {
    let item = fixture_struct(fixture, name);
    assert_eq!(size_of::<T>(), expected_size);
    assert_eq!(align_of::<T>(), expected_align);
    assert_eq!(item["size"].as_u64().unwrap() as usize, size_of::<T>());
    assert_eq!(item["align"].as_u64().unwrap() as usize, align_of::<T>());
}

fn assert_offset<T>(fixture: &Value, struct_name: &str, field_name: &str, offset: usize) {
    let item = fixture_struct(fixture, struct_name);
    let offsets = item["offsets"].as_array().unwrap();
    let expected = offsets
        .iter()
        .find(|entry| entry["field"].as_str().unwrap() == field_name)
        .unwrap();
    assert_eq!(expected["offset"].as_u64().unwrap() as usize, offset);
}

fn fixture_struct<'a>(fixture: &'a Value, name: &str) -> &'a Value {
    fixture["structs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"].as_str().unwrap() == name)
        .unwrap()
}

fn parse_go_version(input: &str) -> Version {
    let trimmed = input.trim_start_matches('v');
    let parts = trimmed
        .split('.')
        .map(|part| part.parse::<u16>().unwrap())
        .collect::<Vec<_>>();
    Version::new(parts[0], parts[1], parts.get(2).copied().unwrap_or(0))
}
