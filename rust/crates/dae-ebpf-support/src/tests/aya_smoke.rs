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
