//! Runs the real startup call site in private mount/network namespaces.
use super::*;
use std::process::Command;

fn command(args: &[&str]) {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn real_resident_start_prepares_before_attach_and_reuses_the_kernel_map_cache() {
    const CHILD: &str = "DAE_RESIDENT_STARTUP_TEST_CHILD";
    if env::var("DAE_RUN_RESIDENT_STARTUP_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip real resident startup kernel test: opt-in required");
        return;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    if env::var_os(CHILD).is_none() {
        let cgroup = dae_ebpf_support::detect_cgroup2_mount()
            .unwrap()
            .join(format!("dae-startup-test-{}", std::process::id()));
        fs::create_dir(&cgroup).unwrap();
        let test_name = concat!(
            module_path!(),
            "::real_resident_start_prepares_before_attach_and_reuses_the_kernel_map_cache"
        )
        .split_once("::")
        .unwrap()
        .1
        .to_owned();
        let output = Command::new("unshare")
            .args(["--mount", "--net", "--fork"])
            .arg(env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture", "--test-threads=1"])
            .env(CHILD, &cgroup)
            .env("RESIDENT_DATAPLANE", "1")
            .output();
        let removed = fs::remove_dir(&cgroup);
        let output = output.unwrap();
        assert!(
            output.status.success(),
            "real startup child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "child did not execute the test"
        );
        removed.unwrap();
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    command(&["mount", "--make-rprivate", "/"]);
    command(&["mount", "-t", "tmpfs", "tmpfs", "/run"]);
    fs::create_dir_all("/run/netns").unwrap();
    // sysfs must reflect this network namespace, rather than its parent's
    // interface list. Retain the private cgroup across the sysfs remount.
    let cgroup = fs::File::open(env::var(CHILD).unwrap()).unwrap();
    use std::os::fd::AsRawFd;
    let cgroup_fd = format!("/proc/{}/fd/{}", std::process::id(), cgroup.as_raw_fd());
    command(&["mount", "-t", "sysfs", "sysfs", "/sys"]);
    command(&["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"]);
    command(&["mount", "--bind", &cgroup_fd, "/sys/fs/cgroup"]);
    command(&["ip", "link", "set", "lo", "up"]);
    for iface in ["route-lan0", "route-lan1", "route-wan0"] {
        command(&["ip", "link", "add", iface, "type", "dummy"]);
        command(&["ip", "link", "set", iface, "up"]);
    }
    let config = dae_config::schema::build_config(&dae_config::parser::parse_config(
        "global { lan_interface: 'route-lan0,route-lan1'\nwan_interface: 'route-wan0' }\ndns {}\nnode { local: 'socks5://127.0.0.1:1080#local' }\ngroup { proxy { filter: name(local) policy: fixed(0) } }\nrouting { dip(198.51.100.0/24) -> block\nl4proto(tcp) -> proxy\nfallback: direct }"
    ).unwrap()).unwrap();
    for backend in [AttachBackend::Tcx, AttachBackend::TcNetlink] {
        let prepared =
            prepare_resident_production_generation(Arc::new(config.clone()), Vec::<PathBuf>::new())
                .unwrap();
        let artifact_dir = PathBuf::from(format!("/run/startup-{backend:?}"));
        fs::create_dir(&artifact_dir).unwrap();
        let start_file = artifact_dir.join("start.json");
        let options = ProductionRuntimeOwnerOptions {
            execute: true,
            ack_root_gate: true,
            native_ebpf_requested: true,
            native_ebpf_embedded_object: true,
            native_ebpf_local_admission: true,
            native_ebpf_backend: backend,
            source_object: PathBuf::from(EMBEDDED_NATIVE_OBJECT_IDENTITY),
            netns_link_mode: super::super::super::netns_link::NetnsLinkMode::Veth,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let mut runtime = start_with_options(ResidentRuntimeStartContext {
            options,
            artifacts: ResidentRuntimeArtifactPaths {
                artifact_dir: artifact_dir.clone(),
                start_file: start_file.clone(),
                cleanup_file: artifact_dir.join("cleanup.json"),
            },
            config: prepared.config,
            geodata: prepared.geodata,
            dataplane: prepared.dataplane,
            interfaces: ResidentRuntimeStartInterfaces {
                lan: vec!["route-lan0".into(), "route-lan1".into()],
                wan: vec!["route-wan0".into()],
            },
            latency_seed: &[],
            dns_reload_snapshot: None,
        })
        .unwrap();
        if let Some(writer) = runtime.start_evidence_writer.take() {
            writer.join().unwrap().unwrap();
        }
        let report: Value = serde_json::from_slice(&fs::read(&start_file).unwrap()).unwrap();
        assert_eq!(report["status"], "pass");
        let steps = report["executed_steps"].as_array().unwrap();
        let preparations: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, x)| x["name"] == "prepare-native-routing-before-physical-attach")
            .collect();
        assert_eq!(preparations.len(), 1);
        let (prepare_index, preparation) = preparations[0];
        assert_eq!(
            preparation["physical_generation"],
            report["runtime_generation"]
        );
        let mut physical_roles = 0;
        for (index, step) in steps.iter().enumerate() {
            let attach = &step["native_attach"];
            if attach["attached"] == true && attach["iface"] != "dae0peer" {
                assert!(
                    index > prepare_index,
                    "physical attach preceded preparation: {step}"
                );
                physical_roles += 1;
            }
            if step["name"] == "attach-native-ebpf-cgroup-programs" && step["status"] == "pass" {
                assert!(index > prepare_index, "cgroup attach preceded preparation");
            }
        }
        assert_eq!(
            steps
                .iter()
                .filter(
                    |s| s["name"] == "attach-native-ebpf-cgroup-programs" && s["status"] == "pass"
                )
                .count(),
            1
        );
        assert!(
            physical_roles >= 6,
            "WAN and both LAN interfaces must actually attach"
        );
        assert_eq!(report["resident_native_cgroup_attached"], true);
        let rows = report["resident_lan_routing"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(
                row["routing_map_update"]["routing_map_update_skipped"],
                true
            );
            assert_eq!(
                row["routing_map_update"]["map"]["id"],
                preparation["routing_map_id"]
            );
        }
        // Exercise the real cache and writer. Freeze the routing map after the
        // first write: a repeated write would now fail with EPERM in-kernel.
        let id = runtime.native_runtime.loaded_map_id("routing_map").unwrap();
        let lpm = runtime.native_runtime.loaded_map_id("lpm_array_map");
        let connectivity = runtime
            .native_runtime
            .loaded_map_id("outbound_connectivity_map");
        let mut cache = ResidentRoutingApplyCache::default();
        let geodata = ResidentGeodataStore::new(Vec::<PathBuf>::new());
        let (first, _) = update_existing_resident_routing_map(
            id,
            lpm,
            connectivity,
            &config,
            &geodata,
            &mut cache,
        )
        .unwrap();
        assert_eq!(first["routing_map_update_skipped"], false);
        let map = dae_ebpf_support::ValidatedRuntimeMapHandle::open_by_id(id).unwrap();
        let attr = [map.as_raw_fd() as u32];
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    22,
                    attr.as_ptr(),
                    std::mem::size_of_val(&attr),
                )
            },
            0
        );
        for _ in 0..2 {
            let (cached, _) = update_existing_resident_routing_map(
                id,
                lpm,
                connectivity,
                &config,
                &geodata,
                &mut cache,
            )
            .unwrap();
            assert_eq!(cached["routing_map_update_skipped"], true);
        }
        assert!(
            update_existing_resident_routing_map(
                id,
                lpm,
                connectivity,
                &config,
                &geodata,
                &mut ResidentRoutingApplyCache::default()
            )
            .is_err(),
            "a fresh cache must attempt the frozen map write"
        );
        drop(map);
        let cleanup = runtime.cleanup().unwrap();
        assert_eq!(cleanup["status"], "pass", "{cleanup}");
        eprintln!(
            "real resident startup {backend:?}: ordered attach and frozen-map cache reuse verified"
        );
    }
}
