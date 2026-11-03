//! Negative admission at the real startup call site, after worker publication.
use super::startup_routing_kernel_tests::{command, enter_private_namespace};
use super::*;
use std::{
    cell::RefCell,
    collections::BTreeSet,
    net::{TcpListener, UdpSocket},
    os::fd::{AsRawFd, OwnedFd},
    process::Command,
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
enum Fault {
    ReadDenied,
    Missing(u32),
    Replace(u32),
}

struct Probe {
    fault: Fault,
    injected: bool,
    executed: Vec<Value>,
    cleanup: Vec<Value>,
}

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
}

struct EffectiveCapabilities([u32; 6]);
impl EffectiveCapabilities {
    fn deny_bpf_open() -> Self {
        let mut header = [0x20080522_u32, 0];
        let mut saved = [0_u32; 6];
        // Linux v3 capability data contains two effective/permitted/inheritable
        // records. Only this thread's effective bits change; permitted stay put.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capget, header.as_mut_ptr(), saved.as_mut_ptr()) },
            0
        );
        let mut denied = saved;
        denied[0] &= !(1 << 21); // CAP_SYS_ADMIN
        denied[3] &= !(1 << (39 - 32)); // CAP_BPF
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), denied.as_ptr()) },
            0
        );
        Self(saved)
    }
}
impl Drop for EffectiveCapabilities {
    fn drop(&mut self) {
        let header = [0x20080522_u32, 0];
        let result = unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), self.0.as_ptr()) };
        if result != 0 {
            eprintln!(
                "cannot restore startup test capabilities: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

pub(super) struct SnapshotFault {
    _capabilities: Option<EffectiveCapabilities>,
    _socket: Option<OwnedFd>,
}

pub(super) fn before_snapshot(map_id: Option<u32>) -> Option<SnapshotFault> {
    PROBE.with_borrow_mut(|probe| {
        let probe = probe.as_mut()?;
        assert!(!probe.injected, "startup snapshot injection ran twice");
        let id = map_id.expect("real startup must have a listener map");
        let before = dae_ebpf_support::sockmap::listen_socket_cookie_snapshot(id).unwrap();
        assert!(before.iter().all(Option::is_some));
        assert_eq!(before[1], before[0], "resident TCP slots diverged");
        assert_eq!(before[3], before[2], "resident UDP slots diverged");
        assert_eq!(before[4], before[0], "fault preceded real publication");
        let cgroup = dae_ebpf_support::query_cgroup_attachments(
            Path::new("/sys/fs/cgroup"),
            &dae_ebpf_support::dae_cgroup_attach_matrix(),
        )
        .unwrap();
        assert!(
            cgroup
                .queries
                .iter()
                .all(|query| query.program_ids.len() == 1)
        );
        probe.injected = true;
        match probe.fault {
            Fault::ReadDenied => Some(SnapshotFault {
                _capabilities: Some(EffectiveCapabilities::deny_bpf_open()),
                _socket: None,
            }),
            Fault::Missing(key) => {
                let map = dae_ebpf_support::ValidatedRuntimeMapHandle::open_by_id(id).unwrap();
                dae_ebpf_support::runtime_maps::delete_map_elem_bytes(
                    map.as_raw_fd(),
                    &key.to_ne_bytes(),
                )
                .unwrap();
                let after = dae_ebpf_support::sockmap::listen_socket_cookie_snapshot(id).unwrap();
                for index in 0..5 {
                    assert_eq!(
                        after[index],
                        if index == key as usize {
                            None
                        } else {
                            before[index]
                        }
                    );
                }
                None
            }
            Fault::Replace(key) => {
                let other: OwnedFd = if matches!(key, 2 | 3) {
                    UdpSocket::bind(("127.0.0.1", 0)).unwrap().into()
                } else {
                    TcpListener::bind(("127.0.0.1", 0)).unwrap().into()
                };
                let map = dae_ebpf_support::ValidatedRuntimeMapHandle::open_by_id(id).unwrap();
                dae_ebpf_support::runtime_maps::update_map_elem_bytes(
                    map.as_raw_fd(),
                    &key.to_ne_bytes(),
                    &(other.as_raw_fd() as u64).to_ne_bytes(),
                )
                .unwrap();
                let after = dae_ebpf_support::sockmap::listen_socket_cookie_snapshot(id).unwrap();
                assert!(after.iter().all(Option::is_some));
                assert_ne!(after[key as usize], before[key as usize]);
                for index in 0..5 {
                    if index != key as usize {
                        assert_eq!(after[index], before[index]);
                    }
                }
                if matches!(key, 1..=3) {
                    assert_eq!(after[4], after[0], "ready changed with unrelated slot");
                }
                Some(SnapshotFault {
                    _capabilities: None,
                    _socket: Some(other),
                })
            }
        }
    })
}

pub(super) fn observe_rollback(executed: &[Value], cleanup: &[Value]) {
    PROBE.with_borrow_mut(|probe| {
        if let Some(probe) = probe {
            probe.executed = executed.to_vec();
            probe.cleanup = cleanup.to_vec();
        }
    });
}

fn context(backend: AttachBackend, path: &Path) -> ResidentRuntimeStartContext<'static> {
    let config = dae_config::schema::build_config(&dae_config::parser::parse_config(
        "global { lan_interface: 'route-lan0,route-lan1'\nwan_interface: 'route-wan0' }\ndns {}\nnode { local: 'socks5://127.0.0.1:1080#local' }\ngroup { proxy { filter: name(local) policy: fixed(0) } }\nrouting { l4proto(tcp) -> proxy\nfallback: direct }"
    ).unwrap()).unwrap();
    let prepared =
        prepare_resident_production_generation(Arc::new(config), Vec::<PathBuf>::new()).unwrap();
    fs::create_dir(path).unwrap();
    ResidentRuntimeStartContext {
        options: ProductionRuntimeOwnerOptions {
            execute: true,
            ack_root_gate: true,
            native_ebpf_requested: true,
            native_ebpf_embedded_object: true,
            native_ebpf_local_admission: true,
            native_ebpf_backend: backend,
            source_object: PathBuf::from(EMBEDDED_NATIVE_OBJECT_IDENTITY),
            netns_link_mode: super::super::super::netns_link::NetnsLinkMode::Veth,
            ..ProductionRuntimeOwnerOptions::default()
        },
        artifacts: ResidentRuntimeArtifactPaths {
            artifact_dir: path.to_owned(),
            start_file: path.join("start.json"),
            cleanup_file: path.join("cleanup.json"),
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
    }
}

fn json_command(args: &[&str]) -> Value {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn object_ids(kind: &str) -> BTreeSet<u64> {
    let command = match kind {
        "prog" => 11, // BPF_PROG_GET_NEXT_ID
        "map" => 12,  // BPF_MAP_GET_NEXT_ID
        "link" => 31, // BPF_LINK_GET_NEXT_ID
        _ => unreachable!(),
    };
    let mut ids = BTreeSet::new();
    let mut attr = [0_u32; 3]; // start_id, next_id, open_flags
    loop {
        // SAFETY: each command uses this initialized three-u32 UAPI prefix.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                command,
                attr.as_mut_ptr(),
                std::mem::size_of_val(&attr),
            )
        };
        if result < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOENT)
            );
            return ids;
        }
        assert!(attr[1] > attr[0], "BPF ID enumeration did not advance");
        ids.insert(u64::from(attr[1]));
        attr[0] = attr[1];
    }
}

fn foreign_filters() -> Value {
    json_command(&["tc", "-j", "filter", "show", "dev", "route-lan0", "ingress"])
}

fn pin_paths(root: &Path) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            paths.extend(pin_paths(&path));
        }
        paths.insert(path);
    }
    paths
}

fn assert_no_bindings_or_topology() {
    assert!(!Path::new("/sys/class/net/dae0").exists());
    assert!(!Path::new("/run/netns/daens").exists());
    let snapshots = dae_ebpf_support::query_cgroup_attachments(
        Path::new("/sys/fs/cgroup"),
        &dae_ebpf_support::dae_cgroup_attach_matrix(),
    )
    .unwrap();
    assert!(
        snapshots
            .queries
            .iter()
            .all(|query| query.program_ids.is_empty())
    );
    for iface in ["route-lan0", "route-lan1", "route-wan0"] {
        for direction in ["ingress", "egress"] {
            let filters = json_command(&["tc", "-j", "filter", "show", "dev", iface, direction]);
            assert!(
                filters
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["kind"] != "bpf")
            );
            let dir = if direction == "ingress" {
                dae_ebpf_support::TcAttachDirection::Ingress
            } else {
                dae_ebpf_support::TcAttachDirection::Egress
            };
            let observed = dae_ebpf_support::query_aya_tcx_binding(
                &dae_ebpf_support::TcAttachTarget::host(iface, dir),
            )
            .unwrap();
            assert!(
                observed.program_order.is_empty(),
                "owned TCX binding left on {iface}"
            );
        }
    }
}

#[test]
fn real_start_rejects_unreadable_or_corrupted_publication_and_rolls_back() {
    let name = concat!(
        module_path!(),
        "::real_start_rejects_unreadable_or_corrupted_publication_and_rolls_back"
    );
    if !enter_private_namespace(name.split_once("::").unwrap().1) {
        return;
    }
    for iface in ["route-lan0", "route-lan1", "route-wan0"] {
        command(&["tc", "qdisc", "add", "dev", iface, "clsact"]);
    }
    command(&[
        "tc",
        "filter",
        "add",
        "dev",
        "route-lan0",
        "ingress",
        "pref",
        "40000",
        "matchall",
        "action",
        "pass",
    ]);
    let foreign = foreign_filters();
    assert!(!foreign.as_array().unwrap().is_empty());
    // Warm the two deliberately persistent caches before comparing global IDs.
    let mut warm = start_with_options(context(AttachBackend::Tcx, Path::new("/run/warm"))).unwrap();
    if let Some(writer) = warm.start_evidence_writer.take() {
        writer.join().unwrap().unwrap();
    }
    assert_eq!(warm.cleanup().unwrap()["status"], "pass");
    drop(warm);
    assert_no_bindings_or_topology();
    let pins = pin_paths(Path::new("/sys/fs/bpf"));
    let qdiscs = json_command(&["tc", "-j", "qdisc", "show"]);
    let baseline: Vec<_> = ["map", "prog", "link"].map(object_ids).into();
    for backend in [AttachBackend::Tcx, AttachBackend::TcNetlink] {
        for fault in [
            Fault::ReadDenied,
            Fault::Missing(0),
            Fault::Missing(1),
            Fault::Missing(2),
            Fault::Missing(3),
            Fault::Missing(4),
            Fault::Replace(0),
            Fault::Replace(1),
            Fault::Replace(2),
            Fault::Replace(3),
            Fault::Replace(4),
        ] {
            PROBE.with_borrow_mut(|probe| {
                *probe = Some(Probe {
                    fault,
                    injected: false,
                    executed: Vec::new(),
                    cleanup: Vec::new(),
                })
            });
            let path = PathBuf::from(format!("/run/listener-{backend:?}-{fault:?}"));
            let error = match start_with_options(context(backend, &path)) {
                Ok(mut runtime) => {
                    runtime.cleanup();
                    panic!("bad publication admitted: {fault:?}");
                }
                Err(error) => error,
            };
            let probe = PROBE.with_borrow_mut(Option::take).unwrap();
            assert!(
                probe.injected,
                "failure occurred before real publication: {error}"
            );
            if matches!(fault, Fault::ReadDenied) {
                assert!(
                    error.contains("observe ready listener before host attach"),
                    "{error}"
                );
                assert!(error.contains("Operation not permitted"), "{error}");
            } else {
                assert!(
                    error.contains("listener kernel publication missing"),
                    "{error}"
                );
            }
            let roles: Vec<_> = probe
                .executed
                .iter()
                .filter_map(|step| step["role"].as_str())
                .collect();
            assert!(
                !roles.contains(&"host_ingress"),
                "host attached before rejection"
            );
            assert_eq!(
                probe
                    .executed
                    .iter()
                    .filter(|step| step["native_attach"]["attached"] == true)
                    .count(),
                7
            );
            // This error precedes construction of the binding registry. Check
            // the actual kernel state below rather than expecting its report.
            assert!(!probe.cleanup.is_empty(), "startup skipped rollback");
            assert_no_bindings_or_topology();
            assert_eq!(foreign_filters(), foreign, "foreign filter changed");
            assert_eq!(pin_paths(Path::new("/sys/fs/bpf")), pins);
            assert_eq!(json_command(&["tc", "-j", "qdisc", "show"]), qdiscs);
            for _ in 0..50 {
                if ["map", "prog", "link"].map(object_ids).as_slice() == baseline {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(["map", "prog", "link"].map(object_ids).as_slice(), baseline);
            eprintln!(
                "real startup {backend:?}/{fault:?}: rejected; host absent; TC/cgroup/topology rolled back; foreign filter and BPF IDs unchanged"
            );
        }
    }
}
