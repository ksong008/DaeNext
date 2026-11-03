//! Real-kernel negative tests for listener publication and UDP initialization.
use super::*;
use crate::runtime_maps::{delete_map_elem_bytes, update_map_elem_bytes};
use crate::{BpfRedirectEntry, BpfRedirectKey, BpfTuplesKey, BpfUdpConnState};
use aya::programs::{TestRun, TestRunOptions};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::AsFd;

struct TestPins(Option<PathBuf>);
impl TestPins {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = crate::default_bpffs_mount().unwrap().join(format!(
            "dae-listener-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(Some(path))
    }
    fn take_path(&mut self) -> PathBuf {
        self.0.take().expect("test pin path already transferred")
    }
}
impl Drop for TestPins {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

pub(super) fn bytes<T>(value: &T) -> &[u8] {
    // All callers explicitly initialize every field, including ABI padding.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}
use std::mem::size_of;

fn loaded() -> Option<AyaUserspaceLoadedObject> {
    loaded_with_timeout(None)
}
pub(super) fn loaded_with_timeout(idle_ns: Option<u64>) -> Option<AyaUserspaceLoadedObject> {
    loaded_with_profile(idle_ns, None)
}
pub(super) fn loaded_with_profile(
    idle_ns: Option<u64>,
    profile: Option<crate::RuntimeMapProfile>,
) -> Option<AyaUserspaceLoadedObject> {
    loaded_with_dae0_ifindex(idle_ns, profile, 1)
}
pub(super) fn loaded_with_dae0_ifindex(
    idle_ns: Option<u64>,
    profile: Option<crate::RuntimeMapProfile>,
    dae0_ifindex: u32,
) -> Option<AyaUserspaceLoadedObject> {
    if std::env::var("DAE_RUN_LISTENER_LIFECYCLE_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip listener lifecycle kernel tests: opt-in required");
        return None;
    }
    let path = PathBuf::from(
        std::env::var_os("DAE_TEST_NATIVE_BPF_OBJECT").expect("native object required"),
    );
    let mut pins = TestPins::new();
    let mut options = AyaUserspaceLoaderOptions::new(&path);
    if let Some(profile) = profile {
        options.max_entries_overrides = profile.max_entries_overrides();
    }
    options.map_pin_path = pins.0.as_deref();
    options.param = Some(crate::build_dae_param(crate::DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 99,
        dae0_ifindex,
        dae_netns_id: 49,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: false,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    }));
    if let Some(idle_ns) = idle_ns {
        options.param.as_mut().unwrap().udp_state_idle_timeout_ns = idle_ns;
    }
    let mut loaded = load_aya_userspace_object(options).unwrap();
    loaded.pin_guard = Some(AyaTestPinGuard(pins.take_path()));
    Some(loaded)
}

#[test]
fn private_pins_live_until_the_loaded_object_is_released() {
    let Some(loaded) = loaded() else { return };
    let path = loaded.report.map_pin_path.clone().unwrap();
    assert!(path.is_dir());
    assert!(path.join("cookie_pid_map").exists());
    drop(loaded);
    assert!(!path.exists());
}
pub(super) fn packet(proto: u8) -> Vec<u8> {
    let mut data = vec![0; 14 + 20 + 20];
    data[12..14].copy_from_slice(&[8, 0]);
    data[14] = 0x45;
    data[16..18].copy_from_slice(&40u16.to_be_bytes());
    data[22] = 64;
    data[23] = proto;
    data[26..30].copy_from_slice(&[127, 0, 0, 1]);
    data[30..34].copy_from_slice(&[127, 0, 0, 2]);
    data[34..36].copy_from_slice(&1234u16.to_be_bytes());
    data[36..38].copy_from_slice(&443u16.to_be_bytes());
    if proto == 6 {
        data[46] = 0x50;
        data[47] = 2;
    } else {
        data[38..40].copy_from_slice(&20u16.to_be_bytes());
    }
    data
}
pub(super) fn tuple(proto: u8) -> BpfTuplesKey {
    let mut key = BpfTuplesKey::zeroed();
    key.sip.u6_addr8[10..].copy_from_slice(&[255, 255, 127, 0, 0, 1]);
    key.dip.u6_addr8[10..].copy_from_slice(&[255, 255, 127, 0, 0, 2]);
    key.sport = 1234u16.to_be();
    key.dport = 443u16.to_be();
    key.l4proto = proto;
    key
}
pub(super) fn map_fd(loaded: &AyaUserspaceLoadedObject, name: &str) -> i32 {
    let data = match loaded.ebpf.map(name).unwrap() {
        Map::SockMap(data) | Map::LruHashMap(data) | Map::HashMap(data) | Map::Array(data) => data,
        _ => panic!("unexpected map kind for {name}"),
    };
    data.fd().as_fd().as_raw_fd()
}
pub(super) fn load(loaded: &mut AyaUserspaceLoadedObject, name: &str) {
    let program: &mut SchedClassifier = loaded.ebpf.program_mut(name).unwrap().try_into().unwrap();
    program.load().unwrap();
}
fn run(loaded: &AyaUserspaceLoadedObject, name: &str, proto: u8) -> u32 {
    let program: &SchedClassifier = loaded.ebpf.program(name).unwrap().try_into().unwrap();
    program
        .test_run(TestRunOptions {
            data_in: Some(&packet(proto)),
            repeat: 1,
            ..Default::default()
        })
        .unwrap()
        .return_value
}
#[test]
fn listener_unpublished_missing_and_assign_failed_packets_are_dropped_and_counted() {
    let Some(mut loaded) = loaded() else { return };
    let program = "tproxy_dae0peer_ingress";
    load(&mut loaded, program);
    let tuples = tuple(6);
    let key = BpfRedirectKey {
        sip: tuples.sip,
        dip: tuples.dip,
        sport: tuples.sport,
        dport: tuples.dport,
        l4proto: 6,
        abi_version: crate::REDIRECT_TRACK_ABI_VERSION,
        padding: [0; 2],
        generation: (99u64 << 32) | 1,
    };
    let entry = BpfRedirectEntry {
        abi_version: crate::REDIRECT_TRACK_ABI_VERSION,
        ..BpfRedirectEntry::zeroed()
    };
    update_map_elem_bytes(
        map_fd(&loaded, "redirect_track"),
        bytes(&key),
        bytes(&entry),
    )
    .unwrap();
    assert_eq!(run(&loaded, program, 6), 2);
    assert_eq!(
        read_aya_tproxy_metrics(&loaded)
            .unwrap()
            .listener_not_ready_total,
        1
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let id = crate::map_info(map_fd(&loaded, "listen_socket_map"))
        .unwrap()
        .id;
    crate::update_listen_socket_map_by_id(id, listener.as_raw_fd(), None, udp.as_raw_fd(), None)
        .unwrap();
    delete_map_elem_bytes(map_fd(&loaded, "listen_socket_map"), &0u32.to_ne_bytes()).unwrap();
    assert_eq!(run(&loaded, program, 6), 2);
    assert_eq!(
        read_aya_tproxy_metrics(&loaded)
            .unwrap()
            .listener_lookup_miss_total,
        1
    );
    // A UDP socket in the TCP slot is legal in SOCKMAP but sk_assign rejects
    // the protocol mismatch. This executes the failure branch in the kernel.
    update_map_elem_bytes(
        map_fd(&loaded, "listen_socket_map"),
        &0u32.to_ne_bytes(),
        &(udp.as_raw_fd() as u64).to_ne_bytes(),
    )
    .unwrap();
    assert_eq!(run(&loaded, program, 6), 2);
    assert_eq!(
        read_aya_tproxy_metrics(&loaded)
            .unwrap()
            .sk_assign_failure_total,
        1
    );
}
#[test]
fn visible_udp_entry_is_initialized_by_its_first_observer_before_classification() {
    let Some(mut loaded) = loaded_with_timeout(Some(100_000_000)) else {
        return;
    };
    let program = "tproxy_lan_ingress_l2";
    load(&mut loaded, program);
    // Freeze the insertion window, without leaving another CPU to initialize.
    // The observer must arm a real timer before using the existing direction.
    let state = BpfUdpConnState::new(false);
    update_map_elem_bytes(
        map_fd(&loaded, "udp_conn_state_map"),
        bytes(&tuple(17)),
        bytes(&state),
    )
    .unwrap();
    let direct = crate::BpfMatchSet {
        kind: crate::MATCH_TYPE_FALLBACK,
        outbound: 0,
        ..Default::default()
    };
    update_map_elem_bytes(
        map_fd(&loaded, "routing_map"),
        &0u32.to_ne_bytes(),
        bytes(&direct),
    )
    .unwrap();
    assert_eq!(run(&loaded, program, 17), u32::MAX);
    let metrics = read_aya_udp_state_metrics(&loaded).unwrap();
    assert_eq!(
        metrics.timer_init_failure_total
            + metrics.timer_callback_failure_total
            + metrics.timer_start_failure_total,
        0
    );
    assert_eq!(metrics.state_refresh_total, 1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while crate::count_map_entries_by_fd(map_fd(&loaded, "udp_conn_state_map")).unwrap() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "assisted timer never reclaimed its entry"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn concurrent_udp_creation_refresh_and_timer_expiry_release_every_entry() {
    let idle_ns = std::env::var("DAE_TEST_UDP_IDLE_TIMEOUT_NS").map_or(500_000_000, |value| {
        value.parse::<u64>().expect("valid test timer TTL")
    });
    let Some(mut loaded) = loaded_with_timeout(Some(idle_ns)) else {
        return;
    };
    let name = "tproxy_lan_ingress_l2";
    load(&mut loaded, name);
    let direct = crate::BpfMatchSet {
        kind: crate::MATCH_TYPE_FALLBACK,
        outbound: 0,
        ..Default::default()
    };
    update_map_elem_bytes(
        map_fd(&loaded, "routing_map"),
        &0u32.to_ne_bytes(),
        bytes(&direct),
    )
    .unwrap();
    let program: &SchedClassifier = loaded.ebpf.program(name).unwrap().try_into().unwrap();
    let barrier = std::sync::Barrier::new(8);
    let dropped = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let barrier = &barrier;
            let dropped = &dropped;
            scope.spawn(move || {
                barrier.wait();
                for sequence in 0..512u16 {
                    let mut data = packet(17);
                    data[34..36].copy_from_slice(&(1234 + sequence % 64).to_be_bytes());
                    let action = program
                        .test_run(TestRunOptions {
                            data_in: Some(&data),
                            repeat: 1,
                            ..Default::default()
                        })
                        .unwrap()
                        .return_value;
                    match action {
                        2 => {
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        u32::MAX => {}
                        other => panic!("unexpected concurrent UDP action: {other}"),
                    }
                }
            });
        }
    });
    let metrics = read_aya_udp_state_metrics(&loaded).unwrap();
    assert!(metrics.state_created_total >= 64);
    assert!(metrics.state_refresh_total > 0);
    assert_eq!(metrics.timer_init_failure_total, 0);
    assert_eq!(metrics.timer_callback_failure_total, 0);
    let rejected = dropped.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        rejected, 0,
        "creation/refresh must cooperatively initialize instead of rejecting racing packets"
    );
    assert_eq!(
        rejected as u64,
        metrics.insert_failure_total
            + metrics.post_insert_lookup_failure_total
            + metrics.timer_start_failure_total,
        "every fail-closed packet must have corresponding failure evidence"
    );
    let fd = map_fd(&loaded, "udp_conn_state_map");
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_nanos(idle_ns)
            .saturating_add(std::time::Duration::from_secs(5));
    loop {
        let entries = crate::count_map_entries_by_fd(fd).unwrap();
        if entries == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timers leaked {entries} entries"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    eprintln!(
        "verified 4096 concurrent UDP packets across 64 tuples, {rejected} fail-closed packets, and complete timer reclamation: {metrics:?}"
    );
}
