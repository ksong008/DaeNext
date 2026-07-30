use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dae_outbound::anytls::{AnyTlsPaddingScheme, contract as anytls_contract, link as anytls_link};
use dae_outbound::socks5::Socks5Address;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tokio_rustls::TlsAcceptor;

use super::anytls_owner::start_anytls_owner_registry_with_resources;
use super::*;

const TEST_AUTH: &str = "anytls-owner-test-secret";
const TEST_TARGET: &str = "192.0.2.10:443";

#[derive(Default)]
struct AnyTlsServerObservation {
    connections: AtomicUsize,
    authentications: AtomicUsize,
    invalid_authentications: AtomicUsize,
    heartbeats: AtomicUsize,
    logical_settings: Mutex<Vec<(u64, u32)>>,
    logical_setting_payloads: Mutex<Vec<Vec<u8>>>,
    logical_application_payloads: Mutex<Vec<(u64, u32, Vec<u8>)>>,
    connection_senders: Mutex<HashMap<u64, mpsc::UnboundedSender<AnyTlsServerCommand>>>,
    latest_connection_id: AtomicU64,
}

enum AnyTlsServerCommand {
    Frame { cmd: u8, sid: u32, data: Vec<u8> },
    Close,
}

impl AnyTlsServerObservation {
    fn inject_latest_frame(&self, cmd: u8, sid: u32, data: &[u8]) {
        let connection_id = self.latest_connection_id.load(Ordering::Acquire);
        let sender = self
            .connection_senders
            .lock()
            .unwrap()
            .get(&connection_id)
            .cloned()
            .expect("AnyTLS test connection sender is registered");
        sender
            .send(AnyTlsServerCommand::Frame {
                cmd,
                sid,
                data: data.to_vec(),
            })
            .unwrap();
    }

    fn close_latest_connection(&self) {
        let connection_id = self.latest_connection_id.load(Ordering::Acquire);
        let sender = self
            .connection_senders
            .lock()
            .unwrap()
            .get(&connection_id)
            .cloned()
            .expect("AnyTLS test connection sender is registered");
        sender.send(AnyTlsServerCommand::Close).unwrap();
    }
}

struct AnyTlsTestServer {
    addr: SocketAddr,
    observation: Arc<AnyTlsServerObservation>,
    respond_to_heartbeats: Arc<AtomicBool>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AnyTlsTestSynackPolicy {
    AfterTarget,
    AfterFirstPayloadWithEarlyResponse,
}

impl AnyTlsTestServer {
    async fn start(respond_to_heartbeats: bool) -> Self {
        Self::start_with_synack_policy(respond_to_heartbeats, AnyTlsTestSynackPolicy::AfterTarget)
            .await
    }

    async fn start_with_synack_policy(
        respond_to_heartbeats: bool,
        synack_policy: AnyTlsTestSynackPolicy,
    ) -> Self {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = anytls_test_tls_acceptor();
        let observation = Arc::new(AnyTlsServerObservation::default());
        let respond_to_heartbeats = Arc::new(AtomicBool::new(respond_to_heartbeats));
        let task_observation = Arc::clone(&observation);
        let task_heartbeat_policy = Arc::clone(&respond_to_heartbeats);
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let acceptor = acceptor.clone();
                        let observation = Arc::clone(&task_observation);
                        let respond_to_heartbeats = Arc::clone(&task_heartbeat_policy);
                        connections.spawn(async move {
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            run_anytls_test_connection(
                                stream,
                                observation,
                                respond_to_heartbeats,
                                synack_policy,
                            )
                            .await;
                        });
                    }
                    completion = connections.join_next(), if !connections.is_empty() => {
                        let _ = completion;
                    }
                }
            }
            let senders = task_observation
                .connection_senders
                .lock()
                .unwrap()
                .drain()
                .map(|(_, sender)| sender)
                .collect::<Vec<_>>();
            for sender in senders {
                let _ = sender.send(AnyTlsServerCommand::Close);
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            addr,
            observation,
            respond_to_heartbeats,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

struct AnyTlsTestFrame {
    cmd: u8,
    sid: u32,
    data: Vec<u8>,
}

#[derive(Default)]
struct AnyTlsTestStreamState {
    target: Option<String>,
    application_writes: usize,
    synack_sent: bool,
}

async fn run_anytls_test_connection<S>(
    mut stream: S,
    observation: Arc<AnyTlsServerObservation>,
    respond_to_heartbeats: Arc<AtomicBool>,
    synack_policy: AnyTlsTestSynackPolicy,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let connection_id = observation.connections.fetch_add(1, Ordering::AcqRel) as u64 + 1;
    observation
        .latest_connection_id
        .store(connection_id, Ordering::Release);
    let mut auth = vec![0_u8; anytls_link::handshake_auth_bytes(TEST_AUTH).len()];
    if stream.read_exact(&mut auth).await.is_err() {
        return;
    }
    if auth == anytls_link::handshake_auth_bytes(TEST_AUTH) {
        observation.authentications.fetch_add(1, Ordering::Relaxed);
    } else {
        observation
            .invalid_authentications
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    let (command_sender, mut commands) = mpsc::unbounded_channel();
    observation
        .connection_senders
        .lock()
        .unwrap()
        .insert(connection_id, command_sender);
    let mut logical = HashMap::<u32, AnyTlsTestStreamState>::new();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(AnyTlsServerCommand::Frame { cmd, sid, data }) => {
                    if write_anytls_test_frame(&mut stream, cmd, sid, &data).await.is_err() {
                        break;
                    }
                }
                Some(AnyTlsServerCommand::Close) | None => break,
            },
            frame = read_anytls_test_frame(&mut stream) => {
                let Ok(frame) = frame else {
                    break;
                };
                match frame.cmd {
                    anytls_contract::CMD_SETTINGS => {
                        observation
                            .logical_settings
                            .lock()
                            .unwrap()
                            .push((connection_id, frame.sid));
                        observation
                            .logical_setting_payloads
                            .lock()
                            .unwrap()
                            .push(frame.data.clone());
                        logical.entry(frame.sid).or_default();
                    }
                    anytls_contract::CMD_SYN => {
                        logical.entry(frame.sid).or_default();
                    }
                    anytls_contract::CMD_PSH => {
                        let state = logical.entry(frame.sid).or_default();
                        if state.target.is_none() {
                            let target = Socks5Address::decode(&frame.data)
                                .map(|(target, _)| target.authority())
                                .unwrap_or_default();
                            let delay_synack = synack_policy
                                == AnyTlsTestSynackPolicy::AfterFirstPayloadWithEarlyResponse
                                && target.starts_with(anytls_contract::UDP_MAGIC_DOMAIN);
                            state.target = Some(target);
                            if !delay_synack {
                                if write_anytls_test_frame(
                                    &mut stream,
                                    anytls_contract::CMD_SYNACK,
                                    frame.sid,
                                    &[],
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                                state.synack_sent = true;
                            }
                        } else {
                            let response = anytls_test_application_response(state, &frame.data);
                            observation
                                .logical_application_payloads
                                .lock()
                                .unwrap()
                                .push((connection_id, frame.sid, frame.data.clone()));
                            state.application_writes = state.application_writes.saturating_add(1);
                            if write_anytls_test_frame(
                                &mut stream,
                                anytls_contract::CMD_PSH,
                                frame.sid,
                                &response,
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                            if !state.synack_sent {
                                if write_anytls_test_frame(
                                    &mut stream,
                                    anytls_contract::CMD_SYNACK,
                                    frame.sid,
                                    &[],
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                                state.synack_sent = true;
                            }
                        }
                    }
                    anytls_contract::CMD_FIN => {
                        logical.remove(&frame.sid);
                    }
                    anytls_contract::CMD_HEART_REQUEST => {
                        observation.heartbeats.fetch_add(1, Ordering::Relaxed);
                        if respond_to_heartbeats.load(Ordering::Acquire)
                            && write_anytls_test_frame(
                                &mut stream,
                                anytls_contract::CMD_HEART_RESPONSE,
                                frame.sid,
                                &[],
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    anytls_contract::CMD_HEART_RESPONSE
                    | anytls_contract::CMD_WASTE
                    | anytls_contract::CMD_SERVER_SETTINGS
                    | anytls_contract::CMD_UPDATE_PADDING => {}
                    _ => {}
                }
            }
        }
    }
    observation
        .connection_senders
        .lock()
        .unwrap()
        .remove(&connection_id);
    let _ = stream.shutdown().await;
}

fn anytls_test_application_response(state: &AnyTlsTestStreamState, data: &[u8]) -> Vec<u8> {
    let is_udp = state
        .target
        .as_deref()
        .is_some_and(|target| target.starts_with(anytls_contract::UDP_MAGIC_DOMAIN));
    if !is_udp {
        return data.to_vec();
    }
    let decoded = if state.application_writes == 0 {
        dae_outbound::anytls::decode_packet_first_write(data)
    } else {
        dae_outbound::anytls::decode_packet_next_write(data)
    };
    decoded
        .map(|packet| anytls_link::packet_next_write(&packet.payload))
        .unwrap_or_default()
}

async fn read_anytls_test_frame(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<AnyTlsTestFrame, String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("read AnyTLS test header: {error}"))?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0_u8; len];
    stream
        .read_exact(&mut data)
        .await
        .map_err(|error| format!("read AnyTLS test data: {error}"))?;
    Ok(AnyTlsTestFrame {
        cmd: header[0],
        sid: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        data,
    })
}

async fn write_anytls_test_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    cmd: u8,
    sid: u32,
    data: &[u8],
) -> Result<(), String> {
    stream
        .write_all(&anytls_link::frame(cmd, sid, data))
        .await
        .map_err(|error| format!("write AnyTLS test frame: {error}"))
}

fn anytls_test_tls_acceptor() -> TlsAcceptor {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

fn anytls_proxy(addr: SocketAddr, generation: u64) -> plan::ResidentProxyBinding {
    let config = dae_config::Config {
        global: dae_config::Global::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: dae_config::Routing::default(),
        dns: dae_config::Dns::default(),
    };
    let mut proxy = plan::build_resident_proxy_plan_for_node(
        &config,
        "anytls-owner-test".to_owned(),
        "anytls-owner-node".to_owned(),
        format!(
            "anytls://{TEST_AUTH}@{}:{}?insecure=1&peer=localhost#owner-test",
            addr.ip(),
            addr.port(),
        ),
    )
    .unwrap();
    proxy.materialize_execution();
    plan::ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(generation),
    )
    .expect("materialized AnyTLS owner test binding")
}

fn anytls_owner_resources(
    idle_timeout: Duration,
    probe_threshold: Duration,
    probe_timeout: Duration,
) -> AnyTlsOwnerResourceProfile {
    AnyTlsOwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
        .with_idle_policy_for_test(idle_timeout, probe_threshold, probe_timeout)
}

fn anytls_owner_deadline() -> dae_runtime_control::AbsoluteDeadline {
    dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2))
}

async fn acquire_from_fresh_runtime(
    registry: AnyTlsOwnerRegistryHandle,
    proxy: plan::ResidentProxyBinding,
) -> AnyTlsLogicalStreamLease {
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(registry.acquire(proxy, TEST_TARGET.to_owned(), anytls_owner_deadline()))
    })
    .await
    .unwrap()
    .unwrap()
}

async fn assert_echo(lease: &mut AnyTlsLogicalStreamLease, payload: &[u8]) {
    lease.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    lease.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("AnyTLS owner integration state reached before timeout");
}

async fn stop_anytls_owner_registry(
    stop: SharedResidentStopSignal,
    owner_thread: std::thread::JoinHandle<()>,
) {
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || owner_thread.join().unwrap())
        .await
        .unwrap();
}

fn assert_anytls_owner_resources_released(registry: &AnyTlsOwnerRegistryHandle) {
    let owner = registry.metrics_snapshot();
    assert_eq!(owner["registeredKeys"], 0);
    assert_eq!(owner["registeredPhysicalSessions"], 0);
    assert_eq!(owner["activePhysicalSessions"], 0);
    assert_eq!(owner["idlePhysicalSessions"], 0);
    assert_eq!(owner["activeLogicalStreams"], 0);
    assert_eq!(owner["currentLogicalBufferBytes"], 0);
    assert_eq!(owner["ownerStateBytesLowerBound"], 0);
    assert_eq!(owner["ownerPaddingSchemeBytes"], 0);
    assert_eq!(owner["activeBuilds"], 0);
    assert_eq!(owner["shutdownTimedOut"], false);
}

#[test]
fn anytls_owner_reuses_one_auth_across_caller_runtimes_and_drops_late_sid_frames() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = AnyTlsTestServer::start(true).await;
            let generation = 9_101;
            let proxy = anytls_proxy(server.addr, generation);
            let stop = ResidentStopSignal::shared();
            let resources = anytls_owner_resources(
                Duration::from_secs(5),
                Duration::from_secs(2),
                Duration::from_millis(100),
            );
            let (registry, owner_thread) = start_anytls_owner_registry_with_resources(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                resources,
            )
            .unwrap();

            let mut first = acquire_from_fresh_runtime(registry.clone(), proxy.clone()).await;
            assert_eq!(first.sid(), 1);
            assert!(!first.reused());
            let physical_instance = first.physical_instance_id();
            let updated_padding = b"stop=20\n4=30-30";
            server
                .observation
                .inject_latest_frame(anytls_contract::CMD_SERVER_SETTINGS, 0, b"v=2");
            server.observation.inject_latest_frame(
                anytls_contract::CMD_UPDATE_PADDING,
                0,
                updated_padding,
            );
            wait_until(|| {
                let snapshot = registry.metrics_snapshot();
                snapshot["peerVersion"] == 2 && snapshot["cumulativePaddingUpdates"] == 1
            })
            .await;
            assert_echo(&mut first, b"first").await;
            let first_sid = first.sid();
            first.shutdown().await.unwrap();
            drop(first);
            wait_until(|| registry.metrics_snapshot()["idlePhysicalSessions"] == 1).await;

            let mut second = acquire_from_fresh_runtime(registry.clone(), proxy.clone()).await;
            assert_eq!(second.physical_instance_id(), physical_instance);
            assert_eq!(second.sid(), 2);
            assert!(second.reused());
            server.observation.inject_latest_frame(
                anytls_contract::CMD_PSH,
                first_sid,
                b"late-first-stream",
            );
            wait_until(|| registry.metrics_snapshot()["lateFrames"] == 1).await;
            assert_echo(&mut second, b"second").await;
            second.shutdown().await.unwrap();
            drop(second);
            wait_until(|| registry.metrics_snapshot()["idlePhysicalSessions"] == 1).await;

            let udp_target: SocketAddr = "192.0.2.20:5353".parse().unwrap();
            let udp = super::udp::exercise_anytls_udp_stream_session(
                proxy.clone(),
                registry.clone(),
                udp_target,
                b"udp-payload",
                anytls_owner_deadline(),
            )
            .await
            .unwrap();
            assert_eq!(udp.payload, b"udp-payload");
            assert_eq!(udp.sid, 3);
            assert_eq!(udp.physical_instance_id, physical_instance);
            assert!(udp.reused);
            wait_until(|| registry.metrics_snapshot()["idlePhysicalSessions"] == 1).await;

            server.observation.close_latest_connection();
            wait_until(|| {
                let snapshot = registry.metrics_snapshot();
                snapshot["registeredPhysicalSessions"] == 0
                    && snapshot["activePhysicalSessions"] == 0
            })
            .await;
            let mut replacement = acquire_from_fresh_runtime(registry.clone(), proxy.clone()).await;
            assert_ne!(replacement.physical_instance_id(), physical_instance);
            assert_eq!(replacement.sid(), 1);
            assert!(!replacement.reused());
            assert_echo(&mut replacement, b"replacement").await;
            replacement.shutdown().await.unwrap();
            drop(replacement);
            wait_until(|| registry.metrics_snapshot()["idlePhysicalSessions"] == 1).await;

            assert_eq!(server.observation.connections.load(Ordering::Relaxed), 2);
            assert_eq!(
                server.observation.authentications.load(Ordering::Relaxed),
                2
            );
            assert_eq!(
                server
                    .observation
                    .invalid_authentications
                    .load(Ordering::Relaxed),
                0
            );
            assert_eq!(
                server.observation.logical_settings.lock().unwrap().clone(),
                vec![(1, 1), (1, 2), (1, 3), (2, 1)]
            );
            let updated_settings = AnyTlsPaddingScheme::parse(updated_padding)
                .unwrap()
                .settings_bytes();
            let setting_payloads = server
                .observation
                .logical_setting_payloads
                .lock()
                .unwrap()
                .clone();
            assert_eq!(setting_payloads[0], anytls_link::settings_bytes());
            assert_eq!(setting_payloads[1], anytls_link::settings_bytes());
            assert_eq!(setting_payloads[2], anytls_link::settings_bytes());
            assert_eq!(setting_payloads[3], updated_settings);
            let snapshot = registry.metrics_snapshot();
            assert_eq!(snapshot["mode"], "bounded-idle-reuse");
            assert_eq!(snapshot["concurrentLogicalMultiplexing"], false);
            assert!(
                snapshot["cumulativePaddingWasteFrames"]
                    .as_u64()
                    .unwrap_or(0)
                    >= 1
            );

            stop_anytls_owner_registry(stop, owner_thread).await;
            assert_anytls_owner_resources_released(&registry);
            server.stop().await;
        });
}

#[test]
fn anytls_udp_sends_one_bounded_initial_payload_before_synack_and_preserves_early_response() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = AnyTlsTestServer::start_with_synack_policy(
                true,
                AnyTlsTestSynackPolicy::AfterFirstPayloadWithEarlyResponse,
            )
            .await;
            let generation = 9_103;
            let proxy = anytls_proxy(server.addr, generation);
            let stop = ResidentStopSignal::shared();
            let resources = anytls_owner_resources(
                Duration::from_secs(5),
                Duration::from_secs(2),
                Duration::from_millis(100),
            );
            let (registry, owner_thread) = start_anytls_owner_registry_with_resources(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                resources,
            )
            .unwrap();

            let udp_target: SocketAddr = "192.0.2.53:5353".parse().unwrap();
            let udp_payload = b"udp-before-synack";
            let udp = super::udp::exercise_anytls_udp_stream_session(
                proxy.clone(),
                registry.clone(),
                udp_target,
                udp_payload,
                anytls_owner_deadline(),
            )
            .await
            .unwrap();
            assert_eq!(udp.payload, udp_payload);
            assert!(!udp.reused);

            let application_payloads = server
                .observation
                .logical_application_payloads
                .lock()
                .unwrap()
                .clone();
            assert_eq!(application_payloads.len(), 1);
            assert_eq!(application_payloads[0].0, 1);
            assert_eq!(application_payloads[0].1, udp.sid);
            let decoded =
                dae_outbound::anytls::decode_packet_first_write(&application_payloads[0].2)
                    .unwrap();
            assert_eq!(
                decoded.target.as_deref(),
                Some(udp_target.to_string().as_str())
            );
            assert_eq!(decoded.payload, udp_payload);

            wait_until(|| registry.metrics_snapshot()["idlePhysicalSessions"] == 1).await;
            let mut tcp = registry
                .acquire(
                    proxy.clone(),
                    TEST_TARGET.to_owned(),
                    anytls_owner_deadline(),
                )
                .await
                .unwrap();
            assert!(tcp.reused());
            assert_eq!(tcp.physical_instance_id(), udp.physical_instance_id);
            assert_echo(&mut tcp, b"tcp-after-udp").await;
            tcp.shutdown().await.unwrap();
            drop(tcp);

            stop_anytls_owner_registry(stop, owner_thread).await;
            assert_anytls_owner_resources_released(&registry);
            server.stop().await;
        });
}

#[test]
fn anytls_owner_identity_partitions_tls_security_and_parent_transport() {
    let base = anytls_proxy("127.0.0.1:443".parse().unwrap(), 9_104);
    let base_digest = super::anytls_owner::anytls_owner_key_digest_for_test(base.plan());

    let mut fingerprinted = base.plan().clone();
    fingerprinted.utls_fingerprint = Some(plan::ResidentUtlsFingerprintPlan {
        source: "link fp",
        requested: "chrome".to_owned(),
        name: "chrome".to_owned(),
        canonical: "chrome_auto".to_owned(),
        family: dae_outbound::shared_transport::UTLS_FAMILY_CHROME.to_owned(),
        client: "chrome".to_owned(),
        randomized: false,
        alpn_policy: "fingerprint-default".to_owned(),
        default_alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
    });
    assert_ne!(
        base_digest,
        super::anytls_owner::anytls_owner_key_digest_for_test(&fingerprinted)
    );

    let mut reality = base.plan().clone();
    reality.tls = "reality".to_owned();
    reality.reality = Some(plan::ResidentRealityUnderlayPlan {
        public_key: [7_u8; 32],
        short_id: vec![1, 2, 3, 4],
        spider_x: "/probe".to_owned(),
    });
    assert_ne!(
        base_digest,
        super::anytls_owner::anytls_owner_key_digest_for_test(&reality)
    );

    let mut parent = base.plan().clone();
    parent.handler = plan::ResidentProxyProtocolPlan::Socks5Tcp {
        username: String::new(),
        password: String::new(),
    };
    let mut chained = base.plan().clone();
    chained.chain_parent = Some(Arc::new(parent));
    assert_ne!(
        base_digest,
        super::anytls_owner::anytls_owner_key_digest_for_test(&chained)
    );
}

#[test]
fn anytls_owner_bounds_concurrent_physical_sessions_probes_idle_and_expires() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = AnyTlsTestServer::start(true).await;
            let generation = 9_102;
            let proxy = anytls_proxy(server.addr, generation);
            let stop = ResidentStopSignal::shared();
            let resources = anytls_owner_resources(
                Duration::from_millis(180),
                Duration::from_millis(25),
                Duration::from_millis(80),
            );
            let (registry, owner_thread) = start_anytls_owner_registry_with_resources(
                generation,
                Arc::clone(&stop),
                RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                resources,
            )
            .unwrap();

            let mut first = registry
                .acquire(
                    proxy.clone(),
                    TEST_TARGET.to_owned(),
                    anytls_owner_deadline(),
                )
                .await
                .unwrap();
            let mut concurrent = registry
                .acquire(
                    proxy.clone(),
                    TEST_TARGET.to_owned(),
                    anytls_owner_deadline(),
                )
                .await
                .unwrap();
            assert_ne!(
                first.physical_instance_id(),
                concurrent.physical_instance_id()
            );
            assert_echo(&mut first, b"flow-a").await;
            assert_echo(&mut concurrent, b"flow-b").await;
            let admitted_instances = [
                first.physical_instance_id(),
                concurrent.physical_instance_id(),
            ];
            first.shutdown().await.unwrap();
            concurrent.shutdown().await.unwrap();
            drop(first);
            drop(concurrent);
            wait_until(|| {
                let snapshot = registry.metrics_snapshot();
                snapshot["registeredPhysicalSessions"] == 1 && snapshot["idlePhysicalSessions"] == 1
            })
            .await;

            time::sleep(Duration::from_millis(40)).await;
            let mut reused = registry
                .acquire(
                    proxy.clone(),
                    TEST_TARGET.to_owned(),
                    anytls_owner_deadline(),
                )
                .await
                .unwrap();
            assert!(admitted_instances.contains(&reused.physical_instance_id()));
            assert!(reused.reused());
            assert!(server.observation.heartbeats.load(Ordering::Relaxed) >= 1);
            let reused_instance = reused.physical_instance_id();
            assert_echo(&mut reused, b"flow-c").await;
            reused.shutdown().await.unwrap();
            drop(reused);
            wait_until(|| registry.metrics_snapshot()["registeredPhysicalSessions"] == 0).await;

            let rebuilt = registry
                .acquire(
                    proxy.clone(),
                    TEST_TARGET.to_owned(),
                    anytls_owner_deadline(),
                )
                .await
                .unwrap();
            assert_ne!(rebuilt.physical_instance_id(), reused_instance);
            drop(rebuilt);

            stop_anytls_owner_registry(stop, owner_thread).await;
            assert_anytls_owner_resources_released(&registry);
            server.stop().await;
        });
}

#[test]
fn anytls_owner_rebuilds_after_idle_probe_failure_and_releases_five_generations() {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let server = AnyTlsTestServer::start(false).await;
            for offset in 0..5_u64 {
                let generation = 9_200 + offset;
                let proxy = anytls_proxy(server.addr, generation);
                let stop = ResidentStopSignal::shared();
                let resources = anytls_owner_resources(
                    Duration::from_secs(1),
                    Duration::from_millis(20),
                    Duration::from_millis(35),
                );
                let (registry, owner_thread) = start_anytls_owner_registry_with_resources(
                    generation,
                    Arc::clone(&stop),
                    RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
                    resources,
                )
                .unwrap();

                let mut first = registry
                    .acquire(
                        proxy.clone(),
                        TEST_TARGET.to_owned(),
                        anytls_owner_deadline(),
                    )
                    .await
                    .unwrap();
                assert_echo(&mut first, b"before-probe").await;
                let first_instance = first.physical_instance_id();
                first.shutdown().await.unwrap();
                drop(first);
                wait_until(|| registry.metrics_snapshot()["idlePhysicalSessions"] == 1).await;
                time::sleep(Duration::from_millis(30)).await;

                let mut rebuilt = registry
                    .acquire(
                        proxy.clone(),
                        TEST_TARGET.to_owned(),
                        anytls_owner_deadline(),
                    )
                    .await
                    .unwrap();
                assert_ne!(rebuilt.physical_instance_id(), first_instance);
                assert_echo(&mut rebuilt, b"after-probe").await;
                rebuilt.shutdown().await.unwrap();
                drop(rebuilt);
                assert!(
                    registry.metrics_snapshot()["cumulativeIdleProbeFailures"]
                        .as_u64()
                        .unwrap_or(0)
                        >= 1
                );

                stop_anytls_owner_registry(stop, owner_thread).await;
                assert_anytls_owner_resources_released(&registry);
            }
            assert!(server.observation.connections.load(Ordering::Relaxed) >= 10);
            assert!(!server.respond_to_heartbeats.load(Ordering::Relaxed));
            server.stop().await;
        });
}
