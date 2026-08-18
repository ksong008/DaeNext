// DNS listener tasks keep bind sockets, routing, shutdown, and metrics handles explicit.
#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket};
use std::os::fd::AsRawFd;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
};
use tokio::sync::Semaphore;
use tokio::time;

use super::dns::{
    DNS_MAX_UDP_MESSAGE_SIZE, ResidentDnsPlan, ResidentDnsQueryResult, ResidentDnsTraceSummary,
    ResidentDnsTransportTrace, build_dns_server_failure_response, fit_dns_response_to_udp_request,
    handle_resident_dns_local_trace_async,
};
#[cfg(test)]
use super::dns::{
    DNS_TRANSPORT_OUTCOME_SUCCESS, DNS_TRANSPORT_ROUTE_DIRECT, DNS_TRANSPORT_TARGET_FAMILY_IPV4,
    DNS_TRANSPORT_TARGET_FAMILY_IPV6,
};
use super::events::{ResidentEventKind, ResidentEventMetadata, append_event_with_metadata};
use super::*;

#[path = "dns_listener/tcp_admission.rs"]
mod tcp_admission;
use tcp_admission::{ResidentDnsTcpBindAdmission, accept_resident_dns_tcp_bind_connection_async};
#[path = "dns_listener/udp_dispatcher.rs"]
mod udp_dispatcher;
use udp_dispatcher::{ResidentDnsUdpBindDispatcher, ResidentDnsUdpBindJob};
const DNS_BIND_READ_LIMIT: usize = DNS_MAX_UDP_MESSAGE_SIZE;
const DNS_BIND_TCP_IO_TIMEOUT: std::time::Duration = RESIDENT_UDP_RESPONSE_TIMEOUT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentDnsBindEndpoint {
    udp: bool,
    tcp: bool,
    addr: SocketAddr,
}

impl ResidentDnsBindEndpoint {
    const fn network(self) -> &'static str {
        match (self.tcp, self.udp) {
            (true, true) => "tcp+udp",
            (true, false) => "tcp",
            (false, true) => "udp",
            (false, false) => "none",
        }
    }
}

pub(super) struct ResidentDnsBindListener {
    udp_socket: Option<UdpSocket>,
    tcp_listener: Option<StdTcpListener>,
    configured: String,
    endpoint: ResidentDnsBindEndpoint,
    udp_local_addr: Option<SocketAddr>,
    tcp_local_addr: Option<SocketAddr>,
    tcp_listen_backlog: Option<usize>,
    resources: ResidentDnsResourceProfile,
}

impl ResidentDnsBindListener {
    pub(super) fn report(&self) -> Value {
        json!({
            "enabled": true,
            "network": self.endpoint.network(),
            "configured": self.configured,
            "udp_local_addr": self.udp_local_addr.map(|addr| addr.to_string()),
            "tcp_local_addr": self.tcp_local_addr.map(|addr| addr.to_string()),
            "tcp_listen_backlog": self.tcp_listen_backlog,
            "status": "pass",
        })
    }
}

pub(super) fn disabled_dns_bind_listener_report() -> Value {
    json!({
        "enabled": false,
        "network": "none",
        "status": "disabled",
        "reason": "dns.bind is empty",
    })
}

pub(super) fn prepare_resident_dns_bind_listener(
    bind: &str,
    resources: ResidentDnsResourceProfile,
) -> Result<Option<ResidentDnsBindListener>, String> {
    let Some(endpoint) = parse_resident_dns_bind_endpoint(bind)? else {
        return Ok(None);
    };
    let udp_socket = if endpoint.udp {
        let socket = UdpSocket::bind(endpoint.addr)
            .map_err(|err| format!("bind resident DNS UDP listener {}: {err}", endpoint.addr))?;
        socket
            .set_nonblocking(true)
            .map_err(|err| format!("set resident DNS UDP listener nonblocking: {err}"))?;
        Some(socket)
    } else {
        None
    };
    let tcp_listener = if endpoint.tcp {
        let listener = StdTcpListener::bind(endpoint.addr)
            .map_err(|err| format!("bind resident DNS TCP listener {}: {err}", endpoint.addr))?;
        set_resident_dns_tcp_listener_backlog(&listener, resources.bind_tcp_listen_backlog())?;
        listener
            .set_nonblocking(true)
            .map_err(|err| format!("set resident DNS TCP listener nonblocking: {err}"))?;
        Some(listener)
    } else {
        None
    };
    let udp_local_addr = udp_socket
        .as_ref()
        .map(UdpSocket::local_addr)
        .transpose()
        .map_err(|err| format!("read resident DNS UDP listener local addr: {err}"))?;
    let tcp_local_addr = tcp_listener
        .as_ref()
        .map(StdTcpListener::local_addr)
        .transpose()
        .map_err(|err| format!("read resident DNS TCP listener local addr: {err}"))?;
    Ok(Some(ResidentDnsBindListener {
        udp_socket,
        tcp_listener,
        configured: bind.trim().to_owned(),
        endpoint,
        udp_local_addr,
        tcp_local_addr,
        tcp_listen_backlog: endpoint.tcp.then(|| resources.bind_tcp_listen_backlog()),
        resources,
    }))
}

fn set_resident_dns_tcp_listener_backlog(
    listener: &StdTcpListener,
    requested: usize,
) -> Result<(), String> {
    let backlog = i32::try_from(requested)
        .map_err(|_| format!("resident DNS TCP listen backlog exceeds i32: {requested}"))?;
    // SAFETY: the listener owns a valid listening socket for the duration of the call;
    // listen does not take ownership of the descriptor. Linux permits updating the
    // backlog of an existing listening socket, and still caps it by net.core.somaxconn.
    let status = unsafe { libc::listen(listener.as_raw_fd(), backlog) };
    if status < 0 {
        return Err(format!(
            "set resident DNS TCP listen backlog to {requested}: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(super) async fn run_resident_dns_bind_listener_async(
    mut listener: ResidentDnsBindListener,
    active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    executor_worker_threads: usize,
) {
    let configured = listener.configured.clone();
    let resources = listener.resources;
    let mut tasks = tokio::task::JoinSet::new();
    if let Some(socket) = listener.udp_socket.take() {
        let local_addr = listener.udp_local_addr.expect("udp local addr was read");
        match TokioUdpSocket::from_std(socket) {
            Ok(socket) => {
                tasks.spawn(run_resident_dns_udp_bind_listener_async(
                    socket,
                    configured.clone(),
                    local_addr,
                    active_generation.clone(),
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    resources,
                    executor_worker_threads,
                ));
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_listener_start_failed",
                    "configured": configured,
                    "local_addr": local_addr.to_string(),
                    "network": "udp",
                    "error": format!("adopt async resident DNS UDP listener: {err}"),
                }),
            ),
        }
    }
    if let Some(tcp_listener) = listener.tcp_listener.take() {
        let local_addr = listener.tcp_local_addr.expect("tcp local addr was read");
        match TokioTcpListener::from_std(tcp_listener) {
            Ok(tcp_listener) => {
                tasks.spawn(run_resident_dns_tcp_bind_listener_async(
                    tcp_listener,
                    configured.clone(),
                    local_addr,
                    active_generation,
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    resources,
                ));
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_listener_start_failed",
                    "configured": configured,
                    "local_addr": local_addr.to_string(),
                    "network": "tcp",
                    "error": format!("adopt async resident DNS TCP listener: {err}"),
                }),
            ),
        }
    }
    if tasks.is_empty() {
        append_event(
            &event_file,
            &event_lock,
            json!({
                "event": "dns_bind_listener_start_failed",
                "configured": configured,
                "error": "no resident DNS bind listener socket was started",
            }),
        );
        return;
    }
    let mut stop_listener = stop.listener();
    while !tasks.is_empty() && !stop.load(Ordering::Relaxed) {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            _ = tasks.join_next() => {}
        }
    }
    let shutdown =
        shutdown_resident_task_set(&mut tasks, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE).await;
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_runtime_stopped",
            "tasksJoined": shutdown.joined,
            "tasksCancelled": shutdown.cancelled,
            "tasksPanicked": shutdown.panicked,
            "tasksForced": shutdown.forced,
            "tasksPending": tasks.len(),
        }),
    );
}

async fn run_resident_dns_udp_bind_listener_async(
    socket: TokioUdpSocket,
    configured: String,
    local_addr: SocketAddr,
    active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    resources: ResidentDnsResourceProfile,
    executor_worker_threads: usize,
) {
    let dispatcher_shards = executor_worker_threads
        .max(1)
        .min(resources.bind_udp_inflight());
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_started",
            "configured": configured,
            "local_addr": local_addr.to_string(),
            "network": "udp",
            "handler": "resident-dns-udp",
            "max_inflight": resources.bind_udp_inflight(),
            "dispatcher_shards": dispatcher_shards,
            "resources": resources.json(),
        }),
    );
    let socket = Arc::new(socket);
    let semaphore = Arc::new(Semaphore::new(resources.bind_udp_inflight()));
    let mut dispatcher = ResidentDnsUdpBindDispatcher::start(
        Arc::clone(&socket),
        local_addr,
        event_file.clone(),
        Arc::clone(&event_lock),
        dispatcher_shards,
        resources.bind_udp_inflight(),
    );
    let mut buf = vec![0_u8; DNS_BIND_READ_LIMIT];
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (read, peer) = match received {
                    Ok(received) => received,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        if !stop.load(Ordering::Relaxed) {
                            append_event(
                                &event_file,
                                &event_lock,
                                json!({
                                    "event": "dns_bind_receive_failed",
                                    "local_addr": local_addr.to_string(),
                                    "network": "udp",
                                    "error": err.to_string(),
                                }),
                            );
                        }
                        continue;
                    }
                };
                let request = buf[..read].to_vec();
                let generation = active_generation.load();
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        let metrics = Arc::clone(&generation.metrics);
                        drop(generation);
                        metrics.add_upload(request.len());
                        let _ = send_resident_dns_udp_bind_failure_response(
                            &socket,
                            peer,
                            &request,
                            metrics.as_ref(),
                        ).await;
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({
                                "event": "dns_bind_overloaded",
                                "local_addr": local_addr.to_string(),
                                "peer": peer.to_string(),
                                "network": "udp",
                                "max_inflight": resources.bind_udp_inflight(),
                            }),
                        );
                        continue;
                    }
                    Err(tokio::sync::TryAcquireError::Closed) => break,
                };
                let dns = Arc::clone(&generation.dns);
                let metrics = Arc::clone(&generation.metrics);
                let flow_stop = generation.drain_control.flow_stop_handle();
                drop(generation);
                let job = ResidentDnsUdpBindJob {
                    peer,
                    dns,
                    metrics,
                    request,
                    flow_stop,
                    permit,
                };
                if let Err(job) = dispatcher.try_dispatch(job) {
                    job.metrics.add_upload(job.request.len());
                    let _ = send_resident_dns_udp_bind_failure_response(
                        &socket,
                        job.peer,
                        &job.request,
                        job.metrics.as_ref(),
                    ).await;
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_dispatch_unavailable",
                            "local_addr": local_addr.to_string(),
                            "peer": job.peer.to_string(),
                            "network": "udp",
                            "dispatcher_shards": dispatcher.shard_count(),
                        }),
                    );
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {}
        }
    }
    let shutdown = dispatcher
        .shutdown(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
        .await;
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_stopped",
            "local_addr": local_addr.to_string(),
            "network": "udp",
            "dispatcherShards": dispatcher_shards,
            "tasksJoined": shutdown.joined,
            "tasksCancelled": shutdown.cancelled,
            "tasksPanicked": shutdown.panicked,
            "tasksForced": shutdown.forced,
        }),
    );
}

async fn handle_resident_dns_udp_bind_packet_async(
    socket: Arc<TokioUdpSocket>,
    local_addr: SocketAddr,
    peer: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    metrics: Arc<ResidentDataplaneMetrics>,
    request: Vec<u8>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _udp_guard = ResidentUdpActivityGuard::new(Arc::clone(&metrics));
    metrics.add_upload(request.len());
    let result = handle_resident_dns_local_trace_async(&dns, local_addr, &request)
        .await
        .and_then(|mut result| {
            result.response = fit_dns_response_to_udp_request(&request, result.response)?;
            Ok(result)
        });
    match result {
        Ok(result) => {
            let response = result.response;
            let response_len = response.len();
            match socket.send_to(&response, peer).await {
                Ok(sent) => {
                    metrics.add_download(sent);
                    append_event_with_metadata(
                        &event_file,
                        &event_lock,
                        ResidentEventMetadata::new(ResidentEventKind::DnsPathChosen),
                        || {
                            dns_path_chosen_event(DnsPathChosenEventInput {
                                local_addr,
                                peer,
                                network: "udp",
                                handler: "resident-dns-udp",
                                request_bytes: request.len(),
                                response_bytes: response_len,
                                sent_bytes: Some(sent),
                                send_error: None,
                                trace: &result.trace,
                            })
                        },
                    );
                    append_event_with_metadata(
                        &event_file,
                        &event_lock,
                        ResidentEventMetadata::new(ResidentEventKind::DnsBindQueryFinished),
                        || {
                            json!({
                                "event": "dns_bind_query_finished",
                                "local_addr": local_addr.to_string(),
                                "peer": peer.to_string(),
                                "network": "udp",
                                "request_bytes": request.len(),
                                "response_bytes": response_len,
                                "sent_bytes": sent,
                                "handler": "resident-dns-udp",
                            })
                        },
                    );
                }
                Err(err) => {
                    let err = err.to_string();
                    append_event_with_metadata(
                        &event_file,
                        &event_lock,
                        ResidentEventMetadata::new(ResidentEventKind::DnsPathChosen),
                        || {
                            dns_path_chosen_event(DnsPathChosenEventInput {
                                local_addr,
                                peer,
                                network: "udp",
                                handler: "resident-dns-udp",
                                request_bytes: request.len(),
                                response_bytes: response_len,
                                sent_bytes: None,
                                send_error: Some(&err),
                                trace: &result.trace,
                            })
                        },
                    );
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_response_send_failed",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "udp",
                            "request_bytes": request.len(),
                            "response_bytes": response_len,
                            "error": err,
                        }),
                    );
                }
            }
        }
        Err(err) => {
            let _ = send_resident_dns_udp_bind_failure_response(
                &socket,
                peer,
                &request,
                metrics.as_ref(),
            )
            .await;
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_query_failed",
                    "local_addr": local_addr.to_string(),
                    "peer": peer.to_string(),
                    "network": "udp",
                    "request_bytes": request.len(),
                    "error": err,
                }),
            );
        }
    }
}

async fn send_resident_dns_udp_bind_failure_response(
    socket: &TokioUdpSocket,
    peer: SocketAddr,
    request: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let Some(response) = dns_bind_failure_response(request) else {
        return Ok(());
    };
    let sent = socket
        .send_to(&response, peer)
        .await
        .map_err(|err| format!("send DNS bind UDP failure response: {err}"))?;
    metrics.add_download(sent);
    Ok(())
}

async fn run_resident_dns_tcp_bind_listener_async(
    listener: TokioTcpListener,
    configured: String,
    local_addr: SocketAddr,
    active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    resources: ResidentDnsResourceProfile,
) {
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_started",
            "configured": configured,
            "local_addr": local_addr.to_string(),
            "network": "tcp",
            "handler": "resident-dns-tcp",
            "max_inflight": resources.bind_tcp_connections(),
            "max_query_inflight": resources.bind_tcp_queries(),
            "max_query_inflight_per_connection": resources.bind_tcp_queries_per_connection(),
            "resources": resources.json(),
        }),
    );
    let semaphore = Arc::new(Semaphore::new(resources.bind_tcp_connections()));
    let query_semaphore = Arc::new(Semaphore::new(resources.bind_tcp_queries()));
    let mut tasks = tokio::task::JoinSet::new();
    let mut admission_wait_active = false;
    while !stop.load(Ordering::Relaxed) {
        let admission = accept_resident_dns_tcp_bind_connection_async(
            &listener,
            &semaphore,
            &mut tasks,
            &stop,
            || {
                if admission_wait_active {
                    return;
                }
                admission_wait_active = true;
                append_event(
                    &event_file,
                    &event_lock,
                    json!({
                        "event": "dns_bind_admission_wait",
                        "local_addr": local_addr.to_string(),
                        "network": "tcp",
                        "mode": "kernel-listen-backlog",
                        "max_inflight": resources.bind_tcp_connections(),
                    }),
                );
            },
        )
        .await;
        let ResidentDnsTcpBindAdmission::Accepted {
            stream,
            peer,
            permit,
            waited,
        } = (match admission {
            Ok(admission) => admission,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                if !stop.load(Ordering::Relaxed) {
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_accept_failed",
                            "local_addr": local_addr.to_string(),
                            "network": "tcp",
                            "error": err.to_string(),
                        }),
                    );
                }
                continue;
            }
        })
        else {
            break;
        };
        if !waited {
            admission_wait_active = false;
        }
        let generation = active_generation.load();
        let dns = Arc::clone(&generation.dns);
        let metrics = Arc::clone(&generation.metrics);
        let flow_stop = generation.drain_control.flow_stop_handle();
        drop(generation);
        let task_event_file = event_file.clone();
        let task_event_lock = Arc::clone(&event_lock);
        let query_semaphore = Arc::clone(&query_semaphore);
        tasks.spawn(async move {
            let _ = run_until_resident_stop(
                &flow_stop,
                handle_resident_dns_tcp_bind_connection_async(
                    stream,
                    peer,
                    local_addr,
                    dns,
                    metrics,
                    Arc::clone(&flow_stop),
                    query_semaphore,
                    task_event_file,
                    task_event_lock,
                    resources,
                    permit,
                ),
            )
            .await;
        });
    }
    let shutdown =
        shutdown_resident_task_set(&mut tasks, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE).await;
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_stopped",
            "local_addr": local_addr.to_string(),
            "network": "tcp",
            "tasksJoined": shutdown.joined,
            "tasksCancelled": shutdown.cancelled,
            "tasksPanicked": shutdown.panicked,
            "tasksForced": shutdown.forced,
        }),
    );
}

async fn handle_resident_dns_tcp_bind_connection_async(
    stream: TokioTcpStream,
    peer: SocketAddr,
    local_addr: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    metrics: Arc<ResidentDataplaneMetrics>,
    stop: SharedResidentStopSignal,
    query_semaphore: Arc<Semaphore>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    resources: ResidentDnsResourceProfile,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
    let (mut reader, writer) = stream.into_split();
    let (response_tx, response_rx) =
        tokio::sync::mpsc::channel(resources.bind_tcp_queries_per_connection());
    let mut writer_task = tokio::spawn(run_resident_dns_tcp_bind_writer_async(
        writer,
        response_rx,
        peer,
        local_addr,
        Arc::clone(&metrics),
        event_file.clone(),
        Arc::clone(&event_lock),
    ));
    let mut tasks = tokio::task::JoinSet::new();
    let mut accepting = true;
    let mut abort_pending = false;
    let mut writer_finished = false;
    let mut stop_listener = stop.listener();
    let outstanding_ids = Arc::new(Mutex::new(BTreeSet::new()));
    let mut frame_reader = DnsTcpFrameReader::default();

    loop {
        if !accepting && tasks.is_empty() {
            break;
        }
        tokio::select! {
            _ = stop_listener.cancelled() => {
                abort_pending = true;
                break;
            }
            writer_result = &mut writer_task => {
                writer_finished = true;
                abort_pending = true;
                if let Ok(Err(error)) = writer_result {
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_response_send_failed",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "tcp",
                            "error": error,
                        }),
                    );
                }
                break;
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            received = read_dns_tcp_payload_bind_timeout_async(&mut frame_reader, &mut reader),
                if accepting && tasks.len() < resources.bind_tcp_queries_per_connection() =>
            {
                let request = match received {
                    Ok(Some(request)) => request,
                    Ok(None) => {
                        accepting = false;
                        continue;
                    }
                    Err(error) => {
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({
                                "event": "dns_bind_receive_failed",
                                "local_addr": local_addr.to_string(),
                                "peer": peer.to_string(),
                                "network": "tcp",
                                "error": error,
                            }),
                        );
                        abort_pending = true;
                        break;
                    }
                };
                metrics.add_upload(request.len());
                let request_id_guard = match ResidentDnsTcpRequestIdGuard::claim(
                    &request,
                    Arc::clone(&outstanding_ids),
                ) {
                    Ok(guard) => guard,
                    Err(error) => {
                        let response_tx = response_tx.clone();
                        tasks.spawn(async move {
                            let _ = response_tx
                                .send(ResidentDnsTcpBindResponse {
                                    request,
                                    result: Err(error),
                                    _request_id_guard: None,
                                })
                                .await;
                        });
                        continue;
                    }
                };
                let permit = {
                    let mut admission_stop = stop.listener();
                    tokio::select! {
                        permit = Arc::clone(&query_semaphore).acquire_owned() => match permit {
                            Ok(permit) => permit,
                            Err(_) => {
                                abort_pending = true;
                                break;
                            }
                        },
                        _ = admission_stop.cancelled() => {
                            abort_pending = true;
                            break;
                        }
                    }
                };
                let dns = Arc::clone(&dns);
                let response_tx = response_tx.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result =
                        handle_resident_dns_local_trace_async(&dns, local_addr, &request).await;
                    let _ = response_tx
                        .send(ResidentDnsTcpBindResponse {
                            request,
                            result,
                            _request_id_guard: request_id_guard,
                        })
                        .await;
                });
            }
        }
    }

    if abort_pending {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    drop(response_tx);
    if !writer_finished {
        let _ = time::timeout(DNS_BIND_TCP_IO_TIMEOUT, &mut writer_task).await;
        if !writer_task.is_finished() {
            writer_task.abort();
            let _ = writer_task.await;
        }
    }
}

struct ResidentDnsTcpBindResponse {
    request: Vec<u8>,
    result: Result<ResidentDnsQueryResult, String>,
    _request_id_guard: Option<ResidentDnsTcpRequestIdGuard>,
}

struct ResidentDnsTcpRequestIdGuard {
    id: u16,
    outstanding_ids: Arc<Mutex<BTreeSet<u16>>>,
}

impl ResidentDnsTcpRequestIdGuard {
    fn claim(
        request: &[u8],
        outstanding_ids: Arc<Mutex<BTreeSet<u16>>>,
    ) -> Result<Option<Self>, String> {
        let Some(id) = request
            .get(0..2)
            .map(|id| u16::from_be_bytes([id[0], id[1]]))
        else {
            return Ok(None);
        };
        let mut active = outstanding_ids
            .lock()
            .map_err(|_| "resident DNS TCP outstanding request ID lock poisoned".to_owned())?;
        if !active.insert(id) {
            return Err(format!(
                "resident DNS TCP client reused outstanding request ID {id}"
            ));
        }
        drop(active);
        Ok(Some(Self {
            id,
            outstanding_ids,
        }))
    }
}

impl Drop for ResidentDnsTcpRequestIdGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.outstanding_ids.lock() {
            active.remove(&self.id);
        }
    }
}

async fn run_resident_dns_tcp_bind_writer_async(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut responses: tokio::sync::mpsc::Receiver<ResidentDnsTcpBindResponse>,
    peer: SocketAddr,
    local_addr: SocketAddr,
    metrics: Arc<ResidentDataplaneMetrics>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
) -> Result<(), String> {
    while let Some(response) = responses.recv().await {
        match response.result {
            Ok(result) => {
                let response_len = result.response.len();
                if let Err(error) =
                    write_dns_tcp_payload_bind_timeout_async(&mut writer, &result.response).await
                {
                    append_event_with_metadata(
                        &event_file,
                        &event_lock,
                        ResidentEventMetadata::new(ResidentEventKind::DnsPathChosen),
                        || {
                            dns_path_chosen_event(DnsPathChosenEventInput {
                                local_addr,
                                peer,
                                network: "tcp",
                                handler: "resident-dns-tcp",
                                request_bytes: response.request.len(),
                                response_bytes: response_len,
                                sent_bytes: None,
                                send_error: Some(&error),
                                trace: &result.trace,
                            })
                        },
                    );
                    return Err(error);
                }
                metrics.add_download(response_len);
                append_event_with_metadata(
                    &event_file,
                    &event_lock,
                    ResidentEventMetadata::new(ResidentEventKind::DnsPathChosen),
                    || {
                        dns_path_chosen_event(DnsPathChosenEventInput {
                            local_addr,
                            peer,
                            network: "tcp",
                            handler: "resident-dns-tcp",
                            request_bytes: response.request.len(),
                            response_bytes: response_len,
                            sent_bytes: Some(response_len + 2),
                            send_error: None,
                            trace: &result.trace,
                        })
                    },
                );
                append_event_with_metadata(
                    &event_file,
                    &event_lock,
                    ResidentEventMetadata::new(ResidentEventKind::DnsBindQueryFinished),
                    || {
                        json!({
                            "event": "dns_bind_query_finished",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "tcp",
                            "request_bytes": response.request.len(),
                            "response_bytes": response_len,
                            "sent_bytes": response_len + 2,
                            "handler": "resident-dns-tcp",
                        })
                    },
                );
            }
            Err(error) => {
                write_resident_dns_tcp_bind_failure_response(
                    &mut writer,
                    &response.request,
                    metrics.as_ref(),
                )
                .await?;
                append_event(
                    &event_file,
                    &event_lock,
                    json!({
                        "event": "dns_bind_query_failed",
                        "local_addr": local_addr.to_string(),
                        "peer": peer.to_string(),
                        "network": "tcp",
                        "request_bytes": response.request.len(),
                        "error": error,
                    }),
                );
            }
        }
    }
    Ok(())
}

async fn write_resident_dns_tcp_bind_failure_response(
    stream: &mut (impl AsyncWrite + Unpin),
    request: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let Some(response) = dns_bind_failure_response(request) else {
        return Ok(());
    };
    write_dns_tcp_payload_bind_timeout_async(stream, &response).await?;
    metrics.add_download(response.len());
    Ok(())
}

async fn read_dns_tcp_payload_bind_timeout_async(
    frame_reader: &mut DnsTcpFrameReader,
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Option<Vec<u8>>, String> {
    read_dns_tcp_payload_with_timeout_async(frame_reader, stream, DNS_BIND_TCP_IO_TIMEOUT).await
}

async fn read_dns_tcp_payload_with_timeout_async<S>(
    frame_reader: &mut DnsTcpFrameReader,
    stream: &mut S,
    timeout: std::time::Duration,
) -> Result<Option<Vec<u8>>, String>
where
    S: AsyncRead + Unpin,
{
    time::timeout(timeout, frame_reader.read_frame(stream))
        .await
        .map_err(|_| "DNS TCP bind read timeout".to_owned())?
}

async fn write_dns_tcp_payload_bind_timeout_async(
    stream: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
) -> Result<(), String> {
    write_dns_tcp_payload_with_timeout_async(stream, payload, DNS_BIND_TCP_IO_TIMEOUT).await
}

async fn write_dns_tcp_payload_with_timeout_async<S>(
    stream: &mut S,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    time::timeout(timeout, write_dns_tcp_payload_async(stream, payload))
        .await
        .map_err(|_| "DNS TCP bind write timeout".to_owned())?
}

fn dns_bind_failure_response(request: &[u8]) -> Option<Vec<u8>> {
    build_dns_server_failure_response(request).ok()
}

struct DnsPathChosenEventInput<'a> {
    local_addr: SocketAddr,
    peer: SocketAddr,
    network: &'a str,
    handler: &'a str,
    request_bytes: usize,
    response_bytes: usize,
    sent_bytes: Option<usize>,
    send_error: Option<&'a str>,
    trace: &'a ResidentDnsTraceSummary,
}

fn dns_path_chosen_event(input: DnsPathChosenEventInput<'_>) -> Value {
    let mut event = json!({
        "event": "dns_path_chosen",
        "local_addr": input.local_addr.to_string(),
        "peer": input.peer.to_string(),
        "network": input.network,
        "handler": input.handler,
        "request_bytes": input.request_bytes,
        "response_bytes": input.response_bytes,
        "sent_bytes": input.sent_bytes,
        "qname": &input.trace.qname,
        "qtype": input.trace.qtype,
        "qclass": input.trace.qclass,
        "cache": &input.trace.cache,
        "routing": &input.trace.request_routing,
        "request_routing": &input.trace.request_routing,
        "response_routing": &input.trace.response_routing,
        "upstream": &input.trace.upstream,
        "upstream_scheme": input.trace.upstream_scheme,
        "upstream_chain": &input.trace.upstream_chain,
        "reroutes": input.trace.reroutes,
        "fallback": input.trace.fallback,
        "rcode": input.trace.rcode,
        "reason": &input.trace.reason,
        "total_ms": input.trace.total_ms,
        "cache_ms": input.trace.cache_ms,
        "routing_ms": input.trace.routing_ms,
        "upstream_ms": input.trace.upstream_ms,
        "transport_attempts": dns_transport_attempts_value(&input.trace.transport_attempts),
    });
    if let Some(send_error) = input.send_error
        && let Some(map) = event.as_object_mut()
    {
        map.insert(
            "send_error".to_owned(),
            Value::String(send_error.to_owned()),
        );
    }
    event
}

fn dns_transport_attempts_value(attempts: &[ResidentDnsTransportTrace]) -> Value {
    Value::Array(
        attempts
            .iter()
            .map(|attempt| {
                json!({
                    "upstream": &attempt.upstream,
                    "scheme": attempt.scheme,
                    "target": &attempt.target,
                    "target_family": attempt.target_family,
                    "l4proto": attempt.l4proto,
                    "route": attempt.route,
                    "elapsed_ms": attempt.elapsed_ms,
                    "outcome": attempt.outcome,
                    "error": &attempt.error,
                })
            })
            .collect(),
    )
}

fn parse_resident_dns_bind_endpoint(bind: &str) -> Result<Option<ResidentDnsBindEndpoint>, String> {
    let bind = bind.trim();
    if bind.is_empty() {
        return Ok(None);
    }
    let (tcp, udp, addr) = if let Some((scheme, addr)) = bind.split_once("://") {
        let mut tcp = false;
        let mut udp = false;
        for item in scheme.split('+') {
            match item {
                "tcp" => tcp = true,
                "udp" => udp = true,
                other => {
                    return Err(format!(
                        "resident DNS bind listener has unsupported protocol {other:?} in dns.bind {bind:?}"
                    ));
                }
            }
        }
        if !tcp && !udp {
            return Err(format!(
                "resident DNS bind listener has no protocol in dns.bind {bind:?}"
            ));
        }
        (tcp, udp, addr)
    } else {
        (false, true, bind)
    };
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|err| format!("parse dns.bind {bind:?} as socket addr: {err}"))?;
    Ok(Some(ResidentDnsBindEndpoint { udp, tcp, addr }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::ResidentGeodataStore;
    use crate::dns::build_resident_dns_plan;
    use dae_dns::{
        DNS_DEFAULT_PORT, DNS_FLAG_RESPONSE, DNS_HEADER_LEN, DNS_RCODE_MASK, DNS_RCODE_SERVFAIL,
        DnsPacketView,
    };

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    fn dns_bind_test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT)
    }

    fn dns_bind_endpoint(udp: bool, tcp: bool) -> ResidentDnsBindEndpoint {
        ResidentDnsBindEndpoint {
            udp,
            tcp,
            addr: dns_bind_test_addr(),
        }
    }

    fn dns_bind_value(scheme: Option<&str>) -> String {
        match scheme {
            Some(scheme) => format!("{scheme}://{}", dns_bind_test_addr()),
            None => dns_bind_test_addr().to_string(),
        }
    }

    #[test]
    fn resident_dns_bind_endpoint_accepts_empty_udp_and_tcp_forms() {
        let udp = dns_bind_endpoint(true, false);
        let tcp = dns_bind_endpoint(false, true);
        let both = dns_bind_endpoint(true, true);

        assert_eq!(parse_resident_dns_bind_endpoint("").unwrap(), None);
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(None)).unwrap(),
            Some(udp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("udp"))).unwrap(),
            Some(udp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("tcp"))).unwrap(),
            Some(tcp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("tcp+udp"))).unwrap(),
            Some(both)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("udp+tcp"))).unwrap(),
            Some(both)
        );
    }

    #[test]
    fn resident_dns_bind_endpoint_rejects_invalid_values() {
        assert!(parse_resident_dns_bind_endpoint(&Ipv4Addr::LOCALHOST.to_string()).is_err());
        assert!(parse_resident_dns_bind_endpoint(&dns_bind_value(Some("http"))).is_err());
    }

    #[test]
    fn dns_path_chosen_event_exposes_trace_summary_fields() {
        let local_addr = dns_bind_test_addr();
        let peer = SocketAddr::new(
            local_addr.ip(),
            local_addr
                .port()
                .saturating_add(u16::from(QUERY[0] != QUERY[1])),
        );
        let handler = "resident-dns-udp";
        let network = handler.strip_prefix("resident-dns-").unwrap();
        let request = DnsPacketView::parse(QUERY).unwrap();
        let question = request.questions().next().unwrap();
        let qname = question.qname_to_canonical_string().unwrap();
        let qtype = question.qtype();
        let qclass = question.qclass();
        let upstream_tag = qname.trim_end_matches('.').to_owned();
        let upstream = Some(upstream_tag.clone());
        let upstream_scheme = Some(network);
        let upstream_chain = vec![upstream_tag.clone()];
        let reroutes = 0_usize;
        let fallback = false;
        let rcode = Some(u16::from(QUERY[3] & DNS_RCODE_MASK as u8));
        let request_bytes = QUERY.len();
        let response_bytes = request_bytes.saturating_add(DNS_HEADER_LEN);
        let sent_bytes = Some(response_bytes);
        let transport_target = local_addr.to_string();
        let mut trace = ResidentDnsTraceSummary::new_for_test(qname.clone(), qtype, qclass);
        trace.upstream = upstream.clone();
        trace.upstream_scheme = upstream_scheme;
        trace.upstream_chain = upstream_chain.clone();
        trace.reroutes = reroutes;
        trace.fallback = fallback;
        trace.rcode = rcode;
        let reason = format!("{}:{}", trace.request_routing, trace.response_routing);
        trace.reason = reason.clone();
        trace.cache_ms = u64::try_from(request.question_count()).unwrap_or_default();
        trace.routing_ms = u64::try_from(request_bytes).unwrap_or_default();
        trace.upstream_ms = u64::try_from(response_bytes).unwrap_or_default();
        trace.total_ms = trace
            .cache_ms
            .saturating_add(trace.routing_ms)
            .saturating_add(trace.upstream_ms);
        trace.transport_attempts = vec![ResidentDnsTransportTrace {
            upstream: upstream_tag,
            scheme: network,
            target: transport_target.clone(),
            target_family: if local_addr.is_ipv6() {
                DNS_TRANSPORT_TARGET_FAMILY_IPV6
            } else {
                DNS_TRANSPORT_TARGET_FAMILY_IPV4
            },
            l4proto: network,
            route: DNS_TRANSPORT_ROUTE_DIRECT,
            elapsed_ms: trace.upstream_ms,
            outcome: DNS_TRANSPORT_OUTCOME_SUCCESS,
            error: None,
        }];
        let event = dns_path_chosen_event(DnsPathChosenEventInput {
            local_addr,
            peer,
            network,
            handler,
            request_bytes,
            response_bytes,
            sent_bytes,
            send_error: None,
            trace: &trace,
        });

        assert_eq!(event["event"], "dns_path_chosen");
        assert_eq!(event["network"], network);
        assert_eq!(event["handler"], handler);
        assert_eq!(event["qname"], qname);
        assert_eq!(event["qtype"], qtype);
        assert_eq!(event["qclass"], qclass);
        assert_eq!(event["cache"], trace.cache);
        assert_eq!(event["routing"], trace.request_routing);
        assert_eq!(event["request_routing"], trace.request_routing);
        assert_eq!(event["response_routing"], trace.response_routing);
        assert_eq!(event["upstream"], json!(upstream));
        assert_eq!(event["upstream_scheme"], json!(upstream_scheme));
        assert_eq!(event["upstream_chain"][0], upstream_chain[0]);
        assert_eq!(event["reroutes"], reroutes);
        assert_eq!(event["fallback"], fallback);
        assert_eq!(event["rcode"], json!(rcode));
        assert_eq!(event["sent_bytes"], json!(sent_bytes));
        assert_eq!(event["reason"], reason);
        assert_eq!(event["total_ms"], trace.total_ms);
        assert_eq!(event["cache_ms"], trace.cache_ms);
        assert_eq!(event["routing_ms"], trace.routing_ms);
        assert_eq!(event["upstream_ms"], trace.upstream_ms);
        assert_eq!(
            event["transport_attempts"][0]["route"],
            DNS_TRANSPORT_ROUTE_DIRECT
        );
        assert_eq!(event["transport_attempts"][0]["target"], transport_target);
        assert_eq!(
            event["transport_attempts"][0]["target_family"],
            if local_addr.is_ipv6() {
                DNS_TRANSPORT_TARGET_FAMILY_IPV6
            } else {
                DNS_TRANSPORT_TARGET_FAMILY_IPV4
            }
        );
    }

    #[test]
    fn dns_bind_failure_response_returns_servfail_for_valid_query() {
        let response = dns_bind_failure_response(QUERY).unwrap();
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(&response[0..2], &QUERY[0..2]);
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_SERVFAIL);
        assert_eq!(&response[DNS_HEADER_LEN..], &QUERY[DNS_HEADER_LEN..]);
    }

    #[test]
    fn dns_bind_failure_response_ignores_non_request_payload() {
        let mut response = QUERY.to_vec();
        response[2] |= (DNS_FLAG_RESPONSE >> 8) as u8;

        assert!(dns_bind_failure_response(&response).is_none());
        assert!(dns_bind_failure_response(&[]).is_none());
    }

    #[test]
    fn dns_bind_tcp_rejects_a_duplicate_outstanding_request_id_until_release() {
        let outstanding_ids = Arc::new(Mutex::new(BTreeSet::new()));
        let query = dns_query_for_test(0x5151, "duplicate.example");
        let first = ResidentDnsTcpRequestIdGuard::claim(&query, Arc::clone(&outstanding_ids))
            .unwrap()
            .unwrap();
        let error = ResidentDnsTcpRequestIdGuard::claim(&query, Arc::clone(&outstanding_ids))
            .err()
            .expect("duplicate outstanding DNS TCP request ID was admitted");
        assert!(error.contains(&format!("reused outstanding request ID {}", 0x5151_u16)));

        drop(first);
        assert!(
            ResidentDnsTcpRequestIdGuard::claim(&query, outstanding_ids)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn dns_bind_tcp_read_timeout_closes_slow_client() {
        let (_client, mut server) = tokio::io::duplex(64);

        let mut frame_reader = DnsTcpFrameReader::default();
        let err = read_dns_tcp_payload_with_timeout_async(
            &mut frame_reader,
            &mut server,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(err.contains("read timeout"));
    }

    #[tokio::test]
    async fn dns_bind_tcp_write_timeout_closes_slow_client() {
        let (mut client, _server) = tokio::io::duplex(1);

        let err =
            write_dns_tcp_payload_with_timeout_async(&mut client, QUERY, Duration::from_millis(1))
                .await
                .unwrap_err();

        assert!(err.contains("write timeout"));
    }

    #[tokio::test]
    async fn dns_bind_tcp_pipeline_does_not_serialize_a_later_query() {
        let upstream_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut frame_reader = DnsTcpFrameReader::default();
            let first = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
            let second = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
            let fast = if dns_packet_id_for_test(&first) == 0x2222 {
                first
            } else {
                second
            };
            let response = dns_a_response_for_test(&fast, [192, 0, 2, 80]);
            write_dns_tcp_payload_async(&mut stream, &response)
                .await
                .unwrap();
            time::sleep(Duration::from_secs(2)).await;
        });
        let input = format!(
            r#"
            global {{}}
            routing {{}}
            dns {{
              upstream {{ primary: 'tcp://{upstream_addr}' }}
              routing {{ request {{ fallback: primary }} }}
            }}
            "#
        );
        let sections = dae_config::parser::parse_config(&input).unwrap();
        let config = dae_config::schema::build_config(&sections).unwrap();
        let geodata = ResidentGeodataStore::new(Vec::<PathBuf>::new());
        let dns = Arc::new(build_resident_dns_plan(&config, &geodata).unwrap());
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let local_addr = listener.local_addr().unwrap();
        let mut client = TokioTcpStream::connect(local_addr).await.unwrap();
        let (server_stream, peer) = listener.accept().await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let event_file = std::env::temp_dir().join(format!(
            "daed-dns-bind-pipeline-{}.jsonl",
            std::process::id()
        ));
        let handler_stop = Arc::clone(&stop);
        let handler = tokio::spawn(handle_resident_dns_tcp_bind_connection_async(
            server_stream,
            peer,
            local_addr,
            dns,
            metrics,
            handler_stop,
            Arc::new(Semaphore::new(16)),
            event_file.clone(),
            Arc::new(Mutex::new(())),
            ResidentDnsResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory),
            permit,
        ));
        let slow = dns_query_for_test(0x1111, "slow.example");
        let fast = dns_query_for_test(0x2222, "fast.example");
        write_dns_tcp_payload_async(&mut client, &slow)
            .await
            .unwrap();
        write_dns_tcp_payload_async(&mut client, &fast)
            .await
            .unwrap();
        let response = time::timeout(
            Duration::from_secs(1),
            read_dns_tcp_payload_async(&mut client),
        )
        .await
        .expect("later DNS query was serialized behind a blackholed query")
        .unwrap()
        .unwrap();
        assert_eq!(dns_packet_id_for_test(&response), 0x2222);
        stop.store(true, Ordering::Relaxed);
        time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap();
        upstream_server.abort();
        let _ = std::fs::remove_file(event_file);
    }

    fn dns_packet_id_for_test(packet: &[u8]) -> u16 {
        u16::from_be_bytes([packet[0], packet[1]])
    }

    fn dns_query_for_test(id: u16, domain: &str) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0_u8; 6]);
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    fn dns_a_response_for_test(query: &[u8], address: [u8; 4]) -> Vec<u8> {
        let view = DnsPacketView::parse(query).unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&0x8180_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&query[12..view.answer_offset()]);
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }
}
