use std::collections::HashMap;

use tokio::sync::mpsc::error::TrySendError;

use super::monitor::{ConnectUdpH3MonitorResult, monitor_connect_udp_h3_stream};
use super::open::{ConnectUdpH3OpenResult, ConnectUdpH3SendStream, open_connect_udp_h3_session};
use super::*;

struct ConnectUdpH3SessionEntry {
    _send: ConnectUdpH3SendStream,
    responses: mpsc::Sender<Result<Bytes, String>>,
    cancel_monitor: Option<oneshot::Sender<()>>,
}

pub(super) struct ConnectUdpH3ActorContext {
    pub(super) endpoint: ObservedQuicEndpoint,
    pub(super) connection: quinn::Connection,
    pub(super) client: ::h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) driver_task: tokio::task::JoinHandle<()>,
    pub(super) proxy: Arc<ResidentProxyPlan>,
    pub(super) runtime: ResidentConnectUdpRuntimePlan,
    pub(super) max_datagram_size: usize,
    pub(super) receiver: mpsc::Receiver<ConnectUdpH3ActorCommand>,
    pub(super) admission: Arc<ConnectUdpH3ActorAdmission>,
}

pub(super) async fn run_connect_udp_h3_actor(context: ConnectUdpH3ActorContext) {
    let ConnectUdpH3ActorContext {
        endpoint,
        connection,
        client,
        mut driver_task,
        proxy,
        runtime,
        max_datagram_size,
        mut receiver,
        admission,
    } = context;
    let mut sessions = HashMap::<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>::new();
    let mut pending_open_count = 0_usize;
    let mut pending_opens = FuturesUnordered::<BoxFuture<'static, ConnectUdpH3OpenResult>>::new();
    let mut monitors = FuturesUnordered::<BoxFuture<'static, ConnectUdpH3MonitorResult>>::new();
    let mut stop_reason = "CONNECT-UDP H3 actor command channel closed".to_owned();

    loop {
        remove_abandoned_sessions(&mut sessions);
        if !admission.is_accepting() && sessions.is_empty() && pending_open_count == 0 {
            stop_reason = "CONNECT-UDP H3 actor retired after its final session".to_owned();
            break;
        }
        tokio::select! {
            command = receiver.recv() => {
                let Some(command) = command else {
                    break;
                };
                match command {
                    ConnectUdpH3ActorCommand::OpenSession { target, response } => {
                        if !admission.is_accepting() {
                            let _ = response.send(Err(
                                ConnectUdpH3OpenFailure::retryable_connection(
                                    "CONNECT-UDP H3 actor no longer accepts new sessions",
                                    ConnectUdpConnectionRetirementReason::Other,
                                ),
                            ));
                            continue;
                        }
                        if sessions.len().saturating_add(pending_open_count)
                            >= runtime.sessions_per_connection.max(1)
                        {
                            let _ = response.send(Err(
                                ConnectUdpH3OpenFailure::terminal(
                                    "CONNECT-UDP H3 connection session capacity is exhausted",
                                ),
                            ));
                            continue;
                        }
                        pending_open_count = pending_open_count.saturating_add(1);
                        pending_opens.push(
                            open_connect_udp_h3_session(
                                client.clone(),
                                Arc::clone(&proxy),
                                target,
                                runtime.h3_session_queue_depth,
                                response,
                            )
                            .boxed(),
                        );
                    }
                    ConnectUdpH3ActorCommand::SendDatagram {
                        quarter_stream_id,
                        payload,
                        response,
                    } => {
                        let result = send_connect_udp_h3_datagram(
                            &connection,
                            &sessions,
                            quarter_stream_id,
                            payload,
                            runtime,
                            max_datagram_size,
                            &admission,
                        );
                        let _ = response.send(result);
                    }
                    ConnectUdpH3ActorCommand::CloseSession { quarter_stream_id } => {
                        remove_session(&mut sessions, quarter_stream_id);
                    }
                    ConnectUdpH3ActorCommand::Shutdown => {
                        stop_reason = "CONNECT-UDP H3 actor generation shutdown".to_owned();
                        break;
                    }
                }
            }
            opened = pending_opens.next(), if !pending_opens.is_empty() => {
                let Some(opened) = opened else {
                    continue;
                };
                pending_open_count = pending_open_count.saturating_sub(1);
                admit_opened_session(&mut sessions, &mut monitors, &admission, opened);
            }
            monitored = monitors.next(), if !monitors.is_empty() => {
                if let Some(monitored) = monitored {
                    handle_stream_monitor_result(&mut sessions, &admission, monitored);
                }
            }
            datagram = connection.read_datagram() => {
                match datagram {
                    Ok(datagram) => {
                        if let Err(err) = dispatch_connect_udp_h3_datagram(
                            &mut sessions,
                            datagram,
                            runtime,
                            &admission,
                        ) {
                            stop_reason = err;
                            break;
                        }
                    }
                    Err(err) => {
                        stop_reason = format!("read CONNECT-UDP H3 datagram: {err}");
                        break;
                    }
                }
            }
            _ = &mut driver_task => {
                stop_reason = "CONNECT-UDP H3 connection driver stopped".to_owned();
                break;
            }
        }
    }

    fail_all_sessions(&mut sessions, &stop_reason);
    drop(pending_opens);
    drop(monitors);
    receiver.close();
    connection.close(0_u32.into(), stop_reason.as_bytes());
    driver_task.abort();
    endpoint.wait_idle().await;
}

fn send_connect_udp_h3_datagram(
    connection: &quinn::Connection,
    sessions: &HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
    quarter_stream_id: MasqueQuarterStreamId,
    payload: Bytes,
    runtime: ResidentConnectUdpRuntimePlan,
    max_datagram_size: usize,
    admission: &ConnectUdpH3ActorAdmission,
) -> Result<(), String> {
    if !sessions.contains_key(&quarter_stream_id) {
        return Err("CONNECT-UDP H3 session is no longer active".to_owned());
    }
    let encoded = encode_http_datagram(
        quarter_stream_id,
        &payload,
        runtime.capsule_limits.max_datagram_payload_bytes,
    )
    .map_err(|err| format!("encode CONNECT-UDP H3 HTTP Datagram: {err}"))?;
    if encoded.len() > max_datagram_size {
        admission.record_mtu_rejection();
        return Err(format!(
            "CONNECT-UDP H3 HTTP Datagram is {} bytes but peer negotiated a {} byte maximum",
            encoded.len(),
            max_datagram_size,
        ));
    }
    connection
        .send_datagram(Bytes::from(encoded))
        .map_err(|err| format!("send CONNECT-UDP H3 HTTP Datagram: {err}"))
}

fn dispatch_connect_udp_h3_datagram(
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
    datagram: Bytes,
    runtime: ResidentConnectUdpRuntimePlan,
    admission: &ConnectUdpH3ActorAdmission,
) -> Result<(), String> {
    let decoded = decode_http_datagram(datagram, runtime.capsule_limits.max_datagram_payload_bytes)
        .map_err(|err| format!("decode CONNECT-UDP H3 HTTP Datagram: {err}"))?;
    let Some(session) = sessions.get(&decoded.quarter_stream_id) else {
        return Ok(());
    };
    match session.responses.try_send(Ok(decoded.payload)) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            admission.record_queue_full();
            Ok(())
        }
        Err(TrySendError::Closed(_)) => {
            remove_session(sessions, decoded.quarter_stream_id);
            Ok(())
        }
    }
}

fn admit_opened_session(
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
    monitors: &mut FuturesUnordered<BoxFuture<'static, ConnectUdpH3MonitorResult>>,
    admission: &ConnectUdpH3ActorAdmission,
    opened: ConnectUdpH3OpenResult,
) {
    let stream = match opened.result {
        Ok(stream) => stream,
        Err(err) => {
            if let Some(reason) = err.retirement_reason() {
                admission.retire(reason);
            }
            let _ = opened.response.send(Err(err));
            return;
        }
    };
    let quarter_stream_id = stream.quarter_stream_id;
    if sessions.contains_key(&quarter_stream_id) {
        let _ = opened
            .response
            .send(Err(ConnectUdpH3OpenFailure::terminal(format!(
                "CONNECT-UDP H3 reused active Quarter Stream ID {}",
                quarter_stream_id.value(),
            ))));
        return;
    }
    let (cancel_monitor, cancelled) = oneshot::channel();
    monitors
        .push(monitor_connect_udp_h3_stream(quarter_stream_id, stream.receive, cancelled).boxed());
    sessions.insert(
        quarter_stream_id,
        ConnectUdpH3SessionEntry {
            _send: stream.send,
            responses: stream.response_sender,
            cancel_monitor: Some(cancel_monitor),
        },
    );
    let result = ConnectUdpH3OpenedSession {
        quarter_stream_id,
        responses: stream.response_receiver,
    };
    if opened.response.send(Ok(result)).is_err() {
        remove_session(sessions, quarter_stream_id);
    }
}

fn handle_stream_monitor_result(
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
    admission: &ConnectUdpH3ActorAdmission,
    monitored: ConnectUdpH3MonitorResult,
) {
    if monitored.reset {
        admission.record_reset();
    }
    if let Some(error) = monitored.error
        && let Some(session) = sessions.get(&monitored.quarter_stream_id)
    {
        let _ = session.responses.try_send(Err(error));
    }
    remove_session(sessions, monitored.quarter_stream_id);
}

fn remove_abandoned_sessions(
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
) {
    let abandoned = sessions
        .iter()
        .filter_map(|(id, session)| session.responses.is_closed().then_some(*id))
        .collect::<Vec<_>>();
    for id in abandoned {
        remove_session(sessions, id);
    }
}

fn remove_session(
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
    quarter_stream_id: MasqueQuarterStreamId,
) {
    if let Some(mut session) = sessions.remove(&quarter_stream_id)
        && let Some(cancel) = session.cancel_monitor.take()
    {
        let _ = cancel.send(());
    }
}

fn fail_all_sessions(
    sessions: &mut HashMap<MasqueQuarterStreamId, ConnectUdpH3SessionEntry>,
    reason: &str,
) {
    for session in sessions.values() {
        let _ = session.responses.try_send(Err(reason.to_owned()));
    }
    let ids = sessions.keys().copied().collect::<Vec<_>>();
    for id in ids {
        remove_session(sessions, id);
    }
}
