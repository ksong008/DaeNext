use super::super::*;
use super::ResidentDnsTransportError;
use super::route::{
    ResidentDnsUpstreamRoutedTarget, race_dns_upstream_targets_with_refresh,
    refresh_dns_upstream_targets, resolved_upstream_targets, select_dns_upstream_targets,
};
use super::udp_multiplex::ResidentDnsUdpMultiplexHandle;
use super::wire::{forward_dns_framed_stream_async, open_dns_tcp_stream_async};
#[cfg(test)]
use std::os::fd::AsRawFd;

#[cfg(test)]
const DNS_UDP_MAX_STALE_RESPONSES: usize = 8;

pub(super) async fn forward_dns_udp_upstream_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream, context.deadline())
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Udp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets_with_refresh(
        upstream,
        &resolved,
        "forward DNS UDP to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        context,
        || async {
            refresh_dns_upstream_targets(
                plan,
                upstream,
                &resolved,
                L4Proto::Udp,
                context.deadline(),
            )
            .await
        },
        |target| async move {
            forward_dns_udp_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

#[cfg(test)]
async fn forward_dns_udp_with_attempts_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
    attempts: usize,
    attempt_timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let attempts = attempts.max(1);
    let bind = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|err| format!("bind DNS UDP socket: {err}"))?;
    apply_udp_socket_buffer_tuning(
        socket.as_raw_fd(),
        ResidentDnsUdpRuntimeConfig::standalone().socket_buffer_bytes,
    );
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set DNS UDP SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set DNS UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt async DNS UDP socket: {err}"))?;
    let request = DnsPacketView::parse(payload).ok();
    let mut response = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
    for _ in 0..attempts {
        socket
            .send_to(payload, target)
            .await
            .map_err(|err| format!("send DNS UDP packet: {err}"))?;
        let deadline = time::Instant::now() + attempt_timeout;
        let mut stale_responses = 0_usize;
        loop {
            let now = time::Instant::now();
            if now >= deadline {
                break;
            }
            match time::timeout(deadline - now, socket.recv_from(&mut response)).await {
                Ok(Ok((read, peer))) => {
                    match validate_dns_udp_response(
                        target,
                        peer,
                        request.as_ref(),
                        &response[..read],
                    ) {
                        Ok(()) => {
                            response.truncate(read);
                            return Ok(response);
                        }
                        Err(err) => {
                            stale_responses += 1;
                            if stale_responses > DNS_UDP_MAX_STALE_RESPONSES {
                                return Err(format!(
                                    "too many stale DNS UDP responses from {target}: {err}"
                                ));
                            }
                        }
                    }
                }
                Ok(Err(err)) => return Err(format!("receive DNS UDP response: {err}")),
                Err(_) => break,
            }
        }
    }
    Err(format!(
        "receive DNS UDP response timeout after {attempts} attempts"
    ))
}

#[cfg(test)]
fn validate_dns_udp_response(
    target: SocketAddr,
    peer: SocketAddr,
    request: Option<&DnsPacketView<'_>>,
    response: &[u8],
) -> Result<(), String> {
    if peer != target {
        return Err(format!("unexpected DNS UDP peer {peer}, expected {target}"));
    }
    let Some(request) = request else {
        return Ok(());
    };
    let response = DnsPacketView::parse(response)
        .map_err(|err| format!("parse DNS UDP response for request validation: {err}"))?;
    validate_dns_packet_response_for_request_fast(request, Some(&response), true)
        .map_err(|err| format!("validate DNS UDP response for request: {err:?}"))
}

pub(super) async fn forward_dns_tcp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream, context.deadline())
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let (targets, failures) =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Tcp)
            .map_err(ResidentDnsTransportError::message)?;
    race_dns_upstream_targets_with_refresh(
        upstream,
        &resolved,
        "forward DNS TCP to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        context,
        || async {
            refresh_dns_upstream_targets(
                plan,
                upstream,
                &resolved,
                L4Proto::Tcp,
                context.deadline(),
            )
            .await
        },
        |target| async move {
            forward_dns_tcp_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

pub(super) async fn forward_dns_udp_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let remote = target.target;
    let route = dns_transport_route_name(&target.selection);
    let result = match &target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .udp_forwarder(upstream, remote, *mark, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder.exchange(payload, context).await.map_err(|err| {
                ResidentDnsTransportError::response_timeout(format!("{remote}: {err}"))
            })
        }
        ResidentDnsUpstreamSelection::Proxy { binding } => {
            let forwarder = forwarders
                .proxy_udp_forwarder(upstream, remote, binding.clone(), &target.selection)
                .map_err(|error| {
                    ResidentDnsTransportError::proxy(ProxyDnsRequestError::new(
                        ProxyDnsRequestStage::OwnerAcquire,
                        ProxyDnsRequestFailure::Protocol,
                        error,
                    ))
                })?;
            forwarder
                .exchange(payload, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote)))
        }
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target: remote,
        l4proto: L4Proto::Udp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

struct ResidentDnsUdpShardLease<'a> {
    shard: &'a ResidentDnsUdpForwarderShard,
}

impl<'a> ResidentDnsUdpShardLease<'a> {
    fn new(shard: &'a ResidentDnsUdpForwarderShard) -> Self {
        shard
            .inflight
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self { shard }
    }
}

impl Drop for ResidentDnsUdpShardLease<'_> {
    fn drop(&mut self) {
        let _ = self.shard.inflight.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |inflight| Some(inflight.saturating_sub(1)),
        );
    }
}

impl ResidentDnsUdpForwarder {
    pub(in crate::dns) async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, String> {
        let (shard_index, _shard_lease) = self.acquire_shard();
        let mut failures = Vec::new();
        for attempt in 0..self.runtime_config.attempts {
            context
                .ensure(ProxyDnsRequestStage::Pending)
                .map_err(|error| error.to_string())?;
            let handle = self.handle(shard_index).await?;
            if attempt > 0 {
                handle.record_retry();
            }
            match handle
                .exchange_once_until(payload, context.deadline())
                .await
            {
                Ok(response) => return Ok(response),
                Err(err) => {
                    failures.push(err);
                    if handle.is_closed() {
                        self.clear_closed_handle(shard_index, &handle).await;
                    }
                }
            }
        }
        Err(format!(
            "receive DNS UDP response timeout after {} attempts: {}",
            self.runtime_config.attempts,
            failures.join("; ")
        ))
    }

    fn acquire_shard(&self) -> (usize, ResidentDnsUdpShardLease<'_>) {
        self.refresh_closed_shards();
        let shard_count = self.shards.len().max(1);
        let start = self
            .next_shard
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % shard_count;
        loop {
            let mut least_loaded = None::<(usize, usize)>;
            let mut unopened = None;
            for offset in 0..shard_count {
                let index = (start + offset) % shard_count;
                let shard = &self.shards[index];
                if shard.opened.load(std::sync::atomic::Ordering::Acquire) {
                    let inflight = shard.inflight.load(std::sync::atomic::Ordering::Acquire);
                    if least_loaded.is_none_or(|(_, load)| inflight < load) {
                        least_loaded = Some((index, inflight));
                    }
                } else if unopened.is_none() {
                    unopened = Some(index);
                }
            }

            let index = match least_loaded {
                Some((index, 0)) => index,
                Some((index, _)) => match unopened {
                    Some(unopened_index) => {
                        let shard = &self.shards[unopened_index];
                        if shard
                            .opened
                            .compare_exchange(
                                false,
                                true,
                                std::sync::atomic::Ordering::AcqRel,
                                std::sync::atomic::Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            unopened_index
                        } else {
                            continue;
                        }
                    }
                    None => index,
                },
                None => {
                    let index = unopened.unwrap_or(0);
                    let shard = &self.shards[index];
                    if shard
                        .opened
                        .compare_exchange(
                            false,
                            true,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    index
                }
            };
            let shard = &self.shards[index];
            return (index, ResidentDnsUdpShardLease::new(shard));
        }
    }

    fn refresh_closed_shards(&self) {
        for shard in &self.shards {
            if !shard.opened.load(std::sync::atomic::Ordering::Acquire)
                || shard.inflight.load(std::sync::atomic::Ordering::Acquire) != 0
            {
                continue;
            }
            let Ok(handle) = shard.handle.try_lock() else {
                continue;
            };
            if handle
                .as_ref()
                .is_none_or(ResidentDnsUdpMultiplexHandle::is_closed)
            {
                shard
                    .opened
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
    }

    async fn handle(&self, shard_index: usize) -> Result<ResidentDnsUdpMultiplexHandle, String> {
        let shard = self
            .shards
            .get(shard_index)
            .ok_or_else(|| format!("DNS UDP forwarder shard {shard_index} is missing"))?;
        let mut handle = shard.handle.lock().await;
        let replacing_closed = handle
            .as_ref()
            .is_some_and(ResidentDnsUdpMultiplexHandle::is_closed);
        if handle
            .as_ref()
            .is_none_or(ResidentDnsUdpMultiplexHandle::is_closed)
        {
            let mut actor_config = self
                .runtime_config
                .actor_partition(shard_index, self.shards.len());
            actor_config.actor_idle_timeout =
                (shard_index > 0).then_some(self.runtime_config.shard_idle_timeout);
            let opened = match self
                .executor
                .open_handle_with_config(self.target, self.mark, actor_config)
                .await
            {
                Ok(opened) => opened,
                Err(error) => {
                    shard
                        .opened
                        .store(false, std::sync::atomic::Ordering::Release);
                    return Err(error);
                }
            };
            shard
                .opened
                .store(true, std::sync::atomic::Ordering::Release);
            *handle = Some(opened);
            if replacing_closed && let Some(opened) = handle.as_ref() {
                opened.record_recreated();
            }
        }
        handle
            .as_ref()
            .cloned()
            .ok_or_else(|| "DNS UDP multiplex handle was not initialized".to_owned())
    }

    async fn clear_closed_handle(
        &self,
        shard_index: usize,
        failed: &ResidentDnsUdpMultiplexHandle,
    ) {
        if !failed.is_closed() {
            return;
        }
        let Some(shard) = self.shards.get(shard_index) else {
            return;
        };
        let mut handle = shard.handle.lock().await;
        if handle
            .as_ref()
            .is_some_and(ResidentDnsUdpMultiplexHandle::is_closed)
        {
            *handle = None;
            shard
                .opened
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
}

pub(super) async fn forward_dns_tcp_to_routed_target_async(
    upstream: &ResidentDnsUpstream,
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let started_at = std::time::Instant::now();
    let remote = target.target;
    let route = dns_transport_route_name(&target.selection);
    let result = match &target.selection {
        ResidentDnsUpstreamSelection::Direct { mark } => {
            let forwarder = forwarders
                .tcp_forwarder(upstream, remote, *mark, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder
                .exchange(payload, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote)))
        }
        ResidentDnsUpstreamSelection::Proxy { .. } => {
            let forwarder = forwarders
                .tcp_forwarder(upstream, remote, 0, &target.selection)
                .map_err(ResidentDnsTransportError::message)?;
            forwarder
                .exchange(payload, context)
                .await
                .map_err(|error| ResidentDnsTransportError::proxy(error.with_context(remote)))
        }
    };
    record_dns_transport_trace(ResidentDnsTransportTraceInput {
        upstream: upstream.tag.clone(),
        scheme: upstream.scheme.as_str(),
        target: remote,
        l4proto: L4Proto::Tcp,
        route,
        started_at,
        error: result.as_ref().err().map(ToString::to_string),
    });
    result
}

impl ResidentDnsTcpForwarder {
    async fn exchange(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ProxyDnsRequestError> {
        let mut first_error = None;
        for _ in 0..2 {
            context.ensure(ProxyDnsRequestStage::Retry)?;
            let connection = self.connection(context).await?;
            match connection.exchange(payload, context).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    first_error.get_or_insert_with(|| error.clone());
                    if error.failure() == ProxyDnsRequestFailure::Capacity {
                        connection.wait_for_capacity(context).await?;
                    } else {
                        self.reap_closed_connections(context).await?;
                    }
                }
            }
        }
        Err(first_error.unwrap_or_else(|| {
            ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Retry,
                ProxyDnsRequestFailure::Protocol,
                "DNS TCP multiplex retry ended without a recorded failure",
            )
        }))
    }

    async fn connection(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<ResidentDnsTcpMultiplexHandle, ProxyDnsRequestError> {
        loop {
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Cancelled,
                    "DNS TCP multiplex forwarder is closing",
                ));
            }
            self.reap_closed_connections(context).await?;
            if let Some(handle) = self.select_connection(true).await {
                return Ok(handle);
            }
            let open_guard = context
                .run(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Cancelled,
                    async { Ok::<_, std::convert::Infallible>(self.open_lock.lock().await) },
                )
                .await?;
            if self.closing.load(std::sync::atomic::Ordering::Acquire) {
                return Err(ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Cancelled,
                    "DNS TCP multiplex forwarder is closing",
                ));
            }
            self.reap_closed_connections(context).await?;
            if let Some(handle) = self.select_connection(true).await {
                return Ok(handle);
            }
            let active_connections = self
                .connections
                .lock()
                .await
                .iter()
                .filter(|connection| !connection.handle.is_closed())
                .count();
            if active_connections < self.connection_limit {
                let connection = self.open_connection(context).await?;
                let handle = connection.handle.clone();
                self.connections.lock().await.push(connection);
                return Ok(handle);
            }
            let waiting = self.select_connection(false).await.ok_or_else(|| {
                ProxyDnsRequestError::new(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Network,
                    "DNS TCP multiplex pool has no live connection",
                )
            })?;
            drop(open_guard);
            waiting.wait_for_capacity(context).await?;
        }
    }

    async fn open_connection(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<ResidentDnsTcpMultiplexConnection, ProxyDnsRequestError> {
        let (handle, registration) = ResidentDnsTcpMultiplexHandle::new(self.request_limit);
        let task = match &self.connection_kind {
            ResidentDnsTcpConnectionKind::Direct => {
                let stream = open_dns_tcp_stream_with_context_async(
                    &self.upstream,
                    self.target,
                    self.mark,
                    context,
                )
                .await?;
                tokio::spawn(registration.run(stream))
            }
            ResidentDnsTcpConnectionKind::Proxy { binding, transport } => {
                let binding = binding.clone();
                let transport = Arc::clone(transport);
                let target = self.target.to_string();
                tokio::spawn(async move {
                    run_resident_proxy_dns_tcp_connection(
                        transport.as_ref(),
                        binding,
                        target,
                        true,
                        Vec::new(),
                        String::new(),
                        context,
                        time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
                        |stream| async move {
                            registration.run(stream).await.map_err(|error| {
                                ProxyDnsRequestError::new(
                                    ProxyDnsRequestStage::Read,
                                    ProxyDnsRequestFailure::Network,
                                    error,
                                )
                            })
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())
                })
            }
        };
        Ok(ResidentDnsTcpMultiplexConnection { handle, task })
    }

    async fn select_connection(
        &self,
        require_capacity: bool,
    ) -> Option<ResidentDnsTcpMultiplexHandle> {
        self.connections
            .lock()
            .await
            .iter()
            .filter(|connection| !connection.handle.is_closed())
            .filter(|connection| !require_capacity || connection.handle.has_capacity())
            .min_by_key(|connection| connection.handle.pending())
            .map(|connection| connection.handle.clone())
    }

    async fn reap_closed_connections(
        &self,
        context: ProxyDnsRequestContext,
    ) -> Result<(), ProxyDnsRequestError> {
        let mut retired = {
            let mut connections = self.connections.lock().await;
            let mut active = Vec::with_capacity(connections.len());
            let mut retired = Vec::new();
            for connection in std::mem::take(&mut *connections) {
                if connection.handle.is_closed() {
                    retired.push(connection);
                } else {
                    active.push(connection);
                }
            }
            *connections = active;
            retired
        };
        for connection in &mut retired {
            if time::timeout_at(context.deadline(), &mut connection.task)
                .await
                .is_err()
            {
                connection.task.abort();
                let _ = (&mut connection.task).await;
            }
        }
        Ok(())
    }
}

pub(super) async fn open_dns_tcp_stream_with_context_async(
    upstream: &ResidentDnsUpstream,
    target: SocketAddr,
    mark: u32,
    context: ProxyDnsRequestContext,
) -> Result<TokioTcpStream, ProxyDnsRequestError> {
    context.ensure(ProxyDnsRequestStage::Connect)?;
    time::timeout_at(
        context.deadline(),
        open_dns_tcp_stream_async(upstream, target, mark),
    )
    .await
    .map_err(|_| ProxyDnsRequestError::deadline(ProxyDnsRequestStage::Connect))?
    .map_err(|error| {
        ProxyDnsRequestError::new(
            ProxyDnsRequestStage::Connect,
            ProxyDnsRequestFailure::Network,
            error,
        )
    })
}

pub(super) fn dns_transport_route_name(selection: &ResidentDnsUpstreamSelection) -> &'static str {
    match selection {
        ResidentDnsUpstreamSelection::Direct { .. } => DNS_TRANSPORT_ROUTE_DIRECT,
        ResidentDnsUpstreamSelection::Proxy { .. } => DNS_TRANSPORT_ROUTE_PROXY,
    }
}

pub(in crate::dns) async fn forward_dns_tcp_asis_async(
    target: SocketAddr,
    payload: &[u8],
    mark: u32,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, String> {
    let connected = time::timeout_at(
        context.deadline(),
        open_direct_tcp_connection_async(target.to_string(), mark, false),
    )
    .await
    .map_err(|_| "DNS TCP asis connect absolute deadline expired".to_owned())?
    .map_err(|err| format!("connect DNS TCP asis {target}: {err}"))?;
    let mut stream = TokioTcpStream::from_std(connected.stream)
        .map_err(|err| format!("adopt DNS TCP asis stream: {err}"))?;
    time::timeout_at(
        context.deadline(),
        forward_dns_framed_stream_async(&mut stream, payload),
    )
    .await
    .map_err(|_| "DNS TCP asis exchange timeout".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Socks5TcpRelay, dns_proxy_binding, socks5_dns_proxy};
    use super::*;
    use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
    use std::time::Duration;

    fn direct_tcp_test_upstream(target: SocketAddr) -> ResidentDnsUpstream {
        ResidentDnsUpstream {
            index: 0,
            tag: "direct-connect-classification".to_owned(),
            target: ResidentDnsUpstreamTarget::new(
                target.to_string(),
                target.ip().to_string(),
                target.port(),
                Some(target),
                target,
                0,
                Duration::from_secs(60),
            ),
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: Arc::from(""),
        }
    }

    #[tokio::test]
    async fn direct_tcp_refusal_is_a_typed_target_connect_failure() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = listener.local_addr().unwrap();
        drop(listener);
        let error = open_dns_tcp_stream_with_context_async(
            &direct_tcp_test_upstream(target),
            target,
            0,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(1)),
        )
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Connect);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Network);
    }

    #[tokio::test]
    async fn direct_tcp_connect_deadline_is_typed_before_socket_work() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT);
        let error = open_dns_tcp_stream_with_context_async(
            &direct_tcp_test_upstream(target),
            target,
            0,
            ProxyDnsRequestContext::from_timeout(Duration::ZERO),
        )
        .await
        .unwrap_err();

        assert_eq!(error.stage(), ProxyDnsRequestStage::Connect);
        assert_eq!(error.failure(), ProxyDnsRequestFailure::Deadline);
    }

    #[tokio::test]
    async fn forward_dns_udp_retries_after_timeout() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let _ = upstream.recv_from(&mut buf).await.unwrap();
            let (read, peer) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&buf[..read], peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            b"fixture-query",
            0,
            2,
            std::time::Duration::from_millis(20),
        )
        .await
        .unwrap();

        assert_eq!(response, b"fixture-query");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forward_dns_udp_reports_attempt_count_after_timeouts() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            while upstream.recv_from(&mut buf).await.is_ok() {}
        });

        let err = forward_dns_udp_with_attempts_async(
            target,
            b"fixture-query",
            0,
            2,
            std::time::Duration::from_millis(5),
        )
        .await
        .unwrap_err();

        assert!(err.contains("after 2 attempts"));
    }

    #[tokio::test]
    async fn forward_dns_udp_discards_stale_response_id() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let query = build_dns_query_packet(0x1234, "example.com", DNS_QTYPE_A).unwrap();
        let response = dns_a_response_for_query(&query, [192, 0, 2, 1]);
        let mut stale = response.clone();
        stale[0..2].copy_from_slice(&0xabcd_u16.to_be_bytes());
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; DNS_RESPONSE_READ_LIMIT];
            let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&stale, peer).await.unwrap();
            upstream.send_to(&response, peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            &query,
            0,
            1,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(response[0..2], 0x1234_u16.to_be_bytes());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forward_dns_udp_discards_unexpected_peer_response() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let other_peer = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let query = build_dns_query_packet(0x4321, "example.com", DNS_QTYPE_A).unwrap();
        let unexpected = dns_a_response_for_query(&query, [192, 0, 2, 1]);
        let expected = dns_a_response_for_query(&query, [192, 0, 2, 2]);
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; DNS_RESPONSE_READ_LIMIT];
            let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
            other_peer.send_to(&unexpected, peer).await.unwrap();
            time::sleep(std::time::Duration::from_millis(10)).await;
            upstream.send_to(&expected, peer).await.unwrap();
        });

        let response = forward_dns_udp_with_attempts_async(
            target,
            &query,
            0,
            1,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(response, dns_a_response_for_query(&query, [192, 0, 2, 2]));
        server.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn direct_dns_udp_forwarder_recreates_a_fatal_actor_for_the_same_target() {
        let reserved = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = reserved.local_addr().unwrap();
        drop(reserved);
        let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
        runtime.direct_shards = 1;
        runtime.actor_worker_threads = 1;
        runtime.attempts = 1;
        runtime.attempt_timeout = Duration::from_millis(500);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
            runtime.clone(),
            Arc::clone(&metrics),
        ));
        let forwarder = ResidentDnsUdpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                Arc::clone(&metrics),
                std::mem::size_of::<ResidentDnsUdpForwarder>()
                    .saturating_add(std::mem::size_of::<ResidentDnsUdpForwarderShard>()),
            ),
            target,
            mark: 0,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
            executor: Arc::clone(&executor),
            shards: vec![ResidentDnsUdpForwarderShard {
                handle: AsyncMutex::new(None),
                opened: std::sync::atomic::AtomicBool::new(false),
                inflight: std::sync::atomic::AtomicUsize::new(0),
            }],
            runtime_config: runtime.clone(),
        };
        let query = build_dns_query_packet(0x6161, "fatal-recreate.example", DNS_QTYPE_A).unwrap();
        let failed_handle = forwarder.handle(0).await.unwrap();
        assert!(failed_handle.exchange_once(&query).await.is_err());
        time::timeout(Duration::from_secs(1), async {
            while !failed_handle.is_closed() {
                time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("fatal DNS UDP actor did not close");

        let upstream = tokio::net::UdpSocket::bind(target).await.unwrap();
        let server = tokio::spawn(async move {
            let mut request = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            let (read, peer) = upstream.recv_from(&mut request).await.unwrap();
            let response = dns_a_response_for_query(&request[..read], [192, 0, 2, 44]);
            upstream.send_to(&response, peer).await.unwrap();
        });
        let response = forwarder
            .exchange(
                &query,
                ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
            )
            .await
            .unwrap();

        assert_eq!(&response[0..2], &0x6161_u16.to_be_bytes());
        server.await.unwrap();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["dnsUdpActorFatalExits"], 1);
        assert_eq!(snapshot["dnsUdpForwarderRecreated"], 1);
        let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
        assert_eq!(executor.shutdown(deadline).await["status"], "pass");
    }

    #[tokio::test]
    async fn direct_dns_udp_shards_expand_under_concurrency_and_release_idle_excess() {
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut packets = Vec::new();
            let mut buffer = vec![0_u8; DNS_RESPONSE_READ_LIMIT];
            for _ in 0..2 {
                let (read, peer) = upstream.recv_from(&mut buffer).await.unwrap();
                packets.push((buffer[..read].to_vec(), peer));
            }
            for (index, (query, peer)) in packets.into_iter().rev().enumerate() {
                let response = dns_a_response_for_query(&query, [192, 0, 2, 110 + index as u8]);
                upstream.send_to(&response, peer).await.unwrap();
            }
        });
        let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
        runtime.direct_shards = 2;
        runtime.attempts = 1;
        runtime.shard_idle_timeout = Duration::from_millis(20);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
            runtime.clone(),
            Arc::clone(&metrics),
        ));
        let forwarder = ResidentDnsUdpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                Arc::clone(&metrics),
                std::mem::size_of::<ResidentDnsUdpForwarder>(),
            ),
            target,
            mark: 0,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
            executor: Arc::clone(&executor),
            shards: (0..2)
                .map(|_| ResidentDnsUdpForwarderShard {
                    handle: AsyncMutex::new(None),
                    opened: std::sync::atomic::AtomicBool::new(false),
                    inflight: std::sync::atomic::AtomicUsize::new(0),
                })
                .collect(),
            runtime_config: runtime,
        };
        let first = build_dns_query_packet(0x7401, "first-udp-shard.example", DNS_QTYPE_A).unwrap();
        let second =
            build_dns_query_packet(0x7402, "second-udp-shard.example", DNS_QTYPE_A).unwrap();
        let context = ProxyDnsRequestContext::from_timeout(Duration::from_secs(1));
        let (first_response, second_response) = tokio::join!(
            forwarder.exchange(&first, context),
            forwarder.exchange(&second, context),
        );
        assert_eq!(&first_response.unwrap()[0..2], &0x7401_u16.to_be_bytes());
        assert_eq!(&second_response.unwrap()[0..2], &0x7402_u16.to_be_bytes());
        server.await.unwrap();
        assert!(
            forwarder
                .shards
                .iter()
                .all(|shard| shard.opened.load(std::sync::atomic::Ordering::Acquire))
        );
        assert_eq!(metrics.snapshot()["dnsUdpActorsOpened"], 2);

        time::timeout(Duration::from_millis(200), async {
            while metrics.snapshot()["dnsUdpActorsClosed"] == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle excess DNS UDP shard did not close");
        forwarder.refresh_closed_shards();
        assert!(
            forwarder.shards[0]
                .opened
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(
            !forwarder.shards[1]
                .opened
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert_eq!(
            executor
                .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
                .await["status"],
            "pass"
        );
    }

    fn dns_a_response_for_query(query: &[u8], address: [u8; 4]) -> Vec<u8> {
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
        response.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address);
        response
    }

    #[tokio::test]
    async fn forward_dns_tcp_tries_next_resolved_target_after_connect_failure() {
        let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let server_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = server_listener.accept().await.unwrap();
            let mut len = [0_u8; 2];
            stream.read_exact(&mut len).await.unwrap();
            let len = u16::from_be_bytes(len) as usize;
            let mut payload = vec![0_u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            let response = dns_a_response_for_query(&payload, [192, 0, 2, 60]);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });

        let upstream = ResidentDnsUpstream {
            index: 0,
            tag: "test".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: Arc::from("test.example:53"),
                host: "test.example".to_owned(),
                port: 53,
                literal_addr: None,
                fallback_resolver: "127.0.0.1:53".parse().unwrap(),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: Arc::from(""),
        };
        upstream
            .target
            .resolved_addrs
            .seed(vec![closed, server_addr], Duration::from_secs(60))
            .await;

        let plan = ResidentDnsPlan::asis(0);
        let forwarders = Arc::new(ResidentDnsForwarderCache::default());
        let query = build_dns_query_packet(0x6060, "next-target.example", DNS_QTYPE_A).unwrap();
        let response = forward_dns_tcp_async(
            &upstream,
            &query,
            &plan,
            &forwarders,
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        )
        .await
        .unwrap();

        assert_eq!(&response[0..2], &0x6060_u16.to_be_bytes());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxied_dns_tcp_reuses_one_pipeline_for_out_of_order_responses() {
        let upstream_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = upstream_listener.local_addr().unwrap();
        let upstream_server = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut frame_reader = DnsTcpFrameReader::default();
            let warm = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
            let warm_response = dns_a_response_for_query(&warm, [192, 0, 2, 70]);
            write_dns_tcp_payload_async(&mut stream, &warm_response)
                .await
                .unwrap();
            let first = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
            let second = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
            let second_response = dns_a_response_for_query(&second, [192, 0, 2, 72]);
            let first_response = dns_a_response_for_query(&first, [192, 0, 2, 71]);
            write_dns_tcp_payload_async(&mut stream, &second_response)
                .await
                .unwrap();
            write_dns_tcp_payload_async(&mut stream, &first_response)
                .await
                .unwrap();
        });
        let relay = Socks5TcpRelay::start().await;
        let upstream = ResidentDnsUpstream {
            index: 0,
            tag: "proxied-pipeline".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: Arc::from(target.to_string()),
                host: target.ip().to_string(),
                port: target.port(),
                literal_addr: Some(target),
                fallback_resolver: "127.0.0.1:53".parse().unwrap(),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: Arc::from(""),
        };
        let binding = dns_proxy_binding(socks5_dns_proxy(relay.address()), 1);
        let selection = ResidentDnsUpstreamSelection::Proxy { binding };
        let cache = Arc::new(ResidentDnsForwarderCache::default());
        let forwarder = cache
            .tcp_forwarder(&upstream, target, 0, &selection)
            .unwrap();
        let warm = build_dns_query_packet(0x7000, "warm.example", DNS_QTYPE_A).unwrap();
        let warm_response = forwarder
            .exchange(
                &warm,
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(&warm_response[0..2], &0x7000_u16.to_be_bytes());

        let first = build_dns_query_packet(0x7100, "first.example", DNS_QTYPE_A).unwrap();
        let second = build_dns_query_packet(0x7200, "second.example", DNS_QTYPE_A).unwrap();
        let first_exchange = forwarder.exchange(
            &first,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
        );
        let second_exchange = forwarder.exchange(
            &second,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
        );
        let (first_response, second_response) = tokio::join!(first_exchange, second_exchange);
        assert_eq!(&first_response.unwrap()[0..2], &0x7100_u16.to_be_bytes());
        assert_eq!(&second_response.unwrap()[0..2], &0x7200_u16.to_be_bytes());
        upstream_server.await.unwrap();
        assert_eq!(relay.connections(), 1);
        let deadline = time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
        assert_eq!(cache.shutdown(deadline).await["status"], "pass");
    }

    #[tokio::test]
    async fn proxied_dns_tcp_pool_expands_before_waiting_on_a_full_pipeline() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let response_barrier = Arc::new(tokio::sync::Barrier::new(3));
        let server_barrier = Arc::clone(&response_barrier);
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for index in 0..2_u8 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let response_barrier = Arc::clone(&server_barrier);
                connections.spawn(async move {
                    let mut frame_reader = DnsTcpFrameReader::default();
                    let query = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
                    response_barrier.wait().await;
                    let response = dns_a_response_for_query(&query, [192, 0, 2, 100 + index]);
                    write_dns_tcp_payload_async(&mut stream, &response)
                        .await
                        .unwrap();
                });
            }
            server_barrier.wait().await;
            while connections.join_next().await.is_some() {}
        });
        let relay = Socks5TcpRelay::start().await;
        let upstream = ResidentDnsUpstream {
            index: 0,
            tag: "proxied-pool".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: Arc::from(target.to_string()),
                host: target.ip().to_string(),
                port: target.port(),
                literal_addr: Some(target),
                fallback_resolver: "127.0.0.1:53".parse().unwrap(),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: Arc::from(""),
        };
        let forwarder = Arc::new(ResidentDnsTcpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                Arc::new(ResidentDataplaneMetrics::default()),
                std::mem::size_of::<ResidentDnsTcpForwarder>(),
            ),
            upstream,
            target,
            mark: 0,
            connection_kind: ResidentDnsTcpConnectionKind::Proxy {
                binding: dns_proxy_binding(socks5_dns_proxy(relay.address()), 1),
                transport: resident_dns_proxy_tcp_transport(
                    ResidentTransportOwnerRegistries::default(),
                ),
            },
            connection_limit: 2,
            request_limit: 1,
            connections: AsyncMutex::new(Vec::new()),
            open_lock: AsyncMutex::new(()),
            closing: std::sync::atomic::AtomicBool::new(false),
        });
        let first =
            build_dns_query_packet(0x7301, "first-proxy-pool.example", DNS_QTYPE_A).unwrap();
        let first_forwarder = Arc::clone(&forwarder);
        let first_exchange = tokio::spawn(async move {
            first_forwarder
                .exchange(
                    &first,
                    ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
                )
                .await
        });
        time::timeout(Duration::from_secs(1), async {
            loop {
                let ready = forwarder
                    .connections
                    .lock()
                    .await
                    .first()
                    .is_some_and(|connection| connection.handle.pending() == 1);
                if ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first proxied DNS TCP pipeline did not reach capacity");
        let second =
            build_dns_query_packet(0x7302, "second-proxy-pool.example", DNS_QTYPE_A).unwrap();
        let second_response = forwarder
            .exchange(
                &second,
                ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        let first_response = first_exchange.await.unwrap().unwrap();
        assert_eq!(&first_response[0..2], &0x7301_u16.to_be_bytes());
        assert_eq!(&second_response[0..2], &0x7302_u16.to_be_bytes());
        server.await.unwrap();
        assert_eq!(relay.connections(), 2);

        forwarder
            .closing
            .store(true, std::sync::atomic::Ordering::Release);
        let mut connections = std::mem::take(&mut *forwarder.connections.lock().await);
        for connection in &connections {
            connection.handle.close();
        }
        for connection in &mut connections {
            let _ = time::timeout(Duration::from_secs(1), &mut connection.task)
                .await
                .expect("proxied DNS TCP pipeline did not join after close")
                .expect("proxied DNS TCP pipeline task panicked");
            assert_eq!(connection.handle.pending(), 0);
        }
    }

    #[tokio::test]
    async fn direct_dns_tcp_pool_expands_before_waiting_on_a_full_connection() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_count = Arc::clone(&accepted);
        let response_barrier = Arc::new(tokio::sync::Barrier::new(3));
        let server_barrier = Arc::clone(&response_barrier);
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                accepted_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                let response_barrier = Arc::clone(&server_barrier);
                connections.spawn(async move {
                    let mut frame_reader = DnsTcpFrameReader::default();
                    let query = frame_reader.read_frame(&mut stream).await.unwrap().unwrap();
                    response_barrier.wait().await;
                    let response = dns_a_response_for_query(&query, [192, 0, 2, 90]);
                    write_dns_tcp_payload_async(&mut stream, &response)
                        .await
                        .unwrap();
                });
            }
            server_barrier.wait().await;
            while connections.join_next().await.is_some() {}
        });
        let upstream = ResidentDnsUpstream {
            index: 0,
            tag: "direct-pool".to_owned(),
            target: ResidentDnsUpstreamTarget {
                authority: Arc::from(target.to_string()),
                host: target.ip().to_string(),
                port: target.port(),
                literal_addr: Some(target),
                fallback_resolver: "127.0.0.1:53".parse().unwrap(),
                resolver_mark: 0,
                resolved_addrs: Arc::default(),
            },
            scheme: ResidentDnsUpstreamScheme::Tcp,
            path: Arc::from(""),
        };
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let forwarder = ResidentDnsTcpForwarder {
            owner_observation: ResidentDnsTransportOwnerObservation::new(
                metrics,
                std::mem::size_of::<ResidentDnsTcpForwarder>(),
            ),
            upstream,
            target,
            mark: 0,
            connection_kind: ResidentDnsTcpConnectionKind::Direct,
            connection_limit: 2,
            request_limit: 1,
            connections: AsyncMutex::new(Vec::new()),
            open_lock: AsyncMutex::new(()),
            closing: std::sync::atomic::AtomicBool::new(false),
        };
        let first = build_dns_query_packet(0x8100, "first-pool.example", DNS_QTYPE_A).unwrap();
        let second = build_dns_query_packet(0x8200, "second-pool.example", DNS_QTYPE_A).unwrap();
        let first_exchange = forwarder.exchange(
            &first,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
        );
        let second_exchange = forwarder.exchange(
            &second,
            ProxyDnsRequestContext::from_timeout(Duration::from_secs(2)),
        );
        let (first_response, second_response) = tokio::join!(first_exchange, second_exchange);
        assert_eq!(&first_response.unwrap()[0..2], &0x8100_u16.to_be_bytes());
        assert_eq!(&second_response.unwrap()[0..2], &0x8200_u16.to_be_bytes());
        server.await.unwrap();
        assert_eq!(accepted.load(std::sync::atomic::Ordering::Acquire), 2);
        for connection in forwarder.connections.lock().await.iter() {
            connection.handle.close();
        }
    }
}
