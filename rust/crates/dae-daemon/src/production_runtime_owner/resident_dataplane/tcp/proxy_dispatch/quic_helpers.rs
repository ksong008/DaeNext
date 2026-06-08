use super::*;
pub(crate) async fn relay_tcp_over_quic_stream_async(
    inbound: &mut TokioTcpStream,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = send.finish();
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send.write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| format!("write client payload to QUIC stream: {err}"))?;
                        send.flush()
                            .await
                            .map_err(|err| format!("flush QUIC stream: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = send.finish();
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for QUIC stream relay: {err}")),
                }
            }
            read = recv.read(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(None) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(Some(read)) => {
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write QUIC stream payload to client: {err}"));
                        }
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read QUIC stream payload: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident QUIC stream relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}

pub(crate) fn open_marked_quic_endpoint(mark: u32) -> Result<quinn::Endpoint, String> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|err| format!("bind QUIC UDP socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set QUIC UDP SO_MARK {mark}: {err}"))?;
    }
    let runtime =
        quinn::default_runtime().ok_or_else(|| "no quinn runtime available".to_owned())?;
    quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(|err| format!("create QUIC endpoint: {err}"))
}

pub(crate) fn resolve_proxy_udp_addr(proxy: &ResidentProxyPlan) -> Result<SocketAddr, String> {
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    target
        .to_socket_addrs()
        .map_err(|err| format!("resolve QUIC endpoint {target}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve QUIC endpoint {target}: no address"))
}

pub(crate) fn resolve_hysteria2_quic_remote(
    proxy: &ResidentProxyPlan,
    port_hop_ports: &[u16],
) -> Result<SocketAddr, String> {
    let selected_port = if port_hop_ports.is_empty() {
        proxy.server_port
    } else {
        port_hop_ports[fastrand::usize(..port_hop_ports.len())]
    };
    let target = format!("{}:{selected_port}", proxy.server_host);
    target
        .to_socket_addrs()
        .map_err(|err| format!("resolve Hysteria2 QUIC endpoint {target}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve Hysteria2 QUIC endpoint {target}: no address"))
}

pub(crate) fn set_socket_mark(fd: i32, mark: u32) -> std::io::Result<()> {
    let mark = mark as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
