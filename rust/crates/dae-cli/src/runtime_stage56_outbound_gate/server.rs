use super::*;

#[derive(Debug, Default)]
pub(super) struct Socks5UdpServerSummary {
    pub(super) accepted: usize,
    pub(super) auth_success_count: usize,
    pub(super) udp_associate_count: usize,
    pub(super) udp_packet_roundtrip_count: usize,
    pub(super) control_retained_during_udp_count: usize,
    pub(super) associate_targets: Vec<String>,
    pub(super) packet_targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_socks5_udp_server(
    opts: &Stage56Options,
) -> Result<
    (
        SocketAddrV4,
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Socks5UdpServerSummary, String>>,
    ),
    String,
> {
    let (tcp_listener, tcp_listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage56 bind loopback tcp control listener failed: {err}"))?;
    let tcp_addr = match tcp_listener
        .local_addr()
        .map_err(|err| format!("stage56 tcp listener local_addr failed: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage56 tcp listener is not IPv4: {addr}"));
        }
    };
    tcp_listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage56 tcp listener nonblocking failed: {err}"))?;

    let udp_socket = UdpSocket::bind(("127.0.0.1", 0))
        .map_err(|err| format!("stage56 bind udp relay failed: {err}"))?;
    udp_socket
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage56 udp relay read timeout failed: {err}"))?;
    udp_socket
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage56 udp relay write timeout failed: {err}"))?;
    let udp_addr = match udp_socket
        .local_addr()
        .map_err(|err| format!("stage56 udp relay local_addr failed: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage56 udp relay is not IPv4: {addr}"));
        }
    };

    let iterations = opts.benchmark_iters;
    let associate_target = opts.associate_target.clone();
    let packet_target = opts.packet_target.clone();
    let username = opts.username.clone();
    let password = opts.password.clone();
    let payload = opts.payload.clone();
    let response = opts.response.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_socks5_udp_associations(
            tcp_listener,
            udp_socket,
            udp_addr,
            iterations,
            &associate_target,
            &packet_target,
            &username,
            &password,
            &payload,
            &response,
            timeout,
        )
    });
    Ok((tcp_addr, udp_addr, tcp_listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_socks5_udp_associations(
    tcp_listener: TcpListener,
    udp_socket: UdpSocket,
    udp_addr: SocketAddrV4,
    iterations: usize,
    associate_target: &str,
    packet_target: &str,
    username: &str,
    password: &str,
    payload: &[u8],
    response: &[u8],
    timeout: Duration,
) -> Result<Socks5UdpServerSummary, String> {
    let mut summary = Socks5UdpServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match tcp_listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage56 server set tcp read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage56 server set tcp write timeout failed: {err}"))?;
                handle_socks5_udp_control(
                    &mut stream,
                    udp_addr.port(),
                    associate_target,
                    username,
                    password,
                    &mut summary,
                )?;
                handle_socks5_udp_packet(
                    &udp_socket,
                    packet_target,
                    payload,
                    response,
                    &mut summary,
                )?;
                summary.control_retained_during_udp_count += 1;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage56 socks5 server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage56 socks5 server accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_socks5_udp_control(
    stream: &mut TcpStream,
    udp_port: u16,
    associate_target: &str,
    username: &str,
    password: &str,
    summary: &mut Socks5UdpServerSummary,
) -> Result<(), String> {
    let mut header = [0_u8; 2];
    stream
        .read_exact(&mut header)
        .map_err(|err| format!("stage56 socks5 greeting header failed: {err}"))?;
    if header[0] != handshake::VERSION {
        return Err(format!("stage56 socks5 bad version: {}", header[0]));
    }
    let mut methods = vec![0_u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .map_err(|err| format!("stage56 socks5 greeting methods failed: {err}"))?;
    if !methods.contains(&handshake::AUTH_PASSWORD) {
        return Err("stage56 socks5 client did not offer password auth".to_owned());
    }
    stream
        .write_all(&[handshake::VERSION, handshake::AUTH_PASSWORD])
        .map_err(|err| format!("stage56 socks5 method reply failed: {err}"))?;

    let mut auth_head = [0_u8; 2];
    stream
        .read_exact(&mut auth_head)
        .map_err(|err| format!("stage56 socks5 auth header failed: {err}"))?;
    if auth_head[0] != handshake::PASSWORD_AUTH_VERSION {
        return Err(format!("stage56 socks5 bad auth version: {}", auth_head[0]));
    }
    let mut got_user = vec![0_u8; auth_head[1] as usize];
    stream
        .read_exact(&mut got_user)
        .map_err(|err| format!("stage56 socks5 auth username failed: {err}"))?;
    let mut pass_len = [0_u8; 1];
    stream
        .read_exact(&mut pass_len)
        .map_err(|err| format!("stage56 socks5 auth password len failed: {err}"))?;
    let mut got_pass = vec![0_u8; pass_len[0] as usize];
    stream
        .read_exact(&mut got_pass)
        .map_err(|err| format!("stage56 socks5 auth password failed: {err}"))?;
    if got_user != username.as_bytes() || got_pass != password.as_bytes() {
        stream
            .write_all(&[handshake::PASSWORD_AUTH_VERSION, 1])
            .map_err(|err| format!("stage56 socks5 auth reject failed: {err}"))?;
        return Err("stage56 socks5 username/password mismatch".to_owned());
    }
    stream
        .write_all(&[handshake::PASSWORD_AUTH_VERSION, 0])
        .map_err(|err| format!("stage56 socks5 auth success failed: {err}"))?;
    summary.auth_success_count += 1;

    let mut request_head = [0_u8; 3];
    stream
        .read_exact(&mut request_head)
        .map_err(|err| format!("stage56 socks5 request header failed: {err}"))?;
    if request_head
        != [
            handshake::VERSION,
            handshake::Socks5Command::UdpAssociate.byte(),
            0,
        ]
    {
        return Err(format!(
            "stage56 socks5 unexpected udp associate header: {:02x?}",
            request_head
        ));
    }
    let requested_target = read_socks5_address(stream)?.authority();
    if requested_target != associate_target {
        return Err(format!(
            "stage56 socks5 associate target mismatch: got {requested_target}, want {associate_target}"
        ));
    }
    summary.udp_associate_count += 1;
    summary.associate_targets.push(requested_target);

    let mut reply = vec![handshake::VERSION, 0, 0];
    Socks5Address::Ipv4 {
        addr: Ipv4Addr::UNSPECIFIED,
        port: udp_port,
    }
    .write_to(&mut reply)
    .map_err(|err| err.to_string())?;
    stream
        .write_all(&reply)
        .map_err(|err| format!("stage56 socks5 udp associate reply failed: {err}"))?;
    Ok(())
}

fn handle_socks5_udp_packet(
    udp_socket: &UdpSocket,
    packet_target: &str,
    payload: &[u8],
    response: &[u8],
    summary: &mut Socks5UdpServerSummary,
) -> Result<(), String> {
    let mut buf = vec![0_u8; 2048];
    let (read, peer) = udp_socket
        .recv_from(&mut buf)
        .map_err(|err| format!("stage56 socks5 udp recv failed: {err}"))?;
    buf.truncate(read);
    let packet = udp_packet::unwrap(&buf).map_err(|err| err.to_string())?;
    if packet.reserved != [0, 0] || packet.fragment != 0 {
        return Err(format!(
            "stage56 socks5 udp bad header: reserved={:02x?} fragment={}",
            packet.reserved, packet.fragment
        ));
    }
    if packet.target.authority() != packet_target {
        return Err(format!(
            "stage56 socks5 udp target mismatch: got {}, want {}",
            packet.target.authority(),
            packet_target
        ));
    }
    if packet.payload != payload {
        return Err("stage56 socks5 udp payload mismatch at server".to_owned());
    }
    let wrapped_response =
        udp_packet::wrap(&packet.target, response).map_err(|err| err.to_string())?;
    udp_socket
        .send_to(&wrapped_response, peer)
        .map_err(|err| format!("stage56 socks5 udp send failed: {err}"))?;
    summary.udp_packet_roundtrip_count += 1;
    summary.packet_targets.push(packet.target.authority());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&packet.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(response).to_string());
    Ok(())
}

pub(super) fn resolve_udp_associate_bind(
    bind: &str,
    proxy_addr: SocketAddrV4,
) -> Result<SocketAddrV4, String> {
    match Socks5Address::parse(bind).map_err(|err| err.to_string())? {
        Socks5Address::Ipv4 { addr, port } => {
            let resolved = if addr.is_unspecified() {
                *proxy_addr.ip()
            } else {
                addr
            };
            Ok(SocketAddrV4::new(resolved, port))
        }
        Socks5Address::Domain { hostname, port } => {
            if hostname == "localhost" {
                Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            } else {
                Err(format!(
                    "stage56 unsupported domain udp associate bind: {hostname}:{port}"
                ))
            }
        }
        Socks5Address::Ipv6 { addr, port } => Err(format!(
            "stage56 unsupported ipv6 udp associate bind: [{addr}]:{port}"
        )),
    }
}

fn read_socks5_address(stream: &mut TcpStream) -> Result<Socks5Address, String> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .map_err(|err| format!("stage56 socks5 address type failed: {err}"))?;
    let mut bytes = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage56 socks5 ipv4 address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|err| format!("stage56 socks5 domain len failed: {err}"))?;
            bytes.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage56 socks5 domain address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage56 socks5 ipv6 address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        value => return Err(format!("stage56 socks5 bad address type: {value}")),
    }
    let (addr, consumed) = Socks5Address::decode(&bytes).map_err(|err| err.to_string())?;
    if consumed != bytes.len() {
        return Err(format!(
            "stage56 socks5 address consumed {consumed}, len {}",
            bytes.len()
        ));
    }
    Ok(addr)
}
