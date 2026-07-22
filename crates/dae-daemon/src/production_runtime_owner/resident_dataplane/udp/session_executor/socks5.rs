use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
pub(in crate::production_runtime_owner::resident_dataplane::udp) struct Socks5UdpAssociateSession {
    control: Option<tokio::net::TcpStream>,
    relay: DatagramRelay,
}

impl Socks5UdpAssociateSession {
    pub(super) async fn exchange(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(binding).await?;
        let request = udp_packet::wrap_target(&original_dst.to_string(), payload)
            .map_err(|err| format!("wrap SOCKS5 UDP packet: {err}"))?;
        self.relay
            .send_packet(&request, binding.effective_socket_mark(), "SOCKS5")
            .await?;
        if let Some(response) = self.poll_response()? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let response = match self.relay.poll_response("SOCKS5")? {
            Some(response) => response,
            None => return Ok(None),
        };
        self.decode_response(&response).map(Some)
    }

    pub(super) async fn wait_response(&mut self) -> Result<UdpExchangeResult, String> {
        let response = self.relay.wait_response("SOCKS5").await?;
        self.decode_response(&response)
    }

    fn decode_response(&self, response: &[u8]) -> Result<UdpExchangeResult, String> {
        let decoded = udp_packet::unwrap(response)
            .map_err(|err| format!("unwrap SOCKS5 UDP packet: {err}"))?;
        let wire_source = decoded.target.authority().parse::<SocketAddr>();
        let result = UdpExchangeResult::new(decoded.payload, "socks5-udp-associate")
            .with_session_executor("tokio-socks5-udp-associate")
            .with_underlay_reuse("tcp-control-and-udp-relay-reused");
        Ok(match wire_source {
            Ok(source) => result.with_decoded_response_identity(Some(source), None),
            Err(_) => {
                result.with_rejected_response_identity(UdpResponseDropReason::MalformedIdentity)
            }
        })
    }

    pub(super) fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("socks5-udp-associate")
            .with_session_executor("tokio-socks5-udp-associate")
            .with_underlay_reuse("tcp-control-and-udp-relay-reused")
    }

    async fn ensure_open(&mut self, binding: &ResidentProxyBinding) -> Result<(), String> {
        if self.control.is_some() && self.relay.is_open() {
            return Ok(());
        }
        let proxy = binding.plan();
        let ResidentProxyProtocolPlan::Socks5Tcp { username, password } = &proxy.handler else {
            return Err("SOCKS5 UDP associate executor received a non-SOCKS handler".to_owned());
        };
        let mut control = open_proxy_tcp_stream_with_binding(binding, proxy.mptcp).await?;
        let bind =
            socks5_udp_associate_control_async(&mut control, "0.0.0.0:0", username, password)
                .await?;
        let control_peer = control
            .peer_addr()
            .map_err(|err| format!("read SOCKS5 control peer address: {err}"))?;
        let relay_candidates = socks5_udp_relay_addr_candidates_async(&bind, control_peer).await?;
        let mut relay = DatagramRelay::default();
        relay
            .open_candidates(relay_candidates, binding.effective_socket_mark(), "SOCKS5")
            .await?;
        self.control = Some(control);
        self.relay = relay;
        Ok(())
    }
}

async fn socks5_udp_associate_control_async(
    stream: &mut tokio::net::TcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        let method = socks5_authenticate_async(stream, username, password).await?;
        let target =
            Socks5Address::parse(target).map_err(|err| format!("parse SOCKS5 target: {err}"))?;
        let request = dae_outbound::socks5::handshake::request(
            dae_outbound::socks5::Socks5Command::UdpAssociate,
            &target,
        )
        .map_err(|err| format!("build SOCKS5 UDP associate request: {err}"))?;
        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("write SOCKS5 UDP associate request: {err}"))?;

        let mut reply_head = [0_u8; 3];
        stream
            .read_exact(&mut reply_head)
            .await
            .map_err(|err| format!("read SOCKS5 UDP associate reply head: {err}"))?;
        let mut reply_bytes = reply_head.to_vec();
        reply_bytes.extend(read_socks5_address_bytes_async(stream).await?);
        let parsed = dae_outbound::socks5::handshake::parse_server_reply(&reply_bytes)
            .map_err(|err| format!("parse SOCKS5 UDP associate reply: {err}"))?;
        if method == dae_outbound::socks5::handshake::AUTH_NO_ACCEPTABLE_METHODS {
            return Err("SOCKS5 UDP associate selected no acceptable auth method".to_owned());
        }
        Ok(parsed.bind.authority())
    })
    .await
    .map_err(|_| "SOCKS5 UDP associate timeout".to_owned())?
}

async fn socks5_authenticate_async(
    stream: &mut tokio::net::TcpStream,
    username: &str,
    password: &str,
) -> Result<u8, String> {
    let greeting = dae_outbound::socks5::handshake::greeting(username, password);
    stream
        .write_all(&greeting)
        .await
        .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
    let mut method_selection = [0_u8; 2];
    stream
        .read_exact(&mut method_selection)
        .await
        .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
    let method = dae_outbound::socks5::handshake::parse_method_selection(&method_selection)
        .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;

    if method == dae_outbound::socks5::handshake::AUTH_PASSWORD {
        let auth = dae_outbound::socks5::handshake::username_password_auth(username, password)
            .map_err(|err| format!("build SOCKS5 password auth: {err}"))?;
        stream
            .write_all(&auth)
            .await
            .map_err(|err| format!("write SOCKS5 password auth: {err}"))?;
        let mut auth_reply = [0_u8; 2];
        stream
            .read_exact(&mut auth_reply)
            .await
            .map_err(|err| format!("read SOCKS5 password auth reply: {err}"))?;
        if auth_reply[0] != dae_outbound::socks5::handshake::PASSWORD_AUTH_VERSION
            || auth_reply[1] != 0
        {
            return Err(format!(
                "SOCKS5 password auth rejected: {:02x?}",
                auth_reply
            ));
        }
    }
    Ok(method)
}

async fn read_socks5_address_bytes_async(
    stream: &mut tokio::net::TcpStream,
) -> Result<Vec<u8>, String> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .await
        .map_err(|err| format!("read SOCKS5 address type: {err}"))?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 IPv4 address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|err| format!("read SOCKS5 domain length: {err}"))?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 domain address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 IPv6 address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        other => return Err(format!("unsupported SOCKS5 address type: {other}")),
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
