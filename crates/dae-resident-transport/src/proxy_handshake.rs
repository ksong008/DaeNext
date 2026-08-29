use dae_outbound::{
    http_proxy::{HttpConnectOptions, request as http_request},
    socks5::{Socks5Address, handshake},
};
use dae_resident_core::RESIDENT_CONNECT_TIMEOUT;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

use crate::stream_io::read_http_connect_head_without_overread;

pub async fn socks5_connect_async(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        stream
            .write_all(&handshake::greeting(username, password))
            .await
            .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
        let mut method_selection = [0_u8; 2];
        stream
            .read_exact(&mut method_selection)
            .await
            .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
        let method = handshake::parse_method_selection(&method_selection)
            .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;
        if method == handshake::AUTH_PASSWORD {
            let auth = handshake::username_password_auth(username, password)
                .map_err(|err| format!("build SOCKS5 auth: {err}"))?;
            stream
                .write_all(&auth)
                .await
                .map_err(|err| format!("write SOCKS5 auth: {err}"))?;
            let mut auth_reply = [0_u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .await
                .map_err(|err| format!("read SOCKS5 auth reply: {err}"))?;
            if auth_reply[0] != handshake::PASSWORD_AUTH_VERSION || auth_reply[1] != 0 {
                return Err(format!("SOCKS5 auth rejected: {:02x?}", auth_reply));
            }
        }
        let target =
            Socks5Address::parse(target).map_err(|err| format!("parse SOCKS5 target: {err}"))?;
        let request = handshake::request(handshake::Socks5Command::Connect, &target)
            .map_err(|err| format!("build SOCKS5 CONNECT: {err}"))?;
        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("write SOCKS5 CONNECT: {err}"))?;
        let mut reply_head = [0_u8; 3];
        stream
            .read_exact(&mut reply_head)
            .await
            .map_err(|err| format!("read SOCKS5 CONNECT reply: {err}"))?;
        let mut reply = reply_head.to_vec();
        reply.extend(read_socks5_address_bytes_async(stream).await?);
        handshake::parse_server_reply(&reply)
            .map_err(|err| format!("parse SOCKS5 CONNECT reply: {err}"))?;
        Ok(())
    })
    .await
    .map_err(|_| "SOCKS5 CONNECT timeout".to_owned())?
}

pub async fn http_proxy_connect_plain_async(
    stream: &mut TcpStream,
    target: &str,
    username: &str,
    password: &str,
    transport: bool,
    transport_host: &str,
    transport_path: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_CONNECT_TIMEOUT, async {
        let mut options = HttpConnectOptions::connect(target);
        options.username = username.to_owned();
        options.password = password.to_owned();
        options.transport.enabled = transport;
        options.host_override = transport_host.to_owned();
        options.transport.path = transport_path.to_owned();
        let request = http_request::connect_request(&options)
            .map_err(|err| format!("build HTTP CONNECT request: {err}"))?;
        stream
            .write_all(&request)
            .await
            .map_err(|err| format!("write HTTP CONNECT request: {err}"))?;
        let response = read_http_connect_head_without_overread(stream).await?;
        let status = http_request::parse_connect_response(&response)
            .map_err(|err| format!("parse HTTP CONNECT response: {err}"))?;
        if status != 200 {
            return Err(format!("HTTP CONNECT status: {status}"));
        }
        Ok(())
    })
    .await
    .map_err(|_| "HTTP CONNECT timeout".to_owned())?
}

async fn read_socks5_address_bytes_async(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .await
        .map_err(|err| format!("read SOCKS5 reply address type: {err}"))?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 IPv4 reply address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|err| format!("read SOCKS5 domain reply length: {err}"))?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; usize::from(len[0]) + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 domain reply address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 IPv6 reply address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        _ => {}
    }
    Ok(out)
}
