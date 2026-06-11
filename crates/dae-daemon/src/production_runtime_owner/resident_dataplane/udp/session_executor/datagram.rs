use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use super::*;

#[derive(Default)]
pub(super) struct DatagramRelay {
    socket: Option<tokio::net::UdpSocket>,
    remote: Option<SocketAddr>,
}

impl DatagramRelay {
    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        request: &[u8],
        label: &str,
    ) -> Result<Vec<u8>, String> {
        self.ensure_open(proxy).await?;
        let remote = self
            .remote
            .ok_or_else(|| format!("{label} UDP relay remote is not initialized"))?;
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| format!("{label} UDP relay socket is not initialized"))?;
        socket
            .send_to(request, remote)
            .await
            .map_err(|err| format!("send {label} UDP datagram: {err}"))?;
        let mut response = vec![0_u8; 64 * 1024];
        let (read, _) = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            socket.recv_from(&mut response),
        )
        .await
        .map_err(|_| format!("receive {label} UDP datagram timeout"))?
        .map_err(|err| format!("receive {label} UDP datagram: {err}"))?;
        response.truncate(read);
        Ok(response)
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.socket.is_some() && self.remote.is_some() {
            return Ok(());
        }
        let remote = resolve_proxy_udp_socket_addr_async(proxy).await?;
        self.socket = Some(open_marked_tokio_udp_socket(remote, proxy.mark).await?);
        self.remote = Some(remote);
        Ok(())
    }
}

pub(super) async fn open_marked_tokio_udp_socket(
    remote: SocketAddr,
    mark: u32,
) -> Result<tokio::net::UdpSocket, String> {
    let bind = match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).map_err(|err| format!("bind UDP relay socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set UDP relay SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set UDP relay socket nonblocking: {err}"))?;
    tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt UDP relay socket into tokio: {err}"))
}
