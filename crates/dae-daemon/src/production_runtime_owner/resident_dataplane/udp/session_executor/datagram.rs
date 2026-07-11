use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use super::*;
use crate::production_runtime_owner::resident_dataplane::try_socket_addr_candidates;

#[derive(Default)]
pub(super) struct DatagramRelay {
    socket: Option<tokio::net::UdpSocket>,
    remote_candidates: Vec<SocketAddr>,
    selected_index: usize,
    response_buf: Vec<u8>,
}

impl DatagramRelay {
    pub(super) async fn send(
        &mut self,
        proxy: &ResidentProxyPlan,
        request: &[u8],
        label: &str,
    ) -> Result<(), String> {
        self.ensure_open(proxy).await?;
        self.send_packet(request, proxy.mark, label).await
    }

    pub(super) async fn open_candidates(
        &mut self,
        candidates: Vec<SocketAddr>,
        mark: u32,
        label: &str,
    ) -> Result<(), String> {
        self.socket = None;
        self.remote_candidates = candidates;
        self.selected_index = 0;
        self.select_open_candidate(0, mark, label).await
    }

    pub(super) async fn send_packet(
        &mut self,
        request: &[u8],
        mark: u32,
        label: &str,
    ) -> Result<(), String> {
        if self.socket.is_none() || self.remote_candidates.is_empty() {
            return Err(format!("{label} UDP relay is not initialized"));
        }
        let remote = self.remote_candidates[self.selected_index];
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| format!("{label} UDP relay socket is not initialized"))?;
        match socket.send_to(request, remote).await {
            Ok(_) => Ok(()),
            Err(first_err) => {
                self.socket = None;
                let next = self.selected_index.saturating_add(1);
                if next >= self.remote_candidates.len() {
                    return Err(format!(
                        "send {label} UDP datagram to {remote}: {first_err}"
                    ));
                }
                let remaining = &self.remote_candidates[next..];
                let context = format!(
                    "send {label} UDP datagram after candidate {remote} failed: {first_err}"
                );
                let (selected, socket) =
                    try_socket_addr_candidates(remaining, &context, |candidate| async move {
                        let socket = open_marked_tokio_udp_socket(candidate, mark).await?;
                        socket
                            .send_to(request, candidate)
                            .await
                            .map_err(|err| format!("send {label} UDP datagram: {err}"))?;
                        Ok(socket)
                    })
                    .await?;
                self.selected_index = next
                    + remaining
                        .iter()
                        .position(|candidate| *candidate == selected)
                        .ok_or_else(|| {
                            format!("{label} UDP relay selected an unknown address candidate")
                        })?;
                self.socket = Some(socket);
                Ok(())
            }
        }
    }

    pub(super) fn poll_response(&mut self, label: &str) -> Result<Option<Vec<u8>>, String> {
        let Some(socket) = self.socket.as_ref() else {
            return Ok(None);
        };
        if self.response_buf.len() < UDP_DATAGRAM_RESPONSE_CAPACITY {
            self.response_buf.resize(UDP_DATAGRAM_RESPONSE_CAPACITY, 0);
        }
        match socket.try_recv_from(&mut self.response_buf) {
            Ok((read, _)) => Ok(Some(self.response_buf[..read].to_vec())),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(format!("receive {label} UDP datagram: {err}")),
        }
    }

    pub(super) async fn wait_response(&mut self, label: &str) -> Result<Vec<u8>, String> {
        let Some(socket) = self.socket.as_ref() else {
            return Err(format!("{label} UDP relay socket is not initialized"));
        };
        if self.response_buf.len() < UDP_DATAGRAM_RESPONSE_CAPACITY {
            self.response_buf.resize(UDP_DATAGRAM_RESPONSE_CAPACITY, 0);
        }
        let (read, _) = socket
            .recv_from(&mut self.response_buf)
            .await
            .map_err(|err| format!("receive {label} UDP datagram: {err}"))?;
        Ok(self.response_buf[..read].to_vec())
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.socket.is_some() && !self.remote_candidates.is_empty() {
            return Ok(());
        }
        let candidates = resolve_proxy_udp_socket_addr_candidates_async(proxy).await?;
        self.open_candidates(candidates, proxy.mark, "proxy").await
    }

    pub(super) fn is_open(&self) -> bool {
        self.socket.is_some() && !self.remote_candidates.is_empty()
    }

    async fn select_open_candidate(
        &mut self,
        start_index: usize,
        mark: u32,
        label: &str,
    ) -> Result<(), String> {
        self.select_open_candidate_with(start_index, mark, label, |remote, mark| {
            open_marked_tokio_udp_socket(remote, mark)
        })
        .await
    }

    async fn select_open_candidate_with<F, Fut>(
        &mut self,
        start_index: usize,
        mark: u32,
        label: &str,
        mut open: F,
    ) -> Result<(), String>
    where
        F: FnMut(SocketAddr, u32) -> Fut,
        Fut: Future<Output = Result<tokio::net::UdpSocket, String>>,
    {
        let remaining = self
            .remote_candidates
            .get(start_index..)
            .ok_or_else(|| format!("open {label} UDP relay: no address candidates remain"))?;
        let (selected, socket) =
            try_socket_addr_candidates(remaining, &format!("open {label} UDP relay"), |remote| {
                open(remote, mark)
            })
            .await?;
        self.selected_index = start_index
            + remaining
                .iter()
                .position(|candidate| *candidate == selected)
                .ok_or_else(|| {
                    format!("{label} UDP relay selected an unknown address candidate")
                })?;
        self.socket = Some(socket);
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

#[cfg(test)]
mod tests;
