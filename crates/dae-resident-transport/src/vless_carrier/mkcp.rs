use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use dae_resident_core::{RESIDENT_CONNECT_TIMEOUT, set_socket_mark};
use dae_resident_model::ResidentProxyBinding;
use dae_runtime_control::AbsoluteDeadline;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::time::{self, Instant, MissedTickBehavior};

use crate::SpawnedLogicalStream;
use crate::quic_transport::resolve_proxy_udp_addr_candidates_async;

const WINDOW: u32 = 64;
const PAYLOAD_LIMIT: usize = 1182;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
const RETRANSMIT: Duration = Duration::from_millis(200);

const ACK: u8 = 0;
const DATA: u8 = 1;
const TERMINATE: u8 = 2;
const PING: u8 = 3;

pub(super) async fn open(binding: &ResidentProxyBinding) -> Result<SpawnedLogicalStream, String> {
    if binding.chain_parent.is_some() {
        return Err("VLESS mKCP does not support proxy chains".to_owned());
    }
    let deadline = AbsoluteDeadline::from_now(std::time::Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let addresses = resolve_proxy_udp_addr_candidates_async(binding.plan(), deadline).await?;
    let mut last_error = None;
    for address in addresses {
        match connect(address, binding.effective_socket_mark()).await {
            Ok(socket) => {
                let conversation = fastrand::u16(..);
                return Ok(SpawnedLogicalStream::spawn(move |io| async move {
                    drive(socket, conversation, io)
                        .await
                        .map_err(|error| format!("VLESS mKCP session: {error}"))
                }));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!("connect VLESS mKCP: {last_error:?}"))
}

async fn connect(address: SocketAddr, mark: u32) -> io::Result<UdpSocket> {
    let local = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(local).await?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)?;
    }
    socket.connect(address).await?;
    Ok(socket)
}

struct Pending {
    payload: Vec<u8>,
    started: Instant,
    last_sent: Instant,
}

struct Session {
    conversation: u16,
    send_next: u32,
    send_base: u32,
    remote_window: u32,
    pending: HashMap<u32, Pending>,
    receive_next: u32,
    received: HashMap<u32, Vec<u8>>,
    write_offset: usize,
    peer_closed: bool,
}

impl Session {
    fn new(conversation: u16) -> Self {
        Self {
            conversation,
            send_next: 0,
            send_base: 0,
            remote_window: WINDOW,
            pending: HashMap::new(),
            receive_next: 0,
            received: HashMap::new(),
            write_offset: 0,
            peer_closed: false,
        }
    }

    fn can_send(&self) -> bool {
        self.send_next.wrapping_sub(self.send_base) < WINDOW
            && before(self.send_next, self.remote_window)
    }

    fn acknowledge(&mut self, next: u32) {
        if next.wrapping_sub(self.send_base) > self.send_next.wrapping_sub(self.send_base) {
            return;
        }
        self.pending.retain(|number, _| !before(*number, next));
        while self.send_base != self.send_next && !self.pending.contains_key(&self.send_base) {
            self.send_base = self.send_base.wrapping_add(1);
        }
    }

    fn frame_header(&self, command: u8) -> [u8; 4] {
        let conversation = self.conversation.to_be_bytes();
        [conversation[0], conversation[1], command, 0]
    }

    async fn control(&self, socket: &UdpSocket, command: u8) -> io::Result<()> {
        let mut frame = [0; 16];
        frame[..4].copy_from_slice(&self.frame_header(command));
        frame[4..8].copy_from_slice(&self.send_base.to_be_bytes());
        frame[8..12].copy_from_slice(&self.receive_next.to_be_bytes());
        frame[12..16].copy_from_slice(&(RETRANSMIT.as_millis() as u32).to_be_bytes());
        socket.send(&frame).await?;
        Ok(())
    }

    async fn ack(&self, socket: &UdpSocket, number: u32, timestamp: u32) -> io::Result<()> {
        let mut frame = [0; 21];
        frame[..4].copy_from_slice(&self.frame_header(ACK));
        let end = self.receive_next.wrapping_add(WINDOW);
        frame[4..8].copy_from_slice(&end.to_be_bytes());
        frame[8..12].copy_from_slice(&self.receive_next.to_be_bytes());
        frame[12..16].copy_from_slice(&timestamp.to_be_bytes());
        frame[16] = 1;
        frame[17..21].copy_from_slice(&number.to_be_bytes());
        socket.send(&frame).await?;
        Ok(())
    }

    async fn input(&mut self, socket: &UdpSocket, mut input: &[u8]) -> io::Result<bool> {
        let mut accepted = false;
        while input.len() >= 4 && input[..2] == self.conversation.to_be_bytes() {
            let command = input[2];
            let flags = input[3];
            let len = match command {
                DATA if input.len() >= 18 => {
                    18 + u16::from_be_bytes([input[16], input[17]]) as usize
                }
                ACK if input.len() >= 17 => 17 + usize::from(input[16]) * 4,
                PING | TERMINATE => 16,
                _ => break,
            };
            if input.len() < len {
                break;
            }
            let (frame, rest) = input.split_at(len);
            input = rest;
            accepted = true;
            self.peer_closed |= flags & 1 != 0 || command == TERMINATE;
            match command {
                DATA => {
                    let number = read_u32(&frame[8..12]);
                    if number.wrapping_sub(self.receive_next) < WINDOW && len > 18 {
                        self.received
                            .entry(number)
                            .or_insert_with(|| frame[18..].to_vec());
                    }
                    if self.received.contains_key(&number) || before(number, self.receive_next) {
                        self.ack(socket, number, read_u32(&frame[4..8])).await?;
                    }
                }
                ACK => {
                    let window = read_u32(&frame[4..8]);
                    if before(self.remote_window, window) {
                        self.remote_window = window;
                    }
                    for number in frame[17..].chunks_exact(4) {
                        self.pending.remove(&read_u32(number));
                    }
                    self.acknowledge(read_u32(&frame[8..12]));
                }
                _ => {
                    self.acknowledge(read_u32(&frame[8..12]));
                }
            }
        }
        Ok(accepted)
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("mKCP integer field width"))
}

fn before(first: u32, second: u32) -> bool {
    (first.wrapping_sub(second) as i32) < 0
}

async fn send_data(
    socket: &UdpSocket,
    conversation: u16,
    base: u32,
    number: u32,
    elapsed: Duration,
    payload: &[u8],
) -> io::Result<()> {
    let mut frame = [0; PAYLOAD_LIMIT + 18];
    frame[..2].copy_from_slice(&conversation.to_be_bytes());
    frame[2] = DATA;
    frame[4..8].copy_from_slice(&(elapsed.as_millis() as u32).to_be_bytes());
    frame[8..12].copy_from_slice(&number.to_be_bytes());
    frame[12..16].copy_from_slice(&base.to_be_bytes());
    frame[16..18].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    frame[18..18 + payload.len()].copy_from_slice(payload);
    socket.send(&frame[..18 + payload.len()]).await?;
    Ok(())
}

async fn drive(socket: UdpSocket, conversation: u16, io: DuplexStream) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut session = Session::new(conversation);
    let mut uplink = [0; PAYLOAD_LIMIT];
    let mut datagram = [0; 4096];
    let started = Instant::now();
    let mut last_reply = started;
    let mut last_ping = started;
    let mut close_started = None;
    let mut uplink_closed = false;
    let mut timer = time::interval(Duration::from_millis(40));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let next_chunk = session
            .received
            .get(&session.receive_next)
            .map(|chunk| &chunk[session.write_offset..]);
        if session.peer_closed && next_chunk.is_none() {
            session.control(&socket, TERMINATE).await?;
            return writer.shutdown().await;
        }
        tokio::select! {
            result = socket.recv(&mut datagram) => {
                if session.input(&socket, &datagram[..result?]).await? {
                    last_reply = Instant::now();
                }
            }
            result = reader.read(&mut uplink), if !uplink_closed && session.can_send() => {
                let len = result?;
                if len == 0 {
                    uplink_closed = true;
                    continue;
                }
                let now = Instant::now();
                let number = session.send_next;
                send_data(&socket, conversation, session.send_base, number, now - started, &uplink[..len]).await?;
                session.pending.insert(number, Pending { payload: uplink[..len].to_vec(), started: now, last_sent: now });
                session.send_next = number.wrapping_add(1);
            }
            result = writer.write(next_chunk.unwrap_or_default()), if next_chunk.is_some() => {
                let written = result?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                session.write_offset += written;
                if written == next_chunk.unwrap().len() {
                    let number = session.receive_next;
                    session.received.remove(&number);
                    session.receive_next = number.wrapping_add(1);
                    session.write_offset = 0;
                    session.ack(&socket, number, 0).await?;
                }
            }
            _ = timer.tick() => {
                let now = Instant::now();
                if now - last_reply >= IDLE_TIMEOUT {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                for (&number, pending) in &mut session.pending {
                    if now - pending.started >= SEND_TIMEOUT {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    if now - pending.last_sent >= RETRANSMIT {
                        send_data(&socket, conversation, session.send_base, number, now - started, &pending.payload).await?;
                        pending.last_sent = now;
                    }
                }
                if uplink_closed && session.pending.is_empty() {
                    let deadline = *close_started.get_or_insert_with(|| now + Duration::from_secs(2));
                    if now >= deadline {
                        return writer.shutdown().await;
                    }
                    if now - last_ping >= RETRANSMIT {
                        session.control(&socket, TERMINATE).await?;
                        last_ping = now;
                    }
                } else if now - last_ping >= Duration::from_secs(3) {
                    session.control(&socket, PING).await?;
                    last_ping = now;
                }
            }
        }
    }
}
