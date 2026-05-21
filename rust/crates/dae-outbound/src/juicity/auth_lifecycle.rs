use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::error::OutboundError;

use super::auth_stream::{
    JUICITY_AUTHENTICATE_HEADER_LEN, build_authenticate_header,
    build_deterministic_authenticate_header,
};
use super::auth_stream_ekm::{DEFAULT_LIVE_EKM_AUTH_PASSWORD, export_juicity_auth_token};
use super::auth_stream_live::{build_live_client_config, build_live_server_config, selected_alpn};
use super::contract::UNDERLAY_AUTH_CHANNEL_CAPACITY;
use super::h3_loopback::{
    DEFAULT_H3_ALPN, DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS, DEFAULT_H3_KEEPALIVE_SECS,
    DEFAULT_H3_SERVER_NAME,
};
use super::packet::{
    JUICITY_UNDERLAY_AUTH_IV_LEN, JUICITY_UNDERLAY_AUTH_PSK_LEN, JuicityDialAuthRecord,
    build_dialauth_record_for_port_zero,
};

pub const DEFAULT_AUTH_LIFECYCLE_TARGETS: [&str; 3] = [
    "stage124-zero-a.example:0",
    "stage124-zero-b.example:0",
    "stage124-zero-c.example:0",
];
pub const DEFAULT_AUTH_LIFECYCLE_RECORD_COUNT: usize = DEFAULT_AUTH_LIFECYCLE_TARGETS.len();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityAuthLifecycleOptions {
    pub server_name: String,
    pub targets: Vec<String>,
    pub password: Vec<u8>,
    pub iterations: usize,
    pub timeout: Duration,
}

impl Default for JuicityAuthLifecycleOptions {
    fn default() -> Self {
        Self {
            server_name: DEFAULT_H3_SERVER_NAME.to_owned(),
            targets: DEFAULT_AUTH_LIFECYCLE_TARGETS
                .iter()
                .map(|target| (*target).to_owned())
                .collect(),
            password: DEFAULT_LIVE_EKM_AUTH_PASSWORD.as_bytes().to_vec(),
            iterations: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct JuicityAuthLifecycleReport {
    pub server_name: String,
    pub targets: Vec<String>,
    pub alpn_protocol: String,
    pub client_selected_alpn: String,
    pub server_selected_alpn: String,
    pub tls13_only_configured: bool,
    pub quic_datagram_disabled: bool,
    pub keepalive_secs: u64,
    pub handshake_idle_timeout_secs: u64,
    pub loopback_addr: String,
    pub iterations: usize,
    pub elapsed_ns: u128,
    pub ns_per_juicity_auth_lifecycle_exchange: f64,
    pub ekm_label_len: usize,
    pub ekm_context_len: usize,
    pub ekm_token_len: usize,
    pub client_ekm_token_nonzero: bool,
    pub server_ekm_token_exported: bool,
    pub authenticate_header_len: usize,
    pub record_count: usize,
    pub dialauth_record_lens: Vec<usize>,
    pub dialauth_metadata_offsets: Vec<usize>,
    pub transcript_len: usize,
    pub auth_header_offset: usize,
    pub first_dialauth_record_offset: usize,
    pub last_dialauth_record_end: usize,
    pub underlay_auth_channel_capacity: u64,
    pub channel_enqueue_count: usize,
    pub channel_receive_count: usize,
    pub channel_closed_after_records: bool,
    pub auth_header_written_first: bool,
    pub underlay_auth_channel_order_validated: bool,
    pub multiple_dialauth_records_over_auth_stream_validated: bool,
    pub open_uni_stream_count: usize,
    pub uni_stream_finish_count: usize,
    pub uni_stream_acked_count: usize,
    pub server_received_count: usize,
    pub server_received_len: usize,
    pub server_read_to_end_count: usize,
    pub server_transcript_match_count: usize,
    pub quic_handshake_validated: bool,
    pub auth_stream_finish_boundary_validated: bool,
    pub send_authentication_lifecycle_validated: bool,
    pub juicity_send_authentication_lifecycle_admitted: bool,
    pub juicity_underlay_auth_channel_order_admitted: bool,
    pub juicity_multiple_dialauth_records_over_auth_stream_admitted: bool,
    pub juicity_auth_stream_finish_boundary_admitted: bool,
    pub juicity_dialauth_over_h3_admitted: bool,
    pub juicity_transport_packet_conn_dataplane_admitted: bool,
    pub juicity_stream_packet_conn_dataplane_admitted: bool,
    pub juicity_true_quic_h3_dataplane_admitted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JuicityAuthLifecycleTranscript {
    targets: Vec<String>,
    record_count: usize,
    dialauth_record_lens: Vec<usize>,
    dialauth_record_offsets: Vec<usize>,
    dialauth_metadata_offsets: Vec<usize>,
    transcript: Vec<u8>,
    transcript_len: usize,
    auth_header_offset: usize,
    first_dialauth_record_offset: usize,
    last_dialauth_record_end: usize,
    auth_header_written_first: bool,
    dialauth_records_match: bool,
    dialauth_record_order_valid: bool,
}

pub fn run_auth_lifecycle_smoke(
    options: &JuicityAuthLifecycleOptions,
) -> Result<JuicityAuthLifecycleReport, OutboundError> {
    if options.iterations == 0 {
        return Err(bad_auth_lifecycle(
            "stage124 auth lifecycle iterations must be greater than zero",
        ));
    }
    if options.password.is_empty() {
        return Err(bad_auth_lifecycle(
            "stage124 auth lifecycle password cannot be empty",
        ));
    }
    if options.targets.is_empty() {
        return Err(bad_auth_lifecycle(
            "stage124 auth lifecycle requires at least one DialAuth target",
        ));
    }
    if options.targets.len() > UNDERLAY_AUTH_CHANNEL_CAPACITY as usize {
        return Err(bad_auth_lifecycle(format!(
            "stage124 auth lifecycle targets exceed channel capacity: got {}, capacity {}",
            options.targets.len(),
            UNDERLAY_AUTH_CHANNEL_CAPACITY
        )));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| bad_auth_lifecycle(format!("build tokio runtime: {err}")))?;
    runtime.block_on(async {
        tokio::time::timeout(options.timeout, run_auth_lifecycle_smoke_async(options))
            .await
            .map_err(|_| bad_auth_lifecycle("stage124 auth lifecycle timed out"))?
    })
}

async fn run_auth_lifecycle_smoke_async(
    options: &JuicityAuthLifecycleOptions,
) -> Result<JuicityAuthLifecycleReport, OutboundError> {
    let seed_header = build_deterministic_authenticate_header();
    let uuid = seed_header.uuid;
    let records = build_dialauth_records(&options.targets)?;

    let server_endpoint = quinn::Endpoint::server(
        build_live_server_config(&options.server_name)?,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .map_err(|err| bad_auth_lifecycle(format!("create server endpoint: {err}")))?;
    let loopback_addr = server_endpoint
        .local_addr()
        .map_err(|err| bad_auth_lifecycle(format!("server local addr: {err}")))?;
    let server_iterations = options.iterations;
    let server_targets = options.targets.clone();
    let server_password = options.password.clone();
    let server_task = tokio::spawn(async move {
        run_auth_lifecycle_server(
            server_endpoint,
            uuid,
            server_password,
            server_targets,
            server_iterations,
        )
        .await
    });

    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(|err| bad_auth_lifecycle(format!("create client endpoint: {err}")))?;
    client_endpoint.set_default_client_config(build_live_client_config()?);
    let client_connection = client_endpoint
        .connect(loopback_addr, &options.server_name)
        .map_err(|err| bad_auth_lifecycle(format!("connect auth lifecycle loopback: {err}")))?
        .await
        .map_err(|err| {
            bad_auth_lifecycle(format!("await auth lifecycle loopback connect: {err}"))
        })?;
    let client_selected_alpn = selected_alpn(&client_connection);
    let client_token = export_juicity_auth_token(&client_connection, &uuid, &options.password)?;
    let client_ekm_token_nonzero = client_token.iter().any(|byte| *byte != 0);
    let header = build_authenticate_header(uuid, client_token, "quic-tls-export-keying-material");
    let transcript = build_auth_lifecycle_transcript(&header.encoded, &records);

    let start = Instant::now();
    let mut open_uni_stream_count = 0_usize;
    let mut uni_stream_finish_count = 0_usize;
    let mut uni_stream_acked_count = 0_usize;
    let mut channel_enqueue_count = 0_usize;
    let mut channel_receive_count = 0_usize;
    let mut channel_closed_after_records = true;
    let mut underlay_auth_channel_order_validated = true;
    for _ in 0..options.iterations {
        let write = send_authentication_once(&client_connection, &header.encoded, &records).await?;
        open_uni_stream_count += 1;
        if write.stream_finished {
            uni_stream_finish_count += 1;
        }
        if write.stream_acked {
            uni_stream_acked_count += 1;
        }
        channel_enqueue_count += write.channel_enqueue_count;
        channel_receive_count += write.channel_receive_count;
        channel_closed_after_records &= write.channel_closed_after_records;
        underlay_auth_channel_order_validated &=
            write.record_targets == transcript.targets && write.stream_finished;
    }
    let elapsed_ns = start.elapsed().as_nanos();
    client_connection.close(0_u32.into(), b"stage124 done");
    client_endpoint.wait_idle().await;

    let server = server_task
        .await
        .map_err(|err| bad_auth_lifecycle(format!("join auth lifecycle server task: {err}")))??;
    let quic_handshake_validated =
        client_selected_alpn == DEFAULT_H3_ALPN && server.selected_alpn == DEFAULT_H3_ALPN;
    let expected_channel_record_total = options.iterations * records.len();
    underlay_auth_channel_order_validated &= channel_enqueue_count == expected_channel_record_total
        && channel_receive_count == expected_channel_record_total
        && channel_closed_after_records;
    let multiple_records_validated = records.len() > 1
        && transcript.dialauth_records_match
        && transcript.dialauth_record_order_valid
        && server.transcript_match_count == options.iterations;
    let auth_stream_finish_boundary_validated = uni_stream_finish_count == options.iterations
        && uni_stream_acked_count == options.iterations
        && server.read_to_end_count == options.iterations
        && server.last_received_len == transcript.transcript_len;
    let send_authentication_lifecycle_validated = quic_handshake_validated
        && client_ekm_token_nonzero
        && server.ekm_token_exported
        && open_uni_stream_count == options.iterations
        && underlay_auth_channel_order_validated
        && multiple_records_validated
        && auth_stream_finish_boundary_validated
        && server.received_count == options.iterations;

    Ok(JuicityAuthLifecycleReport {
        server_name: options.server_name.clone(),
        targets: transcript.targets,
        alpn_protocol: DEFAULT_H3_ALPN.to_owned(),
        client_selected_alpn,
        server_selected_alpn: server.selected_alpn,
        tls13_only_configured: true,
        quic_datagram_disabled: true,
        keepalive_secs: DEFAULT_H3_KEEPALIVE_SECS,
        handshake_idle_timeout_secs: DEFAULT_H3_HANDSHAKE_IDLE_TIMEOUT_SECS,
        loopback_addr: loopback_addr.to_string(),
        iterations: options.iterations,
        elapsed_ns,
        ns_per_juicity_auth_lifecycle_exchange: elapsed_ns as f64 / options.iterations as f64,
        ekm_label_len: uuid.len(),
        ekm_context_len: options.password.len(),
        ekm_token_len: client_token.len(),
        client_ekm_token_nonzero,
        server_ekm_token_exported: server.ekm_token_exported,
        authenticate_header_len: header.encoded.len(),
        record_count: transcript.record_count,
        dialauth_record_lens: transcript.dialauth_record_lens,
        dialauth_metadata_offsets: transcript.dialauth_metadata_offsets,
        transcript_len: transcript.transcript_len,
        auth_header_offset: transcript.auth_header_offset,
        first_dialauth_record_offset: transcript.first_dialauth_record_offset,
        last_dialauth_record_end: transcript.last_dialauth_record_end,
        underlay_auth_channel_capacity: UNDERLAY_AUTH_CHANNEL_CAPACITY,
        channel_enqueue_count,
        channel_receive_count,
        channel_closed_after_records,
        auth_header_written_first: transcript.auth_header_written_first,
        underlay_auth_channel_order_validated,
        multiple_dialauth_records_over_auth_stream_validated: multiple_records_validated,
        open_uni_stream_count,
        uni_stream_finish_count,
        uni_stream_acked_count,
        server_received_count: server.received_count,
        server_received_len: server.last_received_len,
        server_read_to_end_count: server.read_to_end_count,
        server_transcript_match_count: server.transcript_match_count,
        quic_handshake_validated,
        auth_stream_finish_boundary_validated,
        send_authentication_lifecycle_validated,
        juicity_send_authentication_lifecycle_admitted: send_authentication_lifecycle_validated,
        juicity_underlay_auth_channel_order_admitted: underlay_auth_channel_order_validated,
        juicity_multiple_dialauth_records_over_auth_stream_admitted: multiple_records_validated,
        juicity_auth_stream_finish_boundary_admitted: auth_stream_finish_boundary_validated,
        juicity_dialauth_over_h3_admitted: false,
        juicity_transport_packet_conn_dataplane_admitted: false,
        juicity_stream_packet_conn_dataplane_admitted: false,
        juicity_true_quic_h3_dataplane_admitted: false,
    })
}

#[derive(Debug)]
struct AuthLifecycleWriteReport {
    record_targets: Vec<String>,
    channel_enqueue_count: usize,
    channel_receive_count: usize,
    channel_closed_after_records: bool,
    stream_finished: bool,
    stream_acked: bool,
}

async fn send_authentication_once(
    connection: &quinn::Connection,
    header: &[u8],
    records: &[JuicityDialAuthRecord],
) -> Result<AuthLifecycleWriteReport, OutboundError> {
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|err| bad_auth_lifecycle(format!("open auth lifecycle uni stream: {err}")))?;
    stream
        .write_all(header)
        .await
        .map_err(|err| bad_auth_lifecycle(format!("write auth lifecycle header: {err}")))?;

    let (sender, mut receiver) =
        mpsc::channel::<JuicityDialAuthRecord>(UNDERLAY_AUTH_CHANNEL_CAPACITY as usize);
    let mut channel_enqueue_count = 0_usize;
    for record in records {
        sender
            .send(record.clone())
            .await
            .map_err(|err| bad_auth_lifecycle(format!("enqueue underlay auth: {err:?}")))?;
        channel_enqueue_count += 1;
    }
    drop(sender);

    let mut record_targets = Vec::with_capacity(records.len());
    let mut channel_receive_count = 0_usize;
    while let Some(record) = receiver.recv().await {
        stream.write_all(&record.packed).await.map_err(|err| {
            bad_auth_lifecycle(format!("write auth lifecycle DialAuth record: {err}"))
        })?;
        record_targets.push(record.target);
        channel_receive_count += 1;
    }
    let channel_closed_after_records = channel_receive_count == channel_enqueue_count;

    stream
        .finish()
        .map_err(|err| bad_auth_lifecycle(format!("finish auth lifecycle uni stream: {err}")))?;
    let stream_acked = stream
        .stopped()
        .await
        .map_err(|err| bad_auth_lifecycle(format!("wait auth lifecycle uni stream ack: {err}")))?
        .is_none();
    Ok(AuthLifecycleWriteReport {
        record_targets,
        channel_enqueue_count,
        channel_receive_count,
        channel_closed_after_records,
        stream_finished: true,
        stream_acked,
    })
}

#[derive(Debug)]
struct AuthLifecycleServerReport {
    selected_alpn: String,
    ekm_token_exported: bool,
    received_count: usize,
    last_received_len: usize,
    read_to_end_count: usize,
    transcript_match_count: usize,
}

async fn run_auth_lifecycle_server(
    endpoint: quinn::Endpoint,
    uuid: [u8; 16],
    password: Vec<u8>,
    targets: Vec<String>,
    iterations: usize,
) -> Result<AuthLifecycleServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_auth_lifecycle("server accept returned none"))?
        .await
        .map_err(|err| bad_auth_lifecycle(format!("server accept auth lifecycle: {err}")))?;
    let selected_alpn = selected_alpn(&connection);
    let server_token = export_juicity_auth_token(&connection, &uuid, &password)?;
    let header = build_authenticate_header(uuid, server_token, "quic-tls-export-keying-material");
    let records = build_dialauth_records(&targets)?;
    let expected = build_auth_lifecycle_transcript(&header.encoded, &records).transcript;

    let mut received_count = 0_usize;
    let mut last_received_len = 0_usize;
    let mut read_to_end_count = 0_usize;
    let mut transcript_match_count = 0_usize;
    for _ in 0..iterations {
        let mut stream = connection.accept_uni().await.map_err(|err| {
            bad_auth_lifecycle(format!("accept auth lifecycle uni stream: {err}"))
        })?;
        let received = stream
            .read_to_end(expected.len())
            .await
            .map_err(|err| bad_auth_lifecycle(format!("read auth lifecycle uni stream: {err}")))?;
        read_to_end_count += 1;
        received_count += 1;
        last_received_len = received.len();
        if received == expected {
            transcript_match_count += 1;
        }
    }
    endpoint.wait_idle().await;
    Ok(AuthLifecycleServerReport {
        selected_alpn,
        ekm_token_exported: true,
        received_count,
        last_received_len,
        read_to_end_count,
        transcript_match_count,
    })
}

fn build_dialauth_records(targets: &[String]) -> Result<Vec<JuicityDialAuthRecord>, OutboundError> {
    targets
        .iter()
        .map(|target| build_dialauth_record_for_port_zero(target))
        .collect()
}

fn build_auth_lifecycle_transcript(
    header: &[u8],
    records: &[JuicityDialAuthRecord],
) -> JuicityAuthLifecycleTranscript {
    let mut transcript = Vec::with_capacity(
        header.len()
            + records
                .iter()
                .map(|record| record.packed.len())
                .sum::<usize>(),
    );
    transcript.extend_from_slice(header);

    let mut targets = Vec::with_capacity(records.len());
    let mut dialauth_record_lens = Vec::with_capacity(records.len());
    let mut dialauth_record_offsets = Vec::with_capacity(records.len());
    let mut dialauth_metadata_offsets = Vec::with_capacity(records.len());
    let mut offset = header.len();
    for record in records {
        targets.push(record.target.clone());
        dialauth_record_lens.push(record.packed.len());
        dialauth_record_offsets.push(offset);
        dialauth_metadata_offsets
            .push(offset + JUICITY_UNDERLAY_AUTH_IV_LEN + JUICITY_UNDERLAY_AUTH_PSK_LEN);
        transcript.extend_from_slice(&record.packed);
        offset += record.packed.len();
    }

    let auth_header_written_first = transcript.get(..header.len()) == Some(header);
    let dialauth_records_match =
        records
            .iter()
            .zip(dialauth_record_offsets.iter())
            .all(|(record, offset)| {
                transcript.get(*offset..*offset + record.packed.len())
                    == Some(record.packed.as_slice())
            });
    let dialauth_record_order_valid = dialauth_record_offsets
        .iter()
        .copied()
        .zip(records.iter())
        .scan(
            JUICITY_AUTHENTICATE_HEADER_LEN,
            |expected_offset, (offset, record)| {
                let valid = offset == *expected_offset;
                *expected_offset += record.packed.len();
                Some(valid)
            },
        )
        .all(|valid| valid)
        && transcript.len() == offset
        && dialauth_records_match;

    JuicityAuthLifecycleTranscript {
        targets,
        record_count: records.len(),
        dialauth_record_lens,
        dialauth_record_offsets,
        dialauth_metadata_offsets,
        transcript_len: transcript.len(),
        transcript,
        auth_header_offset: 0,
        first_dialauth_record_offset: header.len(),
        last_dialauth_record_end: offset,
        auth_header_written_first,
        dialauth_records_match,
        dialauth_record_order_valid,
    }
}

fn bad_auth_lifecycle(message: impl Into<String>) -> OutboundError {
    OutboundError::BadJuicity(message.into())
}
