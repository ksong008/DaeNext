use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use bytes::Bytes;
use dae_outbound::shared_transport::test_support::self_signed_tls_identity;
use foreign_types::ForeignType;
use h3::server;
use http::{Request, Response, StatusCode};
use quinn_boring::QuicSslContext;
use std::ffi::{CStr, c_int};

use super::super::h3_transport::{
    build_xhttp_h3_client_config, xhttp_h3_client_builder, xhttp_h3_transport_config_for_provider,
};
use super::*;

const SERVER_NAME: &str = "localhost";
static CLIENT_HELLO_RECORD: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));

fn quic_varint(buf: &mut &[u8]) -> u64 {
    let width = 1 << (buf[0] >> 6);
    let (prefix, rest) = buf.split_at(width);
    *buf = rest;
    prefix[1..]
        .iter()
        .fold(u64::from(prefix[0] & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        })
}

fn hello_extension(record: &[u8], extension: u16) -> &[u8] {
    let mut data = &record[43..];
    data = &data[usize::from(data[0]) + 1..];
    data = &data[usize::from(u16::from_be_bytes([data[0], data[1]])) + 2..];
    data = &data[usize::from(data[0]) + 3..];
    while !data.is_empty() {
        let id = u16::from_be_bytes([data[0], data[1]]);
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let (body, rest) = data[4..].split_at(len);
        if id == extension {
            return body;
        }
        data = rest;
    }
    panic!("missing ClientHello extension {extension:04x}");
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_152_quic_resumes_after_a_slow_reader() {
    use dae_outbound::shared_transport::test_support::{
        boring_quic_client_endpoint, boring_quic_server_endpoint,
    };

    const PAYLOAD: usize = 8 << 20;
    let plan = endpoint_plan();
    let profile = ResidentXhttpQuicTlsProvider::Chrome152;
    let server =
        boring_quic_server_endpoint(server_config(c"X25519"), "127.0.0.1:0".parse().unwrap())
            .unwrap();
    let mut client = boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(build_xhttp_h3_client_config(&plan, profile, None).unwrap());
    let (blocked, unblock) = tokio::sync::oneshot::channel();
    let (done, received) = tokio::sync::oneshot::channel();
    tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(
            async {
                let connection = client
                    .connect(server.local_addr().unwrap(), SERVER_NAME)
                    .unwrap()
                    .await
                    .unwrap();
                let mut stream = connection.accept_uni().await.unwrap();
                unblock.await.unwrap();
                let mut total = 0;
                while let Some(chunk) = stream.read_chunk(64 << 10, true).await.unwrap() {
                    total += chunk.bytes.len();
                    assert!(chunk.bytes.iter().all(|&byte| byte == 0x5a));
                }
                assert_eq!(total, PAYLOAD);
                assert_eq!(
                    connection.read_datagram().await.unwrap(),
                    Bytes::from_static(b"quic datagram")
                );
                done.send(()).unwrap();
            },
            async {
                let connection = server.accept().await.unwrap().await.unwrap();
                let mut stream = connection.open_uni().await.unwrap();
                let data = vec![0x5a; PAYLOAD];
                {
                    let write = stream.write_all(&data);
                    tokio::pin!(write);
                    assert!(
                        tokio::time::timeout(Duration::from_millis(50), &mut write)
                            .await
                            .is_err()
                    );
                    blocked.send(()).unwrap();
                    write.await.unwrap();
                }
                stream.finish().unwrap();
                connection
                    .send_datagram(Bytes::from_static(b"quic datagram"))
                    .unwrap();
                received.await.unwrap();
            }
        );
    })
    .await
    .unwrap();
    client.wait_idle().await;
    server.wait_idle().await;
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_152_h3_sends_bounded_settings_and_static_qpack_headers() {
    use tokio::io::AsyncReadExt;

    let server = dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
        server_config(c"X25519"),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client = dae_outbound::shared_transport::test_support::boring_quic_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let plan = endpoint_plan();
    let profile = ResidentXhttpQuicTlsProvider::Chrome152;
    client.set_default_client_config(build_xhttp_h3_client_config(&plan, profile, None).unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async {
                let connection = client
                    .connect(server.local_addr().unwrap(), SERVER_NAME)
                    .unwrap()
                    .await
                    .unwrap();
                let (_driver, mut client) = xhttp_h3_client_builder(profile)
                    .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
                let request = Request::get("https://localhost/fingerprint")
                    .body(())
                    .unwrap();
                let mut stream = client.send_request(request).await.unwrap();
                stream.finish().await.unwrap();
                assert_eq!(
                    connection.closed().await,
                    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                        error_code: 0_u32.into(),
                        reason: Bytes::new(),
                    })
                );
            },
            async {
                let connection = server.accept().await.unwrap().await.unwrap();
                loop {
                    let mut stream = connection.accept_uni().await.unwrap();
                    if stream.read_u8().await.unwrap() != 0 {
                        continue;
                    }
                    assert_eq!(stream.read_u8().await.unwrap(), 4);
                    let len = stream.read_u8().await.unwrap();
                    assert!(len <= 63, "test settings frame length {len}");
                    let mut frame = vec![0; usize::from(len)];
                    stream.read_exact(&mut frame).await.unwrap();
                    let mut body = frame.as_slice();
                    let mut settings = std::collections::BTreeMap::new();
                    while !body.is_empty() {
                        settings.insert(quic_varint(&mut body), quic_varint(&mut body));
                    }
                    assert_eq!(settings.get(&6), Some(&262_144));
                    assert_eq!(settings.get(&0x33), Some(&0));
                    assert!(!settings.contains_key(&1) && !settings.contains_key(&7));
                    assert!(
                        settings
                            .keys()
                            .any(|&id| id >= 0x21 && (id - 0x21) % 0x1f == 0)
                    );
                    break;
                }
                let (_, mut stream) = connection.accept_bi().await.unwrap();
                let frame = stream.read_to_end(4096).await.unwrap();
                let mut data = frame.as_slice();
                assert_eq!(quic_varint(&mut data), 1);
                let len = quic_varint(&mut data) as usize;
                let headers = &data[..len];
                assert_eq!(&headers[..5], &[0, 0, 0xd1, 0xd7, 0x50]);
                connection.close(0_u32.into(), b"");
            }
        );
    })
    .await
    .unwrap();
    client.wait_idle().await;
    server.wait_idle().await;
}

pub(in super::super) fn endpoint_plan() -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: SERVER_NAME.to_owned(),
        server_port: 443,
        server_name: SERVER_NAME.to_owned(),
        alpn: vec!["h3".to_owned()],
        stream_host: SERVER_NAME.to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: ResidentXhttpSettingsPlan::official_default(),
        xmux: None,
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    }
}

fn server_config(group: &CStr) -> quinn::ServerConfig {
    let identity = self_signed_tls_identity(&[SERVER_NAME]).unwrap();
    let mut crypto = quinn_boring::ServerConfig::new().unwrap();
    crypto.set_alpn(&[b"h3".to_vec()]).unwrap();
    let context = crypto.ctx_mut();
    context.set_certificate(identity.certificate).unwrap();
    context.set_private_key(identity.private_key).unwrap();
    assert_eq!(
        unsafe { boring_sys::SSL_CTX_set1_curves_list(context.as_ptr(), group.as_ptr()) },
        1
    );
    quinn_boring::helpers::server_config(Arc::new(crypto)).unwrap()
}

unsafe extern "C" fn capture_client_hello(
    is_write: c_int,
    _version: c_int,
    content_type: c_int,
    buffer: *const std::ffi::c_void,
    length: usize,
    _ssl: *mut boring_sys::SSL,
    _arg: *mut std::ffi::c_void,
) {
    if is_write != 1 || content_type != 22 || length < 4 {
        return;
    }
    let handshake = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    if handshake[0] != 1 || length > u16::MAX as usize {
        return;
    }
    let mut capture = CLIENT_HELLO_RECORD.lock().unwrap();
    if !capture.is_empty() {
        return;
    }
    capture.extend_from_slice(&[22, 3, 1]);
    capture.extend_from_slice(&(length as u16).to_be_bytes());
    capture.extend_from_slice(handshake);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chrome_profiles_complete_h3_with_x25519_and_hybrid_peers() {
    for (provider, expected_shares, server_group) in [
        (
            ResidentXhttpQuicTlsProvider::ChromeBoring,
            &[29_u16][..],
            c"X25519",
        ),
        (
            ResidentXhttpQuicTlsProvider::ChromeBoringHybrid,
            &[0x11ec, 29][..],
            c"X25519",
        ),
        (
            ResidentXhttpQuicTlsProvider::ChromeBoringHybrid,
            &[0x11ec, 29][..],
            c"X25519MLKEM768",
        ),
        (
            ResidentXhttpQuicTlsProvider::Chrome152,
            &[0x11ec, 29][..],
            c"X25519",
        ),
        (
            ResidentXhttpQuicTlsProvider::Chrome152,
            &[0x11ec, 29][..],
            c"X25519MLKEM768",
        ),
    ] {
        check_chrome_client_hello(provider, expected_shares, server_group).await;
    }
}

async fn check_chrome_client_hello(
    tls_provider: ResidentXhttpQuicTlsProvider,
    expected_shares: &[u16],
    server_group: &CStr,
) {
    CLIENT_HELLO_RECORD.lock().unwrap().clear();
    let server_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config(server_group),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accepting_endpoint = server_endpoint.clone();
    let (server_release, wait_for_client) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let connection = accepting_endpoint.accept().await.unwrap().await.unwrap();
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut incoming: server::Connection<h3_quinn::Connection, Bytes> =
            server::Connection::new(h3_connection).await.unwrap();
        let request = incoming.accept().await.unwrap().unwrap();
        let (request, mut stream) = request.resolve_request().await.unwrap();
        assert_eq!(request.uri().path(), "/fingerprint");
        while stream.recv_data().await.unwrap().is_some() {}
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let _ = wait_for_client.await;
    });

    let plan = endpoint_plan();
    let policy = xhttp_h3_boring_policy(&plan, tls_provider).unwrap();
    let mut crypto =
        dae_outbound_quic::boring_quic::build_boring_quic_client_crypto(&policy).unwrap();
    unsafe {
        boring_sys::SSL_CTX_set_msg_callback(crypto.ctx_mut().as_ptr(), Some(capture_client_hello));
    }
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(
        xhttp_h3_transport_config_for_provider(&plan, tls_provider).unwrap(),
    ));
    let mut client_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
        )
        .unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connection = client_endpoint
        .connect(server_address, SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let handshake = connection
        .handshake_data()
        .unwrap()
        .downcast::<quinn_boring::HandshakeData>()
        .unwrap();
    assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));

    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut client) = xhttp_h3_client_builder(tls_provider)
        .build::<_, _, Bytes>(h3_connection)
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
    });
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://{SERVER_NAME}/fingerprint"))
        .body(())
        .unwrap();
    let mut stream = client.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = server_release.send(());
    server_task.await.unwrap();

    let record = CLIENT_HELLO_RECORD.lock().unwrap().clone();
    let profile = dae_outbound::shared_transport::parse_utls_client_hello_record(&record).unwrap();
    assert_eq!(profile.alpn, Some(vec!["h3".to_owned()]));
    let extensions = numeric_profile_values(&profile.extension_types);
    for required in [10, 13, 27, 43, 51, 57] {
        assert!(
            extensions.contains(&required),
            "missing QUIC Chrome ClientHello extension {required}: {extensions:?}"
        );
    }
    let groups = numeric_profile_values(profile.supported_groups.as_ref().unwrap());
    for required in [23, 24, 29] {
        assert!(
            groups.contains(&required),
            "missing group {required}: {groups:?}"
        );
    }
    if tls_provider == ResidentXhttpQuicTlsProvider::Chrome152 {
        for required in [0x12e0, 0x44cd, 0xfe0d] {
            assert!(extensions.contains(&required), "missing {required:04x}");
        }
        assert_eq!(hello_extension(&record, 0x12e0), [0, 0]);
        assert_eq!(hello_extension(&record, 0x44cd), [0, 3, 2, b'h', b'3']);
        assert!(!extensions.iter().copied().any(is_grease));
        assert!(!groups.iter().copied().any(is_grease));
        assert_eq!(
            numeric_profile_values(profile.signature_schemes.as_ref().unwrap()),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201
            ]
        );
        let params = hello_extension(&record, 57);
        let mut pending = params;
        let mut seen = std::collections::BTreeMap::new();
        while !pending.is_empty() {
            let id = quic_varint(&mut pending);
            let len = quic_varint(&mut pending) as usize;
            let (mut body, rest) = pending.split_at(len);
            pending = rest;
            if matches!(id, 4..=9 | 32) {
                seen.insert(id, quic_varint(&mut body));
                assert!(body.is_empty());
            }
        }
        assert_eq!(
            seen,
            [
                (4, 15 << 20),
                (5, 6 << 20),
                (6, 6 << 20),
                (7, 6 << 20),
                (8, 100),
                (9, 103),
                (32, 65_535)
            ]
            .into()
        );
    } else {
        assert!(extensions.iter().copied().any(is_grease));
        assert!(extensions.contains(&5) && extensions.contains(&18));
        assert!(groups.iter().copied().any(is_grease));
    }
    let shares: Vec<_> = numeric_profile_values(profile.key_share_groups.as_ref().unwrap())
        .into_iter()
        .filter(|group| !is_grease(*group))
        .collect();
    assert_eq!(shares, expected_shares);
    let versions = numeric_profile_values(profile.supported_versions.as_ref().unwrap());
    assert!(versions.contains(&0x0304));

    connection.close(0_u32.into(), b"xhttp h3 boring test complete");
    driver_task.abort();
    client_endpoint.wait_idle().await;
    server_endpoint.close(0_u32.into(), b"xhttp h3 boring test complete");
    server_endpoint.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chrome_boring_provider_rejects_untrusted_certificate_without_fallback() {
    let server_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config(c"X25519"),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accepting_endpoint = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        if let Some(connecting) = accepting_endpoint.accept().await {
            let _ = connecting.await;
        }
    });

    let mut plan = endpoint_plan();
    plan.allow_insecure = false;
    let client_config = build_xhttp_h3_client_config(
        &plan,
        ResidentXhttpQuicTlsProvider::ChromeBoringHybrid,
        None,
    )
    .unwrap();
    let mut client_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
        )
        .unwrap();
    client_endpoint.set_default_client_config(client_config);
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        client_endpoint
            .connect(server_address, SERVER_NAME)
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        error.to_string().contains("peer")
            || error.to_string().contains("certificate")
            || error.to_string().contains("crypto"),
        "unexpected BoringSSL verification failure: {error}"
    );

    client_endpoint.close(0_u32.into(), b"xhttp h3 verification test complete");
    client_endpoint.wait_idle().await;
    server_endpoint.close(0_u32.into(), b"xhttp h3 verification test complete");
    server_endpoint.wait_idle().await;
    server_task.await.unwrap();
}

fn numeric_profile_values(values: &[String]) -> Vec<u16> {
    values
        .iter()
        .map(|value| u16::from_str_radix(value.trim_start_matches("0x"), 16).unwrap())
        .collect()
}

const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}
