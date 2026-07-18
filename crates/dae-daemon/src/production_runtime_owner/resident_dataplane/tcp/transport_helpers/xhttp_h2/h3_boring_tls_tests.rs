use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h3::server;
use http::{Request, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::*;

const SERVER_NAME: &str = "localhost";
static CLIENT_HELLO_RECORD: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));

fn endpoint_plan() -> ResidentXhttpEndpointPlan {
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
        reality: None,
    }
}

fn server_config() -> quinn::ServerConfig {
    let certified = generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()))
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
async fn chrome_boring_provider_completes_h3_and_emits_quic_client_hello() {
    CLIENT_HELLO_RECORD.lock().unwrap().clear();
    let server_endpoint =
        quinn::Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
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
    let mut crypto = build_chrome_boring_xhttp_h3_crypto(&plan).unwrap();
    unsafe {
        boring_sys::SSL_CTX_set_msg_callback(crypto.ctx_mut().as_ptr(), Some(capture_client_hello));
    }
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(xhttp_h3_transport_config().unwrap()));
    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
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
    let (mut driver, mut client) = h3::client::new(h3_connection).await.unwrap();
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
    for required in [5, 10, 13, 18, 27, 43, 51, 57] {
        assert!(
            extensions.contains(&required),
            "missing QUIC Chrome ClientHello extension {required}: {extensions:?}"
        );
    }
    assert!(extensions.iter().copied().any(is_grease));
    let groups = numeric_profile_values(profile.supported_groups.as_ref().unwrap());
    for required in [23, 24, 29] {
        assert!(
            groups.contains(&required),
            "missing group {required}: {groups:?}"
        );
    }
    assert!(groups.iter().copied().any(is_grease));
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
        quinn::Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accepting_endpoint = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        if let Some(connecting) = accepting_endpoint.accept().await {
            let _ = connecting.await;
        }
    });

    let mut plan = endpoint_plan();
    plan.allow_insecure = false;
    let client_config = build_chrome_boring_xhttp_h3_client_config(&plan).unwrap();
    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
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
