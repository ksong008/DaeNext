//! Opt-in interoperability against an external, unmodified Xray binary.
use super::*;
use bytes::Bytes;
use dae_resident_transport::{
    XhttpDownloadClient, XhttpH1UploadPool, XhttpPacketUpPipeline, XhttpUploadClient,
    close_xhttp_download_client, close_xhttp_stream_upload_client, close_xhttp_upload_client,
    open_xhttp_packet_up_parts, open_xhttp_stream_parts, read_xhttp_download_data,
    send_xhttp_packet_up_request, send_xhttp_stream_data,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

const UUID: &str = "01010101-0101-4101-8101-010101010101";
const KEY: [u8; 16] = [1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1];

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn echo_server() -> (u16, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    stream.set_nodelay(true).unwrap();
                    tasks.spawn(async move {
                        let (mut reader, mut writer) = stream.into_split();
                        let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    (port, Task(task))
}

async fn forwarder(destination: u16) -> (u16, Arc<AtomicUsize>, Task) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut incoming, _) = accepted.unwrap();
                    incoming.set_nodelay(true).unwrap();
                    counter.fetch_add(1, Ordering::Relaxed);
                    tasks.spawn(async move {
                        let mut outgoing = TcpStream::connect(("127.0.0.1", destination)).await.unwrap();
                        outgoing.set_nodelay(true).unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    (port, count, Task(task))
}

fn request(port: u16, payload: &[u8]) -> Bytes {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&KEY);
    bytes.extend_from_slice(&[0, 1]); // addons length, TCP command
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(&[1, 127, 0, 0, 1]);
    bytes.extend_from_slice(payload);
    Bytes::from(bytes)
}

async fn receive(download: &mut XhttpDownloadClient, expected: &[u8]) {
    let mut output = Vec::new();
    while output.len() < expected.len() {
        let bytes =
            tokio::time::timeout(Duration::from_secs(5), read_xhttp_download_data(download))
                .await
                .expect("download timeout")
                .unwrap()
                .expect("early EOF");
        output.extend_from_slice(&bytes);
    }
    assert_eq!(output, expected);
}

fn binding(port: u16, alpn: &str, mode: &str, extra: Value) -> ResidentProxyBinding {
    let mut url = url::Url::parse(&format!("vless://{UUID}@127.0.0.1:{port}")).unwrap();
    url.query_pairs_mut().extend_pairs([
        ("security", "tls"),
        ("type", "xhttp"),
        ("sni", "localhost"),
        ("allowInsecure", "1"),
        ("alpn", alpn),
        ("mode", mode),
        ("path", "/exact?token=a%20b"),
        ("extra", &extra.to_string()),
    ]);
    binding_from_url(url)
}

fn binding_from_url(url: url::Url) -> ResidentProxyBinding {
    let config = parse_config(
        "global {\nlan_interface: lo\nallow_insecure: false\nso_mark_from_dae: 1234\nmptcp: false\n}\nrouting {\nfallback: direct\n}",
    );
    let mut plan = build_resident_proxy_plan_for_node(
        &config,
        "proxy".into(),
        "official-xhttp".into(),
        url.to_string(),
    )
    .unwrap();
    plan.materialize_execution();
    ResidentProxyBinding::resident(
        Arc::new(plan),
        dae_runtime_control::OwnerGeneration::new(991001),
    )
    .unwrap()
    .without_persistent_xhttp_reuse()
}

async fn start_xray(binary: &Path, dir: &Path, alpn: &str, mut settings: Value) -> (u16, Process) {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    settings["path"] = json!("/exact?token=a%20b");
    let config = json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
            "settings":{"clients":[{"id":UUID}],"decryption":"none"},
            "streamSettings":{"network":"xhttp","security":"tls",
                "tlsSettings":{"alpn":[alpn],"certificates":[{"certificateFile":dir.join("cert.pem"),"keyFile":dir.join("key.pem")}]},
                "xhttpSettings":settings}}],
        "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]
    });
    let child = run_xray(binary, dir, alpn, port, config).await;
    (port, child)
}

async fn run_xray(binary: &Path, dir: &Path, alpn: &str, port: u16, config: Value) -> Process {
    let config_path = dir.join("server.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(dir.join("server.log")).unwrap();
    let mut child = Process(
        Command::new(binary)
            .args(["run", "-c"])
            .arg(config_path)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "Xray exited: {}",
            std::fs::read_to_string(dir.join("server.log")).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
        if alpn != "h3" && TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return child;
        }
    }
    child
}

fn case_dir(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    for file in ["cert.pem", "key.pem"] {
        std::fs::copy(root.join(file), dir.join(file)).unwrap();
    }
    dir
}

async fn exchange(binding: &ResidentProxyBinding, echo_port: u16) {
    let payload = vec![0x42; 2048];
    let mut first_response = vec![0, 0];
    first_response.extend_from_slice(&payload);
    if binding.plan().xhttp_mode == ResidentXhttpMode::PacketUp {
        let mut parts = open_xhttp_packet_up_parts(binding, false).await.unwrap();
        send_xhttp_packet_up_request(
            &mut parts.upload,
            &parts.session_id,
            0,
            request(echo_port, &payload),
        )
        .await
        .unwrap();
        receive(&mut parts.download, &first_response).await;
        send_xhttp_packet_up_request(
            &mut parts.upload,
            &parts.session_id,
            1,
            Bytes::from(payload.clone()),
        )
        .await
        .unwrap();
        receive(&mut parts.download, &payload).await;
        close_xhttp_upload_client(parts.upload).await;
        close_xhttp_download_client(parts.download).await;
    } else {
        let mut parts = open_xhttp_stream_parts(binding, false, request(echo_port, &payload))
            .await
            .unwrap();
        receive(&mut parts.download, &first_response).await;
        send_xhttp_stream_data(&mut parts.upload, Bytes::from(payload.clone()), false)
            .await
            .unwrap();
        receive(&mut parts.download, &payload).await;
        close_xhttp_stream_upload_client(parts.upload).await;
        close_xhttp_download_client(parts.download).await;
    }
}

async fn exchange_large_packet(binding: &ResidentProxyBinding, echo_port: u16) -> u64 {
    // Exceeds the official default; one unsplit POST is rejected by Xray.
    let payload = (0..1_200_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let mut expected = vec![0, 0];
    expected.extend_from_slice(&payload);
    let mut parts = open_xhttp_packet_up_parts(binding, false).await.unwrap();
    let mut pipeline = XhttpPacketUpPipeline::for_upload(&parts.upload);
    assert_eq!(pipeline.max_post_bytes(), 1_000_000);
    let mut seq = 0;
    let upload = async {
        pipeline
            .send(
                &mut parts.upload,
                &parts.session_id,
                &mut seq,
                request(echo_port, &payload),
            )
            .await
            .unwrap();
        pipeline.finish().await.unwrap();
    };
    // Read concurrently so large echoes cannot block the upload's flow control.
    tokio::join!(upload, receive(&mut parts.download, &expected));
    assert_eq!(seq, 2);
    close_xhttp_upload_client(parts.upload).await;
    close_xhttp_download_client(parts.download).await;
    seq
}

async fn start_reality_target(dir: &Path) -> (u16, Process) {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let log = std::fs::File::create(dir.join("target.log")).unwrap();
    let mut process = Process(
        Command::new("openssl")
            .args([
                "s_server", "-quiet", "-www", "-tls1_3", "-alpn", "h2", "-groups", "X25519",
                "-accept",
            ])
            .arg(format!("127.0.0.1:{port}"))
            .arg("-cert")
            .arg(dir.join("cert.pem"))
            .arg("-key")
            .arg(dir.join("key.pem"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "local TLS target exited"
        );
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return (port, process);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("local TLS target did not become ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "requires DAENEXT_XRAY_BIN, DAENEXT_XHTTP_EVIDENCE_DIR and openssl"]
async fn xhttp_official_server_zero_post_and_reality_password() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let binary = PathBuf::from(std::env::var("DAENEXT_XRAY_BIN").expect("DAENEXT_XRAY_BIN"));
    let root = PathBuf::from(
        std::env::var("DAENEXT_XHTTP_EVIDENCE_DIR").expect("DAENEXT_XHTTP_EVIDENCE_DIR"),
    )
    .join("zero-and-reality");
    std::fs::create_dir_all(&root).unwrap();
    let identity = dae_outbound::shared_transport::test_support::self_signed_tls_identity(&[
        "localhost",
        "127.0.0.1",
    ])
    .unwrap();
    std::fs::write(
        root.join("cert.pem"),
        identity.certificate.to_pem().unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("key.pem"),
        identity.private_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let (echo_port, _echo) = echo_server().await;
    let mut results = Vec::new();
    for alpn in ["http/1.1", "h2", "h3"] {
        let name = format!("{}-zero-post", alpn.replace('/', "-"));
        let dir = case_dir(&root, &name);
        let extra = json!({"scMaxEachPostBytes":0});
        let (port, _server) = start_xray(&binary, &dir, alpn, extra.clone()).await;
        let binding = binding(port, alpn, "packet-up", extra);
        eprintln!("official gap start: {name}");
        let seq = tokio::time::timeout(
            Duration::from_secs(20),
            exchange_large_packet(&binding, echo_port),
        )
        .await
        .expect("large packet timeout");
        results.push(json!({"case":name,"status":"pass","payload_bytes":1_200_000,"post_count":seq,"post_limit":1_000_000}));
    }

    let (target_port, _target) = start_reality_target(&root).await;
    let keys = Command::new(&binary).arg("x25519").output().unwrap();
    assert!(keys.status.success(), "Xray x25519 failed");
    let keys = String::from_utf8(keys.stdout).unwrap();
    let private_key = keys
        .lines()
        .find_map(|line| line.strip_prefix("PrivateKey: "))
        .expect("private key field");
    let public_key = keys
        .lines()
        .find_map(|line| line.strip_prefix("Password (PublicKey): "))
        .expect("password field");
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let server_dir = case_dir(&root, "reality");
    let _server = run_xray(&binary, &server_dir, "h2", port, json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
            "settings":{"clients":[{"id":UUID}],"decryption":"none"},
            "streamSettings":{"network":"xhttp","security":"reality",
                "realitySettings":{"show":std::env::var_os("DAENEXT_XHTTP_REALITY_DEBUG").is_some(),"minClientVer":"0.0.0","target":format!("127.0.0.1:{target_port}"),"serverNames":["localhost"],"privateKey":private_key,"shortIds":["01020304"]},
                "xhttpSettings":{"path":"/exact?token=a%20b"}}}],
        "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]
    })).await;
    for mode in ["packet-up", "stream-up"] {
        for credential in ["publicKey", "password", "password-priority"] {
            let mut reality =
                json!({"serverName":"localhost","fingerprint":"chrome","shortId":"01020304"});
            if credential == "publicKey" {
                reality["publicKey"] = json!(public_key);
            } else {
                reality["password"] = json!(public_key);
                if credential == "password-priority" {
                    reality["publicKey"] = json!(URL_SAFE_NO_PAD.encode([7; 32]));
                }
            }
            let extra = json!({"downloadSettings":{"address":"127.0.0.1","port":port,"network":"xhttp","security":"reality",
                "realitySettings":reality,"xhttpSettings":{"path":"/exact?token=a%20b"}}});
            let mut url = url::Url::parse(&format!("vless://{UUID}@127.0.0.1:{port}")).unwrap();
            url.query_pairs_mut().extend_pairs([
                ("security", "reality"),
                ("type", "xhttp"),
                ("sni", "localhost"),
                ("alpn", "h2"),
                ("mode", mode),
                ("path", "/exact?token=a%20b"),
                ("fp", "chrome"),
                ("pbk", public_key),
                ("sid", "01020304"),
                ("extra", &extra.to_string()),
            ]);
            let binding = binding_from_url(url);
            let name = format!("h2-reality-{mode}-{credential}");
            eprintln!("official gap start: {name}");
            tokio::time::timeout(Duration::from_secs(20), exchange(&binding, echo_port))
                .await
                .expect("REALITY exchange timeout");
            results.push(json!({"case":name,"status":"pass"}));
        }
    }
    std::fs::write(
        root.join("matrix.json"),
        serde_json::to_vec_pretty(&results).unwrap(),
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "requires DAENEXT_XRAY_BIN and DAENEXT_XHTTP_EVIDENCE_DIR"]
async fn xhttp_official_server_matrix_and_h1_reuse_ab() {
    let binary = PathBuf::from(std::env::var("DAENEXT_XRAY_BIN").expect("DAENEXT_XRAY_BIN"));
    let root = PathBuf::from(
        std::env::var("DAENEXT_XHTTP_EVIDENCE_DIR").expect("DAENEXT_XHTTP_EVIDENCE_DIR"),
    );
    std::fs::create_dir_all(&root).unwrap();
    let identity = dae_outbound::shared_transport::test_support::self_signed_tls_identity(&[
        "localhost",
        "127.0.0.1",
    ])
    .unwrap();
    std::fs::write(
        root.join("cert.pem"),
        identity.certificate.to_pem().unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("key.pem"),
        identity.private_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    let (echo_port, _echo) = echo_server().await;
    let mut results = Vec::new();
    let ab_only = std::env::var_os("DAENEXT_XHTTP_AB_ONLY").is_some();
    for alpn in ["http/1.1", "h2", "h3"].into_iter().filter(|_| !ab_only) {
        let version = alpn.replace('/', "-");
        let mut cases = Vec::new();
        for mode in ["packet-up", "stream-up", "stream-one", "auto"] {
            cases.push((mode.to_owned(), mode, json!({})));
        }
        cases.push(("put-header".into(), "packet-up", json!({"uplinkHTTPMethod":"PUT","sessionIDPlacement":"header","seqPlacement":"query","uplinkDataPlacement":"header","uplinkChunkSize":"64-128","xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingMethod":"tokenish","xPaddingBytes":"100-200"})));
        cases.push(("get-cookie".into(), "packet-up", json!({"uplinkHTTPMethod":"GET","sessionIDPlacement":"cookie","seqPlacement":"cookie","uplinkDataPlacement":"cookie","uplinkChunkSize":"64-128","xPaddingObfsMode":true,"xPaddingPlacement":"cookie"})));
        cases.push(("patch-query".into(), "packet-up", json!({"uplinkHTTPMethod":"PATCH","sessionIDPlacement":"query","seqPlacement":"header","sessionIDTable":"Base62","sessionIDLength":"6-16","xPaddingObfsMode":true,"xPaddingPlacement":"query"})));
        for mode in ["packet-up", "stream-up"] {
            cases.push((format!("{mode}-download"), mode, json!({})));
        }
        for (label, mode, mut extra) in cases {
            let name = format!("{version}-{label}");
            let dir = case_dir(&root, &name);
            let mut server_settings = extra.clone();
            server_settings["mode"] = json!(mode);
            let (port, _process) = start_xray(&binary, &dir, alpn, server_settings).await;
            if label.ends_with("-download") {
                extra["downloadSettings"] = json!({"address":"127.0.0.1","port":port,"network":"xhttp","security":"tls",
                    "tlsSettings":{"allowInsecure":true,"alpn":[alpn]},"xhttpSettings":{"path":"/exact?token=a%20b"}});
            }
            let binding = binding(port, alpn, mode, extra);
            eprintln!("official matrix start: {name}");
            let started = Instant::now();
            tokio::time::timeout(Duration::from_secs(15), exchange(&binding, echo_port))
                .await
                .unwrap_or_else(|_| panic!("{name} timeout; see {}", dir.display()));
            results.push(json!({"case":name,"status":"pass","elapsed_ms":started.elapsed().as_secs_f64()*1000.0}));
            std::fs::write(
                root.join("matrix.json"),
                serde_json::to_vec_pretty(&results).unwrap(),
            )
            .unwrap();
        }
    }
    let dir = case_dir(&root, "h1-ab");
    let (port, _process) = start_xray(&binary, &dir, "http/1.1", json!({"mode":"packet-up"})).await;
    let (proxy_port, counter, _proxy) = forwarder(port).await;
    let binding = binding(proxy_port, "http/1.1", "packet-up", json!({}));
    let mut measurements = Vec::new();
    for round in 0..5 {
        for reuse in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let before = counter.load(Ordering::Relaxed);
            let cpu_before = cpu_micros();
            let rss_before = rss_kib();
            let start = Instant::now();
            let mut parts = open_xhttp_packet_up_parts(&binding, false).await.unwrap();
            send_xhttp_packet_up_request(
                &mut parts.upload,
                &parts.session_id,
                0,
                request(echo_port, b"start"),
            )
            .await
            .unwrap();
            receive(&mut parts.download, b"\0\0start").await;
            let data = Bytes::from(vec![42; 16 * 1024]);
            for seq in 1..=32 {
                if !reuse && let XhttpUploadClient::H1 { pool, .. } = &mut parts.upload {
                    *pool = XhttpH1UploadPool::new(1);
                }
                send_xhttp_packet_up_request(
                    &mut parts.upload,
                    &parts.session_id,
                    seq,
                    data.clone(),
                )
                .await
                .unwrap();
                receive(&mut parts.download, &data).await;
            }
            close_xhttp_upload_client(parts.upload).await;
            close_xhttp_download_client(parts.download).await;
            let connections = counter.load(Ordering::Relaxed) - before;
            assert_eq!(connections, if reuse { 2 } else { 34 });
            measurements.push(json!({"round":round,"reuse":reuse,"tcp_connections":connections,"payload_bytes":32*16*1024,"elapsed_ms":start.elapsed().as_secs_f64()*1000.0,"client_cpu_us":cpu_micros()-cpu_before,"rss_before_kib":rss_before,"rss_after_kib":rss_kib()}));
        }
    }
    std::fs::write(
        root.join("h1-ab.json"),
        serde_json::to_vec_pretty(&measurements).unwrap(),
    )
    .unwrap();
    eprintln!(
        "{} official cases run in this invocation; H1 A/B: {}",
        results.len(),
        serde_json::to_string(&measurements).unwrap()
    );
}

fn cpu_micros() -> i64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage initializes the whole structure on success.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1_000_000
        + usage.ru_utime.tv_usec
        + usage.ru_stime.tv_usec
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .map(|s| s.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap()
}
