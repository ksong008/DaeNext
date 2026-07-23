use super::*;

#[test]
fn self_signed_tls_fetch_is_classified_before_node_import() {
    let fixture = support::FreshProductState::new("subscription-self-signed-fetch");
    let (port, server) = self_signed_subscription_server();
    let request = HttpRequest {
        method: "POST".to_owned(),
        path: "/api/subscriptions".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "link": format!("https://localhost:{port}/subscription"),
            "tag": "self-signed",
            "cronEnable": false,
        }))
        .unwrap(),
    };
    let runtime = ProductRuntimeManager::new();
    let control_runtime = product_test_control_runtime();

    let response = create_subscription(
        &control_runtime,
        fixture.state(),
        fixture.root(),
        &runtime,
        &request,
    );
    assert_eq!(response.status, 201);
    let response: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response["subscriptionCreated"], true);
    assert_eq!(response["fetched"], false);
    assert_eq!(response["fetchError"]["code"], "tls_unknown_issuer");
    assert_eq!(response["failedNodeCount"], 0);
    assert!(response["nodeImportResult"].as_array().unwrap().is_empty());
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("initial fetch failed")
    );
    assert!(!response["error"].as_str().unwrap().contains("node import"));
    let subscription_id = response["subscription"]["id"].as_i64().unwrap();
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row(
            "SELECT status FROM subscriptions WHERE id = ?1",
            params![subscription_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "fetch_error"
    );
    assert_eq!(
        count_nodes_for_subscription(&conn, subscription_id).unwrap(),
        0
    );
    server.join().unwrap();
}

fn self_signed_subscription_server() -> (u16, thread::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key.into())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let stream = tokio::net::TcpStream::from_std(stream).unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let _ = acceptor.accept(stream).await;
        });
    });
    (port, server)
}
