use super::support::FreshProductState;
use super::*;

struct DelayedSubscriptionServer {
    url: String,
    accepted: Receiver<()>,
    release: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl DelayedSubscriptionServer {
    fn start(response_body: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/subscription", listener.local_addr().unwrap());
        let (accepted_sender, accepted) = mpsc::sync_channel(1);
        let (release, release_receiver) = mpsc::channel();
        let response_body = response_body.map(str::to_owned);
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            accepted_sender.send(()).unwrap();
            release_receiver
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            if let Some(body) = response_body {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        Self {
            url,
            accepted,
            release,
            thread,
        }
    }

    fn wait_until_accepted(&self) {
        self.accepted.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    fn finish(self) {
        self.release.send(()).unwrap();
        self.thread.join().unwrap();
    }
}

fn seed_remote_subscription(fixture: &FreshProductState, link: &str) {
    fixture
        .connection()
        .execute(
            "INSERT INTO subscriptions(
                id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy
             ) VALUES(7, 'old-time', ?1, ?2, 1, 'old-status', 'old-info', 'source-a', 0)",
            params![link, DEFAULT_SUBSCRIPTION_CRON_EXP],
        )
        .unwrap();
    apply_subscription_refresh_result(
        fixture.state(),
        7,
        "seed-time",
        &["socks://127.0.0.1:1080#preserved".to_owned()],
    )
    .unwrap();
}

fn start_refresh(
    fixture: &FreshProductState,
    control_runtime: Arc<ProductControlRuntime>,
) -> thread::JoinHandle<io::Result<Value>> {
    let state = fixture.state().to_path_buf();
    let config_dir = fixture.root().to_path_buf();
    thread::spawn(move || {
        refresh_subscription_from_remote(&control_runtime, &state, &config_dir, 7)
    })
}

fn update_subscription_source(fixture: &FreshProductState) {
    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/subscriptions/7".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: br#"{
            "link":"https://new-source.invalid/subscription",
            "tag":"source-b",
            "useProxy":true
        }"#
        .to_vec(),
    };
    assert_eq!(
        update_subscription(fixture.state(), &request, 7).status,
        200
    );
}

fn update_subscription_link(fixture: &FreshProductState, link: &str) {
    let request = HttpRequest {
        method: "PATCH".to_owned(),
        path: "/api/subscriptions/7".to_owned(),
        query: HashMap::new(),
        headers: HashMap::new(),
        body: serde_json::to_vec(&json!({
            "link": link,
            "tag": "source-a",
            "useProxy": false,
        }))
        .unwrap(),
    };
    assert_eq!(
        update_subscription(fixture.state(), &request, 7).status,
        200
    );
}

#[test]
fn successful_result_for_replaced_source_is_discarded() {
    let fixture = FreshProductState::new("subscription-stale-success");
    let server =
        DelayedSubscriptionServer::start(Some("socks://127.0.0.1:1081#obsolete-response\n"));
    seed_remote_subscription(&fixture, &server.url);
    let refresh = start_refresh(&fixture, product_test_control_runtime());
    server.wait_until_accepted();

    update_subscription_source(&fixture);
    server.finish();
    let report = refresh.join().unwrap().unwrap();

    assert_eq!(report["refreshOutcome"], "stale-source-discarded");
    assert_eq!(report["runtimeInputChanged"], false);
    let subscription = get_subscription_value(fixture.state(), 7).unwrap().unwrap();
    assert_eq!(
        subscription["link"],
        "https://new-source.invalid/subscription"
    );
    assert_eq!(subscription["tag"], "source-b");
    assert_eq!(subscription["useProxy"], true);
    let conn = fixture.connection();
    assert_eq!(count_nodes_for_subscription(&conn, 7).unwrap(), 1);
    assert_eq!(
        conn.query_row(
            "SELECT name FROM nodes WHERE subscription_id = 7",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "preserved"
    );
}

#[test]
fn failed_result_for_replaced_source_does_not_overwrite_status() {
    let fixture = FreshProductState::new("subscription-stale-failure");
    let server = DelayedSubscriptionServer::start(None);
    seed_remote_subscription(&fixture, &server.url);
    let refresh = start_refresh(&fixture, product_test_control_runtime());
    server.wait_until_accepted();

    update_subscription_source(&fixture);
    let expected = get_subscription_value(fixture.state(), 7).unwrap().unwrap();
    server.finish();
    let report = refresh.join().unwrap().unwrap();

    assert_eq!(report["refreshOutcome"], "stale-source-discarded");
    let current = get_subscription_value(fixture.state(), 7).unwrap().unwrap();
    assert_eq!(current["updatedAt"], expected["updatedAt"]);
    assert_eq!(current["status"], expected["status"]);
    assert_eq!(current["info"], expected["info"]);
}

#[test]
fn deleted_subscription_is_not_restored_by_late_result() {
    let fixture = FreshProductState::new("subscription-stale-delete");
    let server =
        DelayedSubscriptionServer::start(Some("socks://127.0.0.1:1081#obsolete-response\n"));
    seed_remote_subscription(&fixture, &server.url);
    let refresh = start_refresh(&fixture, product_test_control_runtime());
    server.wait_until_accepted();

    assert_eq!(delete_subscription(fixture.state(), 7).unwrap(), 1);
    server.finish();
    let report = refresh.join().unwrap().unwrap();

    assert_eq!(report["refreshOutcome"], "stale-source-discarded");
    let conn = fixture.connection();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM subscriptions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM nodes", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[test]
fn stale_http_file_result_does_not_replace_persisted_fallback() {
    let fixture = FreshProductState::new("subscription-stale-persist");
    let server =
        DelayedSubscriptionServer::start(Some("socks://127.0.0.1:1081#obsolete-response\n"));
    let link = server.url.replacen("http:", "http-file:", 1);
    seed_remote_subscription(&fixture, &link);
    let refresh = start_refresh(&fixture, product_test_control_runtime());
    server.wait_until_accepted();

    update_subscription_link(&fixture, "http-file://new-source.invalid/subscription");
    server.finish();
    let report = refresh.join().unwrap().unwrap();

    assert_eq!(report["refreshOutcome"], "stale-source-discarded");
    assert!(!fixture.root().join("persist.d/source-a.sub").exists());
}

#[test]
fn current_http_file_result_updates_persisted_fallback() {
    let fixture = FreshProductState::new("subscription-current-persist");
    let body = "socks://127.0.0.1:1081#current-response\n";
    let server = DelayedSubscriptionServer::start(Some(body));
    let link = server.url.replacen("http:", "http-file:", 1);
    seed_remote_subscription(&fixture, &link);
    let refresh = start_refresh(&fixture, product_test_control_runtime());
    server.wait_until_accepted();

    server.finish();
    let report = refresh.join().unwrap().unwrap();

    assert_eq!(report["fetched"], true);
    assert_eq!(
        fs::read_to_string(fixture.root().join("persist.d/source-a.sub")).unwrap(),
        body
    );
}
