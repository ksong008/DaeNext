use super::*;
#[cfg(test)]
mod remote_strategy_live_tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    use dae_config::Config;

    use super::*;

    const REMOTE_STRATEGY_LIVE_ENV: &str = "REMOTE_STRATEGY_LIVE";
    const REMOTE_STRATEGY_LIVE_LEGACY_ENV: &str = "DAE_REMOTE_STRATEGY_LIVE";

    struct LiveHttpProxy {
        port: u16,
        delay_ms: Arc<AtomicU64>,
    }

    impl LiveHttpProxy {
        fn set_delay_ms(&self, delay_ms: u64) {
            self.delay_ms.store(delay_ms, Ordering::Relaxed);
        }
    }

    #[test]
    fn remote_resident_group_strategy_matrix_uses_live_proxy_health_checks() {
        if !remote_strategy_live_enabled() {
            return;
        }

        let check_server = start_live_http_check_server();
        let node_a = start_live_http_proxy(140);
        let node_b = start_live_http_proxy(20);

        assert_strategy_selects(
            "fixed(0)",
            r#"
        filter: name(node_a, node_b)
        policy: fixed(0)
        "#,
            &node_a,
            &node_b,
            check_server,
            "node_a",
        );
        assert_strategy_selects(
            "random",
            r#"
        filter: name(node_a, node_b)
        policy: random
        "#,
            &node_a,
            &node_b,
            check_server,
            "any",
        );
        assert_strategy_selects(
            "min",
            r#"
        filter: name(node_a, node_b)
        policy: min
        "#,
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "min_avg10",
            r#"
        filter: name(node_a, node_b)
        policy: min_avg10
        "#,
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "min_moving_avg",
            r#"
        filter: name(node_a, node_b)
        policy: min_moving_avg
        "#,
            &node_a,
            &node_b,
            check_server,
            "node_b",
        );
        assert_strategy_selects(
            "add_latency",
            r#"
        filter: name(node_a)
        filter: name(node_b) [add_latency: 250ms]
        policy: min
        "#,
            &node_a,
            &node_b,
            check_server,
            "node_a",
        );

        node_a.set_delay_ms(140);
        node_b.set_delay_ms(110);
        let tolerance_config = live_strategy_config(
            r#"
        filter: name(node_a, node_b)
        policy: min
        check_tolerance: 80ms
        "#,
            &node_a,
            &node_b,
            check_server,
        );
        let plan = build_resident_dataplane_plan(&tolerance_config).unwrap();
        let group = plan.default_proxy_group().unwrap();
        let probes = group.probe_candidates();
        run_resident_group_health_checks(group, &probes);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_a");
        node_b.set_delay_ms(20);
        run_resident_group_health_checks(group, &probes);
        assert_eq!(group.select_proxy_for_tcp().unwrap().node_tag, "node_b");
    }

    fn remote_strategy_live_enabled() -> bool {
        std::env::var(REMOTE_STRATEGY_LIVE_ENV)
            .or_else(|_| std::env::var(REMOTE_STRATEGY_LIVE_LEGACY_ENV))
            .as_deref()
            == Ok("1")
    }

    fn assert_strategy_selects(
        label: &str,
        group_body: &str,
        node_a: &LiveHttpProxy,
        node_b: &LiveHttpProxy,
        check_server: u16,
        expected: &str,
    ) {
        let config = live_strategy_config(group_body, node_a, node_b, check_server);
        let plan = build_resident_dataplane_plan(&config)
            .unwrap_or_else(|err| panic!("{label}: build plan: {err}"));
        let group = plan
            .default_proxy_group()
            .unwrap_or_else(|| panic!("{label}: missing default proxy group"));
        let probes = group.probe_candidates();
        run_resident_group_health_checks(group, &probes);
        if expected == "any" {
            let selected = group
                .select_proxy_for_tcp()
                .unwrap_or_else(|err| panic!("{label}: select tcp: {err}"));
            assert!(
                matches!(selected.node_tag.as_str(), "node_a" | "node_b"),
                "{label}: unexpected random selection {}",
                selected.node_tag
            );
            assert!(
                group
                    .latency_snapshots()
                    .iter()
                    .filter(|snapshot| snapshot.latency_ms.is_some())
                    .count()
                    >= 2,
                "{label}: expected live latency for both candidates"
            );
            return;
        }
        assert_eq!(
            group
                .select_proxy_for_tcp()
                .unwrap_or_else(|err| panic!("{label}: select tcp: {err}"))
                .node_tag,
            expected,
            "{label}: selected node"
        );
    }

    fn live_strategy_config(
        group_body: &str,
        node_a: &LiveHttpProxy,
        node_b: &LiveHttpProxy,
        check_server: u16,
    ) -> Config {
        let input = format!(
            r#"
        global {{
        lan_interface: daerust0
        tcp_check_url: 'http://127.0.0.1:{check_server}/generate_204,127.0.0.1'
        udp_check_dns: '127.0.0.1:53,127.0.0.1'
        check_interval: 1s
        }}
        node {{
        node_a: 'http://127.0.0.1:{node_a_port}'
        node_b: 'http://127.0.0.1:{node_b_port}'
        }}
        group {{
        proxy {{
        {group_body}
        }}
        }}
        routing {{
        l4proto(tcp) -> proxy
        fallback: direct
        }}
        "#,
            node_a_port = node_a.port,
            node_b_port = node_b.port,
        );
        let sections = dae_config::parser::parse_config(&input)
            .unwrap_or_else(|err| panic!("parse live strategy config: {err}"));
        dae_config::schema::build_config(&sections)
            .unwrap_or_else(|err| panic!("build live strategy config: {err}"))
    }

    fn start_live_http_check_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_live_http_check(stream));
            }
        });
        port
    }

    fn handle_live_http_check(mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = read_headers(&mut stream);
        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn start_live_http_proxy(delay_ms: u64) -> LiveHttpProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let delay_ms = Arc::new(AtomicU64::new(delay_ms));
        let delay_for_thread = Arc::clone(&delay_ms);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let delay_ms = Arc::clone(&delay_for_thread);
                thread::spawn(move || handle_live_http_proxy(stream, delay_ms));
            }
        });
        LiveHttpProxy { port, delay_ms }
    }

    fn handle_live_http_proxy(mut inbound: TcpStream, delay_ms: Arc<AtomicU64>) {
        let _ = inbound.set_read_timeout(Some(Duration::from_secs(5)));
        let request = match read_headers(&mut inbound) {
            Ok(request) => request,
            Err(_) => return,
        };
        let Some(target) = connect_target_from_request(&request) else {
            let _ = inbound.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        thread::sleep(Duration::from_millis(delay_ms.load(Ordering::Relaxed)));
        let mut outbound = match TcpStream::connect(target) {
            Ok(outbound) => outbound,
            Err(_) => {
                let _ = inbound.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                return;
            }
        };
        let _ = outbound.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let _ = inbound.flush();
        let mut inbound_reader = match inbound.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let mut outbound_writer = match outbound.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let upload = thread::spawn(move || {
            let _ = std::io::copy(&mut inbound_reader, &mut outbound_writer);
            let _ = outbound_writer.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut outbound, &mut inbound);
        let _ = inbound.shutdown(Shutdown::Write);
        let _ = upload.join();
    }

    fn read_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut buf = [0_u8; 256];
        while request.len() < 8192 {
            let read = stream.read(&mut buf)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok(request)
    }

    fn connect_target_from_request(request: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(request);
        let mut first_line = text.lines().next()?.split_whitespace();
        let method = first_line.next()?;
        let target = first_line.next()?;
        if method.eq_ignore_ascii_case("CONNECT") && !target.is_empty() {
            Some(target.to_owned())
        } else {
            None
        }
    }
}
