use super::*;
use dae_config::Item;

pub(crate) fn test_config_with_node(node_name: &str, link: &str, group_name: &str) -> String {
    format!(
        r#"
global {{}}
node {{
    {node_name}: '{link}'
}}
group {{
    {group_name} {{
        filter: name({node_name})
        policy: random
    }}
}}
routing {{
    fallback: direct
}}
dns {{}}
"#
    )
}

pub(crate) fn node_link_from_config(content: &str, node_name: &str) -> String {
    let sections = parse_config(content).unwrap();
    sections
        .iter()
        .find(|section| section.name == "node")
        .and_then(|section| {
            section.items.iter().find_map(|item| {
                let Item::Param(param) = item else {
                    return None;
                };
                (param.key == node_name).then(|| param.val.clone())
            })
        })
        .unwrap_or_else(|| panic!("node {node_name} not found in test config"))
}

pub(crate) fn config_node_value(id: i64, node_name: &str, link: &str) -> Value {
    let content = test_config_with_node(node_name, link, "egress");
    build_runtime_config_from_content(&content).unwrap();
    let link = node_link_from_config(&content, node_name);
    let parsed = parse_node_link(&link, Some(node_name));
    json!({
        "id": id,
        "link": link,
        "name": parsed.display_name,
        "address": parsed.address,
        "protocol": parsed.protocol,
        "tag": node_name
    })
}

pub(crate) fn insert_config_node(
    conn: &Connection,
    id: i64,
    node_name: &str,
    link: &str,
    subscription_id: Option<i64>,
) {
    let content = test_config_with_node(node_name, link, "egress");
    build_runtime_config_from_content(&content).unwrap();
    let link = node_link_from_config(&content, node_name);
    let parsed = parse_node_link(&link, Some(node_name));
    conn.execute(
        "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            link,
            parsed.display_name,
            parsed.address,
            parsed.protocol,
            node_name,
            subscription_id
        ],
    )
    .unwrap();
}

#[test]
pub(crate) fn stored_successful_latency_seed_snapshots_skip_failures_and_redact_links() {
    let dir = std::env::temp_dir().join(format!("daed-product-latency-seed-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    insert_config_node(&conn, 11, "one", "socks://127.0.0.1:1080#one", None);
    insert_config_node(&conn, 12, "two", "socks://127.0.0.1:1081#two", None);
    store_node_latency_result(
        &conn,
        &NodeLatencyWrite {
            node_id: 11,
            node_link: "socks://127.0.0.1:1080#one".to_owned(),
            latency_ms: Some(37),
            alive: true,
            tested_at: iso8601_utc(42),
            message: None,
        },
    )
    .unwrap();
    store_node_latency_result(
        &conn,
        &NodeLatencyWrite {
            node_id: 12,
            node_link: "socks://127.0.0.1:1081#two".to_owned(),
            latency_ms: Some(10000),
            alive: false,
            tested_at: iso8601_utc(43),
            message: Some("timeout".to_owned()),
        },
    )
    .unwrap();

    let snapshots = stored_successful_node_latency_seed_snapshots(&state).unwrap();

    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0]["displayName"], json!("one"));
    assert_eq!(
        snapshots[0]["linkHash"],
        json!(runtime_link_hash("socks://127.0.0.1:1080#one"))
    );
    assert_eq!(snapshots[0]["latencyMs"], json!(37));
    assert_eq!(snapshots[0]["alive"], json!(true));
    assert_eq!(snapshots[0]["checkedAtUnix"], json!(42));
    assert!(snapshots[0].get("link").is_none(), "{:?}", snapshots[0]);
    assert!(!snapshots[0].to_string().contains("127.0.0.1:1080"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn empty_latency_probe_ids_select_all_nodes() {
    let dir = std::env::temp_dir().join(format!("daed-product-latency-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    insert_config_node(&conn, 11, "one", "socks://127.0.0.1:1080#one", None);
    insert_config_node(&conn, 12, "two", "socks://127.0.0.1:1081#two", None);

    let nodes = latency_probe_nodes_for_ids(&conn, &[]).unwrap();
    assert_eq!(
        nodes.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
        vec![11, 12]
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn enqueue_latency_probe_returns_job_contract_for_all_nodes() {
    let dir = std::env::temp_dir().join(format!("daed-product-latency-job-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.db");
    ensure_state_schema(&state).unwrap();
    let conn = open_state_connection(&state).unwrap();
    insert_config_node(&conn, 11, "one", "socks://127.0.0.1:1080#one", None);
    insert_config_node(&conn, 12, "two", "socks://127.0.0.1:1081#two", None);
    drop(conn);

    let runtime = Arc::new(ProductRuntimeManager::new());
    let jobs = Arc::new(LatencyJobManager::default());
    let reclaim_before = allocator_reclaim_snapshot_json()["reasons"]["manual_latency_probe"]
        .as_u64()
        .unwrap_or(0);
    let value =
        enqueue_node_latency_job(&state, &dir, Arc::clone(&runtime), Arc::clone(&jobs), &[])
            .unwrap();

    assert!(value["items"].as_array().is_some());
    assert_eq!(value["job"]["total"].as_u64(), Some(2));
    assert_eq!(value["job"]["completed"].as_u64(), Some(0));
    assert_eq!(value["job"]["status"].as_str(), Some("queued"));

    let mut current = current_node_latency_job_value(&jobs);
    for _ in 0..50 {
        let status = current["job"]["status"].as_str().unwrap_or_default();
        if status != "queued" && status != "running" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        current = current_node_latency_job_value(&jobs);
    }

    assert_eq!(
        current["job"]["status"].as_str(),
        Some("finished"),
        "job message: {:?}",
        current["job"]["message"]
    );
    assert_eq!(current["job"]["total"].as_u64(), Some(2));
    assert_eq!(current["job"]["completed"].as_u64(), Some(2));
    assert_eq!(
        list_stored_node_latencies_value(&state).unwrap()["items"]
            .as_array()
            .map(Vec::len),
        Some(2),
    );
    let reclaim_after = allocator_reclaim_snapshot_json()["reasons"]["manual_latency_probe"]
        .as_u64()
        .unwrap_or(0);
    assert!(reclaim_after > reclaim_before);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
pub(crate) fn latency_probe_helper_accepts_runtime_config_request() {
    let content = test_config_with_node("one", "socks://127.0.0.1:1080#one", "egress");
    let request = json!({
        "schemaVersion": 1,
        "scope": "manual-latency-probe",
        "reloadGeneration": 7,
        "requestedLinks": [],
        "config": {
            "source": "current-runtime-config",
            "content": content,
        },
        "concurrency": 8,
    });
    let response =
        latency_probe_helper_response_from_request(request.to_string().as_bytes()).unwrap();
    assert_eq!(response["schemaVersion"].as_u64(), Some(1));
    assert_eq!(response["scope"].as_str(), Some("manual-latency-probe"));
    assert_eq!(response["reloadGeneration"].as_u64(), Some(7));
    assert_eq!(response["snapshots"].as_array().map(Vec::len), Some(0));
}

#[test]
pub(crate) fn latency_probe_helper_stream_accepts_runtime_config_request() {
    let content = test_config_with_node("one", "socks://127.0.0.1:1080#one", "egress");
    let request = json!({
        "schemaVersion": 1,
        "scope": "manual-latency-probe",
        "reloadGeneration": 7,
        "requestedLinks": [],
        "config": {
            "source": "current-runtime-config",
            "content": content,
        },
        "concurrency": 8,
    });
    let mut output = Vec::new();
    latency_probe_helper_response_lines_from_request(request.to_string().as_bytes(), &mut output)
        .unwrap();
    assert!(output.is_empty());
}

#[test]
pub(crate) fn latency_probe_link_chunks_preserve_unique_order_and_node_mapping() {
    let nodes = vec![
        (
            11,
            "socks://127.0.0.1:1080#one".to_owned(),
            "127.0.0.1".to_owned(),
        ),
        (
            12,
            "socks://127.0.0.1:1081#two".to_owned(),
            "127.0.0.1".to_owned(),
        ),
        (
            13,
            "socks://127.0.0.1:1080#one".to_owned(),
            "127.0.0.1".to_owned(),
        ),
        (
            14,
            "socks://127.0.0.1:1082#three".to_owned(),
            "127.0.0.1".to_owned(),
        ),
    ];

    let chunks = latency_probe_link_chunks(&nodes, 2);
    assert_eq!(
        chunks,
        vec![
            vec![
                "socks://127.0.0.1:1080#one".to_owned(),
                "socks://127.0.0.1:1081#two".to_owned(),
            ],
            vec!["socks://127.0.0.1:1082#three".to_owned()],
        ]
    );

    let first_chunk_nodes = latency_probe_nodes_for_links(&nodes, &chunks[0]);
    assert_eq!(
        first_chunk_nodes
            .iter()
            .map(|(id, _, _)| *id)
            .collect::<Vec<_>>(),
        vec![11, 12, 13]
    );
}

#[test]
pub(crate) fn latency_probe_helper_parent_chunk_size_bounds_process_work() {
    assert_eq!(latency_probe_helper_parent_chunk_size(0, 0), 1);
    assert_eq!(latency_probe_helper_parent_chunk_size(0, 27), 4);
    assert_eq!(latency_probe_helper_parent_chunk_size(8, 1), 1);
    assert_eq!(latency_probe_helper_parent_chunk_size(8, 27), 27);
    assert_eq!(latency_probe_helper_parent_chunk_size(32, 129), 128);

    let make_nodes = |count, port_base: i64, prefix: &str| {
        (0..count)
            .map(|index| {
                (
                    index,
                    format!("socks://127.0.0.1:{}#{prefix}-{index}", port_base + index),
                    "127.0.0.1".to_owned(),
                )
            })
            .collect::<Vec<_>>()
    };

    let nodes = make_nodes(27, 10_000, "node");
    let chunks = latency_probe_link_chunks(
        &nodes,
        latency_probe_helper_parent_chunk_size(8, latency_probe_unique_link_count(&nodes)),
    );
    assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![27]);

    let nodes = make_nodes(50, 20_000, "many");
    let chunks = latency_probe_link_chunks(
        &nodes,
        latency_probe_helper_parent_chunk_size(8, latency_probe_unique_link_count(&nodes)),
    );
    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![32, 18]
    );

    let nodes = make_nodes(129, 30_000, "large");
    let chunks = latency_probe_link_chunks(
        &nodes,
        latency_probe_helper_parent_chunk_size(8, latency_probe_unique_link_count(&nodes)),
    );
    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![32, 32, 32, 32, 1]
    );
}

#[test]
pub(crate) fn latency_probe_helper_parent_chunk_size_uses_unique_link_count() {
    let mut nodes = (0..27)
        .map(|index| {
            (
                index,
                format!("socks://127.0.0.1:{}#node-{index}", 10_000 + index),
                "127.0.0.1".to_owned(),
            )
        })
        .collect::<Vec<_>>();
    nodes.push((
        1000,
        "socks://127.0.0.1:10000#node-0".to_owned(),
        "127.0.0.1".to_owned(),
    ));
    assert_eq!(latency_probe_unique_link_count(&nodes), 27);
    let chunks = latency_probe_link_chunks(
        &nodes,
        latency_probe_helper_parent_chunk_size(8, latency_probe_unique_link_count(&nodes)),
    );
    assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![27]);
}

#[test]
pub(crate) fn latency_probe_helper_timeout_scales_with_parallel_batches() {
    let tcp_timeout = std::time::Duration::from_secs(4);
    let small = latency_probe_helper_timeout(8, 8, tcp_timeout);
    let large = latency_probe_helper_timeout(8, 80, tcp_timeout);
    assert!(small >= std::time::Duration::from_secs(20));
    assert!(large > small);
}

#[test]
pub(crate) fn latency_probe_failure_snapshots_only_cover_unseen_links() {
    let links = vec![
        "socks://127.0.0.1:1080#one".to_owned(),
        "socks://127.0.0.1:1081#two".to_owned(),
    ];
    let seen = vec![fake_runtime_tcp_latency_snapshot(&links[0])];
    let failures = latency_probe_failure_snapshots_for_unseen_links(
        &links,
        7,
        "manual latency probe helper failed",
        "stream interrupted",
        &seen,
    );

    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0]["linkHash"].as_str(),
        Some(runtime_link_hash(&links[1]).as_str())
    );
    assert_eq!(failures[0]["alive"].as_bool(), Some(false));
}

#[test]
pub(crate) fn runtime_latency_snapshots_map_to_node_ids_by_link() {
    let nodes = vec![
        (
            11,
            "socks://127.0.0.1:1080#one".to_owned(),
            "127.0.0.1:1080".to_owned(),
        ),
        (
            12,
            "socks://127.0.0.1:1081#two".to_owned(),
            "127.0.0.1:1081".to_owned(),
        ),
    ];
    let snapshots = vec![
        json!({
            "name": "one",
            "linkHash": runtime_link_hash("socks://127.0.0.1:1080#one"),
            "linkIdentity": {
                "schemaVersion": 1,
                "displayName": "one",
                "linkHash": runtime_link_hash("socks://127.0.0.1:1080#one"),
                "redactedSource": "socks:<redacted>#one",
            },
            "latencyMs": 37,
            "alive": true,
            "checkedAtUnix": 42,
            "message": "37ms",
        }),
        json!({
            "name": "two",
            "linkHash": runtime_link_hash("socks://127.0.0.1:1081#two"),
            "linkIdentity": {
                "schemaVersion": 1,
                "displayName": "two",
                "linkHash": runtime_link_hash("socks://127.0.0.1:1081#two"),
                "redactedSource": "socks:<redacted>#two",
            },
            "latencyMs": null,
            "alive": false,
            "checkedAtUnix": 0,
            "message": "no latency result",
        }),
    ];
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.get("link").is_none())
    );
    let (results, tested_ids) = runtime_node_latency_results_for_nodes(&nodes, &snapshots);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].node_id, 11);
    assert_eq!(results[0].latency_ms, Some(37));
    assert!(results[0].alive);
    assert_eq!(results[0].message, None);
    assert_eq!(results[0].tested_at, iso8601_utc(42));
    assert!(tested_ids.contains(&11));
    assert!(!tested_ids.contains(&12));
}

#[test]
pub(crate) fn streaming_latency_snapshot_writes_only_matching_nodes() {
    let nodes = vec![
        (
            11,
            "socks://127.0.0.1:1080#one".to_owned(),
            "127.0.0.1:1080".to_owned(),
        ),
        (
            12,
            "socks://127.0.0.1:1081#two".to_owned(),
            "127.0.0.1:1081".to_owned(),
        ),
    ];
    let snapshot = fake_runtime_tcp_latency_snapshot(&nodes[0].1);
    let streaming_results = node_latency_results_for_runtime_snapshots_only(&nodes, &[snapshot]);

    assert_eq!(streaming_results.len(), 1);
    assert_eq!(streaming_results[0].node_id, 11);
}

#[test]
pub(crate) fn runtime_latency_failure_snapshot_is_tested_with_message() {
    let nodes = vec![(
        21,
        "socks://127.0.0.1:1080#one".to_owned(),
        "127.0.0.1:1080".to_owned(),
    )];
    let snapshots = vec![json!({
        "name": "one",
        "linkHash": runtime_link_hash("socks://127.0.0.1:1080#one"),
        "linkIdentity": {
            "schemaVersion": 1,
            "displayName": "one",
            "linkHash": runtime_link_hash("socks://127.0.0.1:1080#one"),
            "redactedSource": "socks:<redacted>#one",
        },
        "latencyMs": null,
        "alive": false,
        "checkedAtUnix": 84,
        "message": "connect failed",
    })];
    assert!(snapshots[0].get("link").is_none());
    let (results, tested_ids) = runtime_node_latency_results_for_nodes(&nodes, &snapshots);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].node_id, 21);
    assert_eq!(results[0].latency_ms, None);
    assert!(!results[0].alive);
    assert_eq!(results[0].message.as_deref(), Some("connect failed"));
    assert_eq!(results[0].tested_at, iso8601_utc(84));
    assert!(tested_ids.contains(&21));
}

#[test]
pub(crate) fn runtime_latency_failed_snapshot_with_placeholder_latency_keeps_message() {
    let nodes = vec![(
        22,
        "socks://127.0.0.1:1080#one".to_owned(),
        "127.0.0.1:1080".to_owned(),
    )];
    let snapshots = vec![json!({
        "name": "one",
        "linkHash": runtime_link_hash("socks://127.0.0.1:1080#one"),
        "linkIdentity": {
            "schemaVersion": 1,
            "displayName": "one",
            "linkHash": runtime_link_hash("socks://127.0.0.1:1080#one"),
            "redactedSource": "socks:<redacted>#one",
        },
        "latencyMs": 10000,
        "alive": false,
        "checkedAtUnix": 85,
        "message": "TLS handshake failed unexpected EOF",
    })];
    let (results, tested_ids) = runtime_node_latency_results_for_nodes(&nodes, &snapshots);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].node_id, 22);
    assert_eq!(results[0].latency_ms, Some(10000));
    assert!(!results[0].alive);
    assert_eq!(
        results[0].message.as_deref(),
        Some("TLS handshake failed unexpected EOF")
    );
    assert!(tested_ids.contains(&22));
}

#[test]
pub(crate) fn fake_runtime_latency_snapshot_redacts_raw_link() {
    let raw_link = "http://user:secret@127.0.0.1:1/node?token=secret#demo";
    let snapshot = fake_runtime_tcp_latency_snapshot(raw_link);
    assert!(snapshot.get("link").is_none(), "{snapshot}");
    assert_eq!(snapshot["name"], "demo");
    assert_eq!(snapshot["displayName"], "demo");
    assert_eq!(snapshot["linkHash"], runtime_link_hash(raw_link));
    assert_eq!(
        snapshot["linkIdentity"]["redactedSource"],
        "http:<redacted>#demo"
    );
    assert!(!snapshot.to_string().contains("user:secret"));
    assert!(!snapshot.to_string().contains("token=secret"));
}
