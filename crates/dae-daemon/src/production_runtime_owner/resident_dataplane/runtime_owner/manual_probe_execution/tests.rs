use super::*;

#[test]
fn basic_probe_scope_uses_one_bounded_runtime_without_transport_owners() {
    let link = "socks5://127.0.0.1:1080".to_owned();
    let config = parse_manual_probe_config(&link);
    let mut execution = ManualProbeExecution::start(&config, &[link], 81_001, 3).unwrap();

    assert_eq!(execution.owners.task_count(), 0);
    assert!(execution.runtime.worker_threads() <= 3);
    assert!(execution.runtime.worker_threads() >= 1);
    assert!(execution.runtime.is_active());

    execution.shutdown().unwrap();
    assert!(!execution.runtime.is_active());
    execution.shutdown().unwrap();
}

#[test]
fn manual_probe_runtime_workers_keep_the_helper_control_identity() {
    let link = "socks5://127.0.0.1:1080".to_owned();
    let config = parse_manual_probe_config(&link);
    let resources = ResidentRuntimeResourceConfig::from_config(&config);
    let mut runtime = ManualProbeRuntime::start(&resources, 2).unwrap();

    let (worker_name, task_comm) = runtime.block_on(async {
        tokio::spawn(async {
            (
                std::thread::current().name().map(str::to_owned),
                std::fs::read_to_string("/proc/thread-self/comm")
                    .unwrap()
                    .trim()
                    .to_owned(),
            )
        })
        .await
        .unwrap()
    });

    assert_eq!(
        RESIDENT_MANUAL_PROBE_TASK_NAME, "daed-latency",
        "the helper task name is an existing eBPF routing contract"
    );
    assert_eq!(
        worker_name.as_deref(),
        Some(RESIDENT_MANUAL_PROBE_TASK_NAME)
    );
    assert_eq!(task_comm, RESIDENT_MANUAL_PROBE_TASK_NAME);
    runtime.shutdown();
}

fn parse_manual_probe_config(link: &str) -> Config {
    let source = format!(
        r#"
        global {{
            lan_interface: daerust0
        }}
        node {{
            probe_node: '{link}'
        }}
        group {{
            proxy {{
                filter: name(probe_node)
                policy: fixed(0)
            }}
        }}
        routing {{
            fallback: proxy
        }}
        "#
    );
    let sections = dae_config::parser::parse_config(&source).unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}
