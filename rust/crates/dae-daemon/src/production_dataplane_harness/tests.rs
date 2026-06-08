#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn production_dataplane_report_is_read_only_by_default() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-default-{}",
            std::process::id()
        ));
        let report = production_dataplane_harness_report(
            &root,
            &ProductionDataplaneHarnessOptions::default(),
        )
        .unwrap();
        assert!(
            !report["production_dataplane_harness_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["production_dataplane_harness_passed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            report["production_dataplane_admission_scope"]
                .as_str()
                .unwrap(),
            "not-executed"
        );
        assert_eq!(report["admission_plan"].as_array().unwrap().len(), 5);
        assert!(
            report["admission_plan"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["command"].is_null())
        );
        assert!(report["admissions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn production_dataplane_execute_requires_root_gate_ack() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-noack-{}",
            std::process::id()
        ));
        let options = ProductionDataplaneHarnessOptions {
            execute: true,
            ..ProductionDataplaneHarnessOptions::default()
        };
        let err = production_dataplane_harness_report(&root, &options).unwrap_err();
        assert!(err.contains("--ack-root-gate"));
    }

    #[test]
    fn production_dataplane_rejects_zero_benchmark_iters() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-zero-{}",
            std::process::id()
        ));
        let options = ProductionDataplaneHarnessOptions {
            benchmark_iters: 0,
            ..ProductionDataplaneHarnessOptions::default()
        };
        let err = production_dataplane_harness_report(&root, &options).unwrap_err();
        assert!(err.contains("benchmark-iters"));
    }

    #[test]
    fn production_dataplane_owner_profiles_match_admissions() {
        let options = ProductionDataplaneHarnessOptions {
            ack_root_gate: true,
            benchmark_iters: 7,
            ..ProductionDataplaneHarnessOptions::default()
        };
        let specs = dataplane_admission_specs();

        let listener = owner_options_for_admission(specs[0], &options);
        assert!(listener.execute);
        assert!(listener.ack_root_gate);
        assert!(!listener.execute_active_tcp);

        let tcp = owner_options_for_admission(specs[1], &options);
        assert!(tcp.execute_active_tcp);
        assert!(!tcp.execute_active_tcp_relay);

        let relay = owner_options_for_admission(specs[2], &options);
        assert!(relay.execute_active_tcp);
        assert!(relay.execute_active_tcp_relay);
        assert_eq!(relay.active_tcp_benchmark_iters, 7);

        let udp = owner_options_for_admission(specs[3], &options);
        assert!(udp.execute_active_tcp);
        assert!(udp.execute_active_udp);
        assert!(!udp.execute_active_dns);
        assert_eq!(udp.active_udp_benchmark_iters, 7);

        let dns = owner_options_for_admission(specs[4], &options);
        assert!(dns.execute_active_tcp);
        assert!(dns.execute_active_udp);
        assert!(dns.execute_active_dns);
        assert_eq!(dns.active_dns_benchmark_iters, 7);
    }
}
