#[cfg(test)]
mod tests {
    use super::super::*;
    use dae_config::{Global, Routing};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct FakeRuntime {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for FakeRuntime {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn minimal_config() -> Config {
        Config {
            global: Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: Routing::default(),
            dns: Default::default(),
        }
    }

    #[test]
    fn resident_reload_preflight_rejects_missing_interface_before_swap() {
        let mut config = minimal_config();
        config.global.lan_interface = Some(vec!["dae-missing-a4-interface".to_owned()]);
        let err = validate_resident_runtime_reload_config(&config).unwrap_err();
        assert!(err.contains("rejected before current runtime swap"));
        assert!(err.contains("dae-missing-a4-interface"));
    }

    #[test]
    fn resident_reload_swap_restores_previous_runtime_when_next_start_fails() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut current_config = minimal_config();
        current_config.global.log_level = "info".to_owned();
        let mut next_config = current_config.clone();
        next_config.global.log_level = "debug".to_owned();
        let mut runtime = Some(FakeRuntime {
            drops: Arc::clone(&drops),
        });
        let err =
            swap_runtime_with_rollback(&mut runtime, &mut current_config, next_config, |cfg| {
                if cfg.global.log_level == "debug" {
                    Err("simulated next runtime start failure".to_owned())
                } else {
                    Ok(FakeRuntime {
                        drops: Arc::clone(&drops),
                    })
                }
            })
            .unwrap_err();
        assert!(err.contains("simulated next runtime start failure"));
        assert!(err.contains("restored previous resident runtime"));
        assert!(runtime.is_some());
        assert_eq!(current_config.global.log_level, "info");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resident_reload_swap_reports_fatal_when_rollback_start_fails() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut current_config = minimal_config();
        let mut next_config = current_config.clone();
        next_config.global.log_level = "debug".to_owned();
        let mut runtime = Some(FakeRuntime {
            drops: Arc::clone(&drops),
        });
        let err =
            swap_runtime_with_rollback(&mut runtime, &mut current_config, next_config, |_| {
                Err("simulated runtime start failure".to_owned())
            })
            .unwrap_err();
        assert!(err.contains("rollback failed"));
        assert!(runtime.is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resident_dataplane_default_switch_requires_explicit_enable_value() {
        for value in ["1", "true", "TRUE", "on", "ON", "yes", "YES"] {
            assert!(resident_dataplane_default_switch_value_enabled(Some(value)));
        }
        for value in ["", "0", "false", "FALSE", "off", "OFF", "no", "NO"] {
            assert!(!resident_dataplane_default_switch_value_enabled(Some(
                value
            )));
        }
        assert!(!resident_dataplane_default_switch_value_enabled(None));
    }
}
