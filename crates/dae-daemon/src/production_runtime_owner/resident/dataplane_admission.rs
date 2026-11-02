use super::*;

pub(super) fn validate_prepared_dataplane(
    prepared: &ResidentPreparedDataplane,
) -> Result<(), String> {
    if !resident_dataplane_enabled() {
        return Err(format!(
            "resident production runtime requires {DEFAULT_RESIDENT_DATAPLANE_ENV}=1; userspace dataplane is explicitly disabled"
        ));
    }
    prepared.require_enabled()
}

pub(super) fn validate_started_dataplane(
    report: &Value,
    runtime_present: bool,
    listeners_published: bool,
) -> Result<(), String> {
    if report["status"].as_str() != Some("pass")
        || report["enabled"].as_bool() != Some(true)
        || !runtime_present
        || !listeners_published
    {
        return Err(format!(
            "resident dataplane is not ready: status={}, enabled={}, runtime_present={runtime_present}, listeners_published={listeners_published}",
            report["status"], report["enabled"]
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_attach_requires_every_dataplane_ready_condition() {
        let ready = json!({"status": "pass", "enabled": true});
        assert!(validate_started_dataplane(&ready, true, true).is_ok());
        for report in [
            json!({"status": "fail", "enabled": true}),
            json!({"status": "pass", "enabled": false}),
            json!({"status": "pass"}),
            Value::Null,
        ] {
            assert!(validate_started_dataplane(&report, true, true).is_err());
        }
        assert!(validate_started_dataplane(&ready, false, true).is_err());
        assert!(validate_started_dataplane(&ready, true, false).is_err());
    }

    #[test]
    fn disabled_plan_is_rejected_before_runtime_artifacts_or_kernel_preflight() {
        const CHILD: &str = "DAE_TEST_DISABLED_PLAN_CHILD";
        if env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "production_runtime_owner::resident::dataplane_admission::tests::disabled_plan_is_rejected_before_runtime_artifacts_or_kernel_preflight", "--nocapture"])
                .env(CHILD, "1")
                .env_remove(DEFAULT_RESIDENT_DATAPLANE_ENV)
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let config = dae_config::empty_config().unwrap();
        let error =
            match start_resident_production_runtime_with_asset_dirs(&config, Vec::<PathBuf>::new())
            {
                Ok(_) => panic!("disabled resident plan unexpectedly started"),
                Err(error) => error,
            };
        assert!(
            error.contains("requires an enabled userspace dataplane"),
            "{error}"
        );
    }

    #[test]
    fn environment_disabled_is_rejected_before_kernel_preflight() {
        const CHILD: &str = "DAE_TEST_DISABLED_DATAPLANE_CHILD";
        if env::var_os(CHILD).is_some() {
            let error = match start_resident_production_runtime_with_asset_dirs(
                &dae_config::empty_config().unwrap(),
                Vec::<PathBuf>::new(),
            ) {
                Ok(_) => panic!("environment-disabled resident dataplane started"),
                Err(error) => error,
            };
            assert!(
                error.contains("userspace dataplane is explicitly disabled"),
                "{error}"
            );
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "production_runtime_owner::resident::dataplane_admission::tests::environment_disabled_is_rejected_before_kernel_preflight", "--nocapture"])
            .env(CHILD, "1")
            .env(DEFAULT_RESIDENT_DATAPLANE_ENV, "0")
            .status().unwrap();
        assert!(status.success());
    }
}
