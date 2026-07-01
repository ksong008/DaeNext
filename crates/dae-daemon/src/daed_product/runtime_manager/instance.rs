use super::*;

pub(in crate::daed_product) fn runtime_started_at_after_success(
    previous_runtime_was_running: bool,
    previous_runtime_started_at: Option<String>,
    transition_at: String,
) -> String {
    if previous_runtime_was_running {
        previous_runtime_started_at.unwrap_or(transition_at)
    } else {
        transition_at
    }
}

#[allow(dead_code)]
pub(in crate::daed_product) fn start_product_runtime_instance(
    config: &Config,
    source: &str,
    latency_seed: &[Value],
) -> Result<(ProductRuntimeInstance, Value), String> {
    start_product_runtime_instance_with_dns_reload_snapshot(config, source, latency_seed, None)
}

pub(in crate::daed_product) fn start_product_runtime_instance_with_dns_reload_snapshot(
    config: &Config,
    source: &str,
    latency_seed: &[Value],
    dns_reload_snapshot: Option<ResidentDnsReloadSnapshot>,
) -> Result<(ProductRuntimeInstance, Value), String> {
    if product_runtime_fake_start_enabled() {
        let started_at = now_text();
        let report = json!({
            "status": "pass",
            "runtimeControl": "fake-resident-runtime-test-only",
            "source": source,
            "fakeRuntime": true,
            "startedAt": started_at,
            "tproxyPort": config.global.tproxy_port,
        });
        return Ok((
            ProductRuntimeInstance::Fake(FakeProductRuntime {
                started_at,
                tproxy_port: config.global.tproxy_port,
            }),
            report,
        ));
    }

    crate::service_contract::validate_resident_runtime_reload_config(config)?;

    let mut runtime = start_resident_production_runtime_with_latency_seed_and_dns_reload_snapshot(
        config,
        latency_seed,
        dns_reload_snapshot,
    )?;
    let state = runtime.product_state_summary();
    let dataplane_enabled = state["residentDataplane"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    let dataplane_status = state["residentDataplane"]["status"].as_str().unwrap_or("");
    if !dataplane_enabled || dataplane_status != "pass" {
        let dataplane_detail = resident_dataplane_admission_detail(&state);
        let _ = runtime.cleanup();
        return Err(format!(
            "resident production runtime started without admitted userspace dataplane: {dataplane_detail}; set {}=1 and require resident_dataplane.status=pass before Rust daed can be the production product path",
            crate::service_contract::RESIDENT_DATAPLANE_ENV
        ));
    }
    let report = json!({
        "status": "pass",
        "runtimeControl": "resident-production-runtime-manager",
        "source": source,
        "fakeRuntime": false,
        "tproxyPort": config.global.tproxy_port,
        "residentDataplane": state["residentDataplane"].clone(),
        "residentStartupEvidence": state["startupEvidence"].clone(),
    });
    Ok((ProductRuntimeInstance::Resident(runtime), report))
}

pub(in crate::daed_product) fn product_runtime_fake_start_enabled() -> bool {
    std::env::var(PRODUCT_RUNTIME_FAKE_START_ENV)
        .or_else(|_| std::env::var(PRODUCT_RUNTIME_FAKE_START_LEGACY_ENV))
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES"
            )
        })
        .unwrap_or(false)
}

pub(in crate::daed_product) fn resident_dataplane_admission_detail(state: &Value) -> String {
    let dataplane = &state["residentDataplane"];
    for key in ["error", "reason", "message"] {
        if let Some(value) = dataplane
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return value.to_owned();
        }
    }
    let enabled = dataplane.get("enabled").and_then(Value::as_bool);
    let status = dataplane.get("status").and_then(Value::as_str);
    format!(
        "resident_dataplane.enabled={}, resident_dataplane.status={}",
        enabled
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        status.unwrap_or("unknown")
    )
}
