use super::*;

pub(in crate::daed_product) struct PreparedRuntimeReload {
    pub(in crate::daed_product) plan: RuntimeMaterializationPlan,
    pub(in crate::daed_product) config: Arc<Config>,
    pub(in crate::daed_product) runtime_candidate: PreparedProductRuntime,
    pub(in crate::daed_product) process_transition: Option<Value>,
    pub(in crate::daed_product) preflight_evidence: Value,
    pub(in crate::daed_product) compile_elapsed_ns: u64,
    pub(in crate::daed_product) preflight_elapsed_ns: u64,
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct AppliedRuntimeReload {
    pub(in crate::daed_product) applied: bool,
    pub(in crate::daed_product) coalesced: bool,
    pub(in crate::daed_product) runtime_report: Value,
    pub(in crate::daed_product) materialized_report: Value,
    pub(in crate::daed_product) allocator_reclaim: Value,
    pub(in crate::daed_product) pending_process_transition: Option<Value>,
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) enum RuntimeReloadPrepareError {
    Materialize(String),
    BuildConfig(String),
    NetworkWait(String),
    Preflight(String),
}

impl RuntimeReloadPrepareError {
    pub(in crate::daed_product) fn http_status(&self) -> u16 {
        match self {
            Self::Materialize(_) | Self::BuildConfig(_) => 400,
            Self::NetworkWait(_) => 503,
            Self::Preflight(_) => 409,
        }
    }

    pub(in crate::daed_product) fn api_log_message(&self) -> &'static str {
        match self {
            Self::Materialize(_) => "[Reload] Failed to materialize runtime preview",
            Self::BuildConfig(_) => "[Reload] Failed to build runtime config",
            Self::NetworkWait(_) => "[Runtime] Waiting for network before runtime build failed",
            Self::Preflight(_) => "[Reload] Candidate preflight failed",
        }
    }
}

impl std::fmt::Display for RuntimeReloadPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Materialize(err)
            | Self::BuildConfig(err)
            | Self::NetworkWait(err)
            | Self::Preflight(err) => formatter.write_str(err),
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) enum CoordinatedRuntimeReloadError {
    Prepare(RuntimeReloadPrepareError),
    Apply(String),
}

impl CoordinatedRuntimeReloadError {
    pub(in crate::daed_product) fn http_status(&self) -> u16 {
        match self {
            Self::Prepare(err) => err.http_status(),
            Self::Apply(err) if err.contains("superseded by stop") => 409,
            Self::Apply(_) => 500,
        }
    }

    pub(in crate::daed_product) fn api_log_message(&self) -> &'static str {
        match self {
            Self::Prepare(err) => err.api_log_message(),
            Self::Apply(_) => "[Reload] Failed to reload",
        }
    }
}

impl std::fmt::Display for CoordinatedRuntimeReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prepare(err) => std::fmt::Display::fmt(err, formatter),
            Self::Apply(err) => formatter.write_str(err),
        }
    }
}

#[cfg(test)]
pub(in crate::daed_product) fn prepare_runtime_reload_config(
    state: &Path,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let plan = prepare_runtime_materialization_plan(state)
        .map_err(|err| RuntimeReloadPrepareError::Materialize(err.to_string()))?;
    build_prepared_runtime_reload(plan, false)
}

pub(in crate::daed_product) fn prepare_runtime_reload_preview(
    state: &Path,
) -> Result<RuntimeMaterializationPlan, RuntimeReloadPrepareError> {
    let plan = prepare_runtime_materialization_plan(state)
        .map_err(|err| RuntimeReloadPrepareError::Materialize(err.to_string()))?;
    build_runtime_config_from_content(&plan.content)
        .map_err(RuntimeReloadPrepareError::BuildConfig)?;
    Ok(plan)
}

fn build_prepared_runtime_reload(
    plan: RuntimeMaterializationPlan,
    wait_for_network: bool,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let compile_started = Instant::now();
    let config = Arc::new(
        build_runtime_config_from_content(&plan.content)
            .map_err(RuntimeReloadPrepareError::BuildConfig)?,
    );
    if wait_for_network && !config.global.disable_waiting_network && !config.subscription.is_empty()
    {
        wait_for_network_before_subscriptions(&config)
            .map_err(RuntimeReloadPrepareError::NetworkWait)?;
    }
    let runtime_candidate = prepare_product_runtime_candidate(Arc::clone(&config))
        .map_err(RuntimeReloadPrepareError::Preflight)?
        .with_transition_identity(RuntimeTransitionIdentity {
            routing_version: plan.routing_version,
            geodata_input_version: plan.geodata_input_version,
        });
    Ok(PreparedRuntimeReload {
        plan,
        config,
        runtime_candidate,
        process_transition: None,
        preflight_evidence: Value::Null,
        compile_elapsed_ns: elapsed_nanos(compile_started),
        preflight_elapsed_ns: 0,
    })
}

impl PreparedRuntimeReload {
    fn with_activation_metadata(
        mut self,
        preflight_evidence: Value,
        preflight_elapsed_ns: u64,
        process_transition: Option<Value>,
    ) -> Self {
        self.preflight_evidence = preflight_evidence;
        self.preflight_elapsed_ns = preflight_elapsed_ns;
        self.process_transition = process_transition;
        self
    }
}

pub(in crate::daed_product) fn apply_prepared_runtime_reload(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    source: &str,
    prepared: PreparedRuntimeReload,
    latency_seed: &[Value],
) -> Result<AppliedRuntimeReload, String> {
    let mut checkpoints = NoopFaultCheckpoints;
    let (runtime_report, materialized_report) = apply_runtime_generation(
        runtime,
        state,
        config_dir,
        source,
        prepared,
        latency_seed,
        &mut checkpoints,
    )?;
    runtime.set_runtime_required_for_readiness(true);
    let pending_process_transition = runtime.pending_process_transition();
    Ok(AppliedRuntimeReload {
        applied: true,
        coalesced: false,
        runtime_report,
        materialized_report,
        allocator_reclaim: Value::Null,
        pending_process_transition,
    })
}

pub(in crate::daed_product) fn coordinate_runtime_reload_inner(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    intent: RuntimeApplyIntent,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
) -> Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError> {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Publication);
    let request = runtime.begin_reconcile(intent);
    request.set_phase("reread-desired-state");
    let (plan, modified) =
        match prepare_runtime_materialization_plan_with_modified_state(state, runtime.is_running())
        {
            Ok(snapshot) => snapshot,
            Err(err) => {
                return Err(CoordinatedRuntimeReloadError::Prepare(
                    RuntimeReloadPrepareError::Materialize(err.to_string()),
                ));
            }
        };
    let admission = request
        .admit(&plan.active_fingerprint)
        .map_err(CoordinatedRuntimeReloadError::Apply)?;
    let RuntimeReconcileAdmission::Lead(mut lead) = admission else {
        let RuntimeReconcileAdmission::Follow(follower) = admission else {
            unreachable!("runtime reconcile admission has exactly two variants")
        };
        return follower.wait();
    };
    if let Err(error) = lead.checkpoint("desired-admitted") {
        return lead.finish(Err(error));
    }
    let activation_identity_consistent = if runtime.is_running() {
        match runtime_activation_identity_consistent(state, runtime) {
            Ok(consistent) => consistent,
            Err(error) => {
                return lead.finish(Err(CoordinatedRuntimeReloadError::Apply(error.to_string())));
            }
        }
    } else {
        true
    };
    if runtime.is_running() && !modified && activation_identity_consistent {
        let commit = lead.begin_commit();
        if commit.is_err() {
            let error = commit
                .err()
                .expect("runtime commit admission error was checked");
            return lead.finish(Err(error));
        }
        let permit = commit.expect("runtime commit admission success was checked");
        let runtime_report = runtime.summary();
        permit.finish_coalesced();
        return lead.finish(Ok(AppliedRuntimeReload {
            applied: false,
            coalesced: true,
            runtime_report,
            materialized_report: json!({
                "applied": false,
                "coalesced": true,
                "reason": "active runtime already matches latest desired state",
            }),
            allocator_reclaim: Value::Null,
            pending_process_transition: runtime.pending_process_transition(),
        }));
    }
    if let Err(error) = lead.checkpoint("materializing") {
        return lead.finish(Err(error));
    }
    // Legacy rebuilds the control plane on both startup and reload, so a
    // reload that will pull subscriptions must honor the selected network
    // waiting policy as well.  Dry previews still use the non-waiting helper.
    let prepared = match build_prepared_runtime_reload(plan, true) {
        Ok(prepared) => prepared,
        Err(err) => {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(err)));
        }
    };
    if let Err(error) = lead.checkpoint("compiled") {
        return lead.finish(Err(error));
    }
    if let Err(error) = lead.checkpoint("preflight") {
        return lead.finish(Err(error));
    }
    let preflight_started = Instant::now();
    let preflight_evidence = match preflight_product_runtime_candidate(&prepared.config) {
        Ok(evidence) => evidence,
        Err(err) => {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(
                RuntimeReloadPrepareError::Preflight(err),
            )));
        }
    };
    if let Err(error) = lead.checkpoint("preflight-complete") {
        return lead.finish(Err(error));
    }
    let preflight_elapsed_ns = elapsed_nanos(preflight_started);
    let process_transition = runtime.process_transition_for_config(&prepared.config);
    let prepared = prepared.with_activation_metadata(
        preflight_evidence,
        preflight_elapsed_ns,
        process_transition,
    );
    let previous_pprof_port = runtime.pprof_port();
    if let Err(error) = runtime.configure_pprof_port(prepared.config.global.pprof_port) {
        return lead.finish(Err(CoordinatedRuntimeReloadError::Apply(format!(
            "pprof listener preflight failed: {error}"
        ))));
    }
    let commit = lead.begin_commit();
    if commit.is_err() {
        let error = commit
            .err()
            .expect("runtime commit admission error was checked");
        let _ = runtime.configure_pprof_port(previous_pprof_port);
        return lead.finish(Err(error));
    }
    let permit = commit.expect("runtime commit admission success was checked");
    permit.set_phase("applying");
    let result = apply_prepared_runtime_reload(
        runtime,
        state,
        config_dir,
        intent.source(),
        prepared,
        latency_seed,
    )
    .map_err(CoordinatedRuntimeReloadError::Apply);
    match result {
        Ok(mut applied) => {
            if applied.applied {
                applied.allocator_reclaim = allocator_request_reclaim_for_publication(
                    reclaim_reason,
                    runtime.allocator_publication_id(),
                );
            }
            permit.finish("succeeded");
            lead.finish(Ok(applied))
        }
        Err(err) => {
            let pprof_restore = runtime
                .configure_pprof_port(previous_pprof_port)
                .map_err(|restore| format!("pprof listener rollback failed: {restore}"));
            permit.finish("failed");
            lead.finish(Err(match pprof_restore {
                Ok(()) => err,
                Err(restore) => CoordinatedRuntimeReloadError::Apply(format!("{err}; {restore}")),
            }))
        }
    }
}

pub(in crate::daed_product) fn coordinate_runtime_reload(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    intent: RuntimeApplyIntent,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
) -> Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError> {
    coordinate_runtime_reload_inner(
        runtime,
        state,
        config_dir,
        intent,
        latency_seed,
        reclaim_reason,
    )
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

const NETWORK_WAIT_LINKS: &[&str] = &[
    "http://edge.microsoft.com/captiveportal/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://www.qualcomm.cn/generate_204",
];
const NETWORK_WAIT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const NETWORK_WAIT_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Resolve a probe host with a hard deadline.
///
/// Delegates to the shared bounded resolver in `service_contract`, which runs
/// a single process-lifetime resolver thread: `ToSocketAddrs` (getaddrinfo)
/// has no built-in timeout and can block far longer than the connect timeout
/// on a stalled resolver.  A per-call detached thread would be leaked on
/// timeout; the shared resolver queues stuck resolutions instead and never
/// leaks threads.  The caller gives up after the deadline and fails the
/// probe, which is correct since the network is not usable.
fn resolve_probe_addresses(host: &str, port: u16) -> Vec<std::net::SocketAddr> {
    crate::service_contract::resolve_probe_addresses_bounded(host, port)
}

/// Match legacy's pre-subscription network gate without coupling it to the
/// resident dataplane.  Startup waits until one of the captive-portal probes
/// returns an HTTP status below 500.  The retry budget is bounded by default
/// (60 probe attempts, one every `NETWORK_WAIT_RETRY_DELAY` plus probe time)
/// so an unreachable network fails the reload with a clear error instead of
/// permanently occupying the HTTP worker thread; `DAED_NETWORK_WAIT_MAX_ATTEMPTS`
/// overrides the budget and an explicit 0 opts back into the legacy unbounded
/// behavior.
fn wait_for_network_before_subscriptions(config: &Config) -> Result<(), String> {
    // A probe that already succeeded for this process is authoritative:
    // re-probing here would only re-block the HTTP worker on a network that
    // was reachable.
    if crate::service_contract::network_ready_cached() {
        return Ok(());
    }
    let max_attempts = std::env::var("DAED_NETWORK_WAIT_MAX_ATTEMPTS")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(60);
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        for link in NETWORK_WAIT_LINKS {
            let Ok(url) = url::Url::parse(link) else {
                continue;
            };
            let Some(host) = url.host_str() else {
                continue;
            };
            let port = url.port_or_known_default().unwrap_or(80);
            let addresses = resolve_probe_addresses(host, port);
            for address in addresses {
                let Ok(mut stream) =
                    TcpStream::connect_timeout(&address, NETWORK_WAIT_CONNECT_TIMEOUT)
                else {
                    continue;
                };
                // Bound the whole probe: a peer that accepts the connection
                // but never responds must not wedge the HTTP worker thread.
                let _ = stream.set_read_timeout(Some(NETWORK_WAIT_CONNECT_TIMEOUT));
                let _ = stream.set_write_timeout(Some(NETWORK_WAIT_CONNECT_TIMEOUT));
                let request = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    url.path(),
                    host
                );
                if stream.write_all(request.as_bytes()).is_err() {
                    continue;
                }
                let mut response = [0_u8; 128];
                let Ok(read) = stream.read(&mut response) else {
                    continue;
                };
                let status_ok = std::str::from_utf8(&response[..read])
                    .ok()
                    .and_then(|line| line.strip_prefix("HTTP/"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|status| status.parse::<u16>().ok())
                    .is_some_and(|status| (200..500).contains(&status));
                if status_ok {
                    crate::service_contract::mark_network_ready();
                    return Ok(());
                }
            }
        }
        if max_attempts != 0 && attempts >= max_attempts {
            return Err(format!(
                "network did not become ready after {attempts} probe attempts (max_attempts={max_attempts})"
            ));
        }
        thread::sleep(NETWORK_WAIT_RETRY_DELAY);
        // Keep the parameter in the contract even though the current direct
        // resolver owns its own fallback resolver; callers still get a clear
        // diagnostic when a malformed fallback is supplied.
        let _ = &config.global.fallback_resolver;
    }
}

pub(in crate::daed_product) fn runtime_modified_for_running_runtime(
    state: &Path,
    runtime: &ProductRuntimeManager,
) -> Result<bool, String> {
    if !runtime.is_running() {
        return Ok(false);
    }
    let conn = open_state_connection(state).map_err(|err| err.to_string())?;
    runtime_modified(&conn, true).map_err(|err| err.to_string())
}
