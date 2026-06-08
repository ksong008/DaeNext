fn resident_utls_fingerprint_plan(
    config: &Config,
    link_fingerprint: Option<&str>,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    let link_fingerprint = link_fingerprint.unwrap_or_default().trim();
    if !link_fingerprint.is_empty() && !link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return resolve_optional_resident_utls_fingerprint("link fp", link_fingerprint);
    }
    if link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }

    if config
        .global
        .tls_implementation
        .trim()
        .eq_ignore_ascii_case("utls")
    {
        let global_fingerprint = config.global.utls_imitate.trim();
        if global_fingerprint.is_empty() {
            return resolve_resident_utls_fingerprint("default fingerprint", "chrome").map(Some);
        }
        return resolve_optional_resident_utls_fingerprint(
            "global utls_imitate",
            global_fingerprint,
        );
    }

    Ok(None)
}

fn resolve_optional_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    if requested.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }
    resolve_resident_utls_fingerprint(source, requested).map(Some)
}

fn resolve_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<ResidentUtlsFingerprintPlan, String> {
    let fingerprint = resolve_utls_client_hello_id(requested)
        .map_err(|err| format!("resident dataplane unsupported {source} {requested}: {err}"))?;
    Ok(resident_utls_fingerprint_plan_from(
        source,
        requested,
        fingerprint,
    ))
}

fn resident_utls_fingerprint_plan_from(
    source: &'static str,
    requested: &str,
    fingerprint: UtlsFingerprint,
) -> ResidentUtlsFingerprintPlan {
    ResidentUtlsFingerprintPlan {
        source,
        requested: requested.to_owned(),
        name: fingerprint.name.to_owned(),
        canonical: fingerprint.canonical.to_owned(),
        family: fingerprint.family.to_owned(),
        client: fingerprint.client.to_owned(),
        randomized: fingerprint.randomized,
        alpn_policy: fingerprint.alpn_policy.to_owned(),
    }
}

fn parse_tcp_dial_mode(config: &Config) -> Result<TcpDialMode, String> {
    config
        .global
        .dial_mode
        .parse::<TcpDialMode>()
        .map_err(|err| format!("resident dataplane dial_mode: {err}"))
}

fn tcp_sniffing_timeout(config: &Config, dial_mode: TcpDialMode) -> Duration {
    if dial_mode == TcpDialMode::Ip {
        return Duration::ZERO;
    }
    let nanos = config.global.sniffing_timeout.as_nanos();
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
}
