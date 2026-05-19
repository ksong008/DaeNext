use super::*;

pub(super) fn run_http(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_http_contract(),
        Some("link") => run_http_link(&args[1..]),
        Some("connect") => run_http_connect(&args[1..]),
        Some("forward") => run_http_forward(&args[1..]),
        Some("smoke") => run_http_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound http subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound http subcommand"),
    }
}

pub(super) fn run_http_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "stage15-http-native-optin",
            "default_go_path": http_proxy::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": http_proxy::contract::ADAPTER_MODE,
            "protocol_scope": http_proxy::contract::PROTOCOL_SCOPE,
            "allow_insecure_aliases": http_proxy::contract::ALLOW_INSECURE_ALIASES,
            "https": {
                "default_port": 443,
                "default_alpn_query_value": http_proxy::contract::HTTPS_DEFAULT_ALPN_QUERY_VALUE,
                "default_tls_implementation": http_proxy::contract::HTTPS_DEFAULT_TLS_IMPLEMENTATION,
                "h2_route_context_required": http_proxy::contract::HTTPS_H2_ROUTE_CONTEXT_REQUIRED,
            },
            "live_smoke_required": http_proxy::contract::LIVE_SMOKE_REQUIRED,
        })
    ))
}

pub(super) fn run_http_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound http link --link");
    };
    match HttpProxyLink::parse(link) {
        Ok(parsed) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "input": link,
                "server": parsed.server,
                "port": parsed.port,
                "username": parsed.username,
                "password": parsed.password,
                "sni": parsed.sni,
                "effective_sni": parsed.effective_sni(),
                "protocol": parsed.protocol.as_str(),
                "allowInsecure": parsed.allow_insecure,
                "export": parsed.export_url(),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_http_connect(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound http connect --target");
    };
    let options = http_options_from_args(target, args);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "target": options.target,
            "transport": options.transport.enabled,
            "request_hex": hex_encode(&http_request::connect_request(&options)),
            "basic_auth_header": http_request::basic_auth_header(&options.username, &options.password),
        })
    ))
}

pub(super) fn run_http_forward(args: &[String]) -> RunnerOutput {
    let Some(raw_hex) = string_arg(args, "--raw-hex") else {
        return RunnerOutput::usage("missing outbound http forward --raw-hex");
    };
    let raw = match hex_decode(raw_hex) {
        Ok(raw) => raw,
        Err(err) => return RunnerOutput::stdout_error(err),
    };
    match http_request::forward_http_request(&raw) {
        Ok(request) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "request_hex": hex_encode(&request),
                "proxy_connection_removed": true,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_http_smoke(args: &[String]) -> RunnerOutput {
    let Some(proxy) = string_arg(args, "--proxy") else {
        return RunnerOutput::usage("missing outbound http smoke --proxy");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound http smoke --target");
    };
    let timeout_ms = match u64_arg(args, "--timeout-ms").unwrap_or(Ok(2000)) {
        Ok(value) => value,
        Err(message) => return RunnerOutput::usage(message),
    };
    let options = http_options_from_args(target, args);
    match http_smoke(proxy, &options, Duration::from_millis(timeout_ms)) {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err),
    }
}

pub(super) fn http_options_from_args(target: &str, args: &[String]) -> HttpConnectOptions {
    let mut options = HttpConnectOptions::connect(target);
    options.username = string_arg(args, "--username").unwrap_or("").to_owned();
    options.password = string_arg(args, "--password").unwrap_or("").to_owned();
    options.host_override = string_arg(args, "--host").unwrap_or("").to_owned();
    options.transport.enabled = bool_arg(args, "--transport").unwrap_or(false);
    options.transport.path = string_arg(args, "--path").unwrap_or("/").to_owned();
    options
}

pub(super) fn http_smoke(
    proxy: &str,
    options: &HttpConnectOptions,
    timeout: Duration,
) -> Result<String, String> {
    let mut stream = TcpStream::connect(proxy).map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| err.to_string())?;
    let request = http_request::connect_request(options);
    stream.write_all(&request).map_err(|err| err.to_string())?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let n = stream.read(&mut buf).map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let status = http_request::parse_connect_response(&response).map_err(|err| err.to_string())?;
    if status != 200 {
        return Err(format!("http proxy status: {status}"));
    }
    Ok(format!(
        "{}",
        json!({
            "ok": true,
            "proxy": proxy,
            "target": options.target,
            "transport": options.transport.enabled,
            "status": status,
            "request_hex": hex_encode(&request),
        })
    ))
}
