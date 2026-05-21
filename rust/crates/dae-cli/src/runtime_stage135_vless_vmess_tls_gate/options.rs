use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage135Options {
    pub(super) execute_smoke: bool,
    pub(super) ack_root_gate: bool,
    pub(super) benchmark_iters: usize,
    pub(super) uuid: String,
    pub(super) tls_server_name: String,
    pub(super) alpn_protocol: String,
    pub(super) vless_wss_target: String,
    pub(super) vmess_wss_target: String,
    pub(super) vless_httpupgrade_target: String,
    pub(super) vmess_httpupgrade_target: String,
    pub(super) wss_host: String,
    pub(super) wss_path: String,
    pub(super) httpupgrade_host: String,
    pub(super) httpupgrade_path: String,
    pub(super) payload: Vec<u8>,
    pub(super) so_mark: u32,
    pub(super) mptcp: bool,
    pub(super) timeout: Duration,
}

impl Default for Stage135Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            tls_server_name: DEFAULT_TLS_SERVER_NAME.to_owned(),
            alpn_protocol: shared_transport::DEFAULT_TLS_ALPN.to_owned(),
            vless_wss_target: DEFAULT_VLESS_WSS_TARGET.to_owned(),
            vmess_wss_target: DEFAULT_VMESS_WSS_TARGET.to_owned(),
            vless_httpupgrade_target: DEFAULT_VLESS_HTTPUPGRADE_TARGET.to_owned(),
            vmess_httpupgrade_target: DEFAULT_VMESS_HTTPUPGRADE_TARGET.to_owned(),
            wss_host: DEFAULT_WSS_HOST.to_owned(),
            wss_path: DEFAULT_WSS_PATH.to_owned(),
            httpupgrade_host: DEFAULT_HTTPUPGRADE_HOST.to_owned(),
            httpupgrade_path: DEFAULT_HTTPUPGRADE_PATH.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1350,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage135Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage135 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage135 --uuid")?,
                "--tls-server-name" => {
                    opts.tls_server_name = next_value(&mut iter, "stage135 --tls-server-name")?
                }
                "--alpn" => opts.alpn_protocol = next_value(&mut iter, "stage135 --alpn")?,
                "--wss-host" => opts.wss_host = next_value(&mut iter, "stage135 --wss-host")?,
                "--wss-path" => opts.wss_path = next_value(&mut iter, "stage135 --wss-path")?,
                "--httpupgrade-host" => {
                    opts.httpupgrade_host = next_value(&mut iter, "stage135 --httpupgrade-host")?
                }
                "--httpupgrade-path" => {
                    opts.httpupgrade_path = next_value(&mut iter, "stage135 --httpupgrade-path")?
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage135 --payload")?.into_bytes()
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage135 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage135 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--uuid=") => {
                    opts.uuid = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--tls-server-name=") => {
                    opts.tls_server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--alpn=") => {
                    opts.alpn_protocol = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--wss-host=") => {
                    opts.wss_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--wss-path=") => {
                    opts.wss_path = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--httpupgrade-host=") => {
                    opts.httpupgrade_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--httpupgrade-path=") => {
                    opts.httpupgrade_path = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(arg.split_once('=').unwrap().1, "--so-mark")?;
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    let timeout_ms = parse_u64(arg.split_once('=').unwrap().1, "--timeout-ms")?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage135 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage135 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage135 uuid is invalid: {err}")))?;
        vmess::vmess_cmd_key_from_uuid(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage135 vmess uuid is invalid: {err}")))?;
        for (label, target) in [
            ("vless wss", &opts.vless_wss_target),
            ("vmess wss", &opts.vmess_wss_target),
            ("vless httpupgrade", &opts.vless_httpupgrade_target),
            ("vmess httpupgrade", &opts.vmess_httpupgrade_target),
        ] {
            dae_outbound::VMessMetadata::parse("tcp", target).map_err(|err| {
                RunnerOutput::usage(format!("stage135 {label} target is invalid: {err}"))
            })?;
        }
        opts.tls_options()
            .map_err(|err| RunnerOutput::usage(format!("stage135 tls options invalid: {err}")))?;
        normalize_path(&mut opts.wss_path);
        normalize_path(&mut opts.httpupgrade_path);
        if opts.wss_host.trim().is_empty() || opts.httpupgrade_host.trim().is_empty() {
            return Err(RunnerOutput::usage(
                "stage135 host options must not be empty",
            ));
        }
        Ok(opts)
    }

    pub(super) fn tls_options(
        &self,
    ) -> Result<shared_transport::TlsUnderlayOptions, dae_outbound::OutboundError> {
        shared_transport::TlsUnderlayOptions::new(&self.tls_server_name, &self.alpn_protocol)
    }
}

fn normalize_path(path: &mut String) {
    if path.is_empty() {
        *path = "/".to_owned();
    } else if !path.starts_with('/') {
        *path = format!("/{path}");
    }
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    context: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("{context} requires a value")))
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, RunnerOutput> {
    value
        .parse::<usize>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
}

fn parse_u32(value: &str, flag: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
}
