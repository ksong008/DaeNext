use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage137Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) vless_uuid: String,
    pub(super) vmess_uuid: String,
    pub(super) vless_target: String,
    pub(super) vmess_target: String,
    pub(super) xhttp_host: String,
    pub(super) xhttp_path: String,
    pub(super) xhttp_mode: String,
    pub(super) xhttp_security: String,
    pub(super) xhttp_alpn: String,
    pub(super) xhttp_session_id: String,
    pub(super) xhttp_seq: u64,
    pub(super) vless_payload: Vec<u8>,
    pub(super) vmess_payload: Vec<u8>,
    pub(super) timeout: Duration,
}

impl Default for Stage137Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            vless_uuid: DEFAULT_VLESS_UUID.to_owned(),
            vmess_uuid: DEFAULT_VMESS_UUID.to_owned(),
            vless_target: DEFAULT_VLESS_TARGET.to_owned(),
            vmess_target: DEFAULT_VMESS_TARGET.to_owned(),
            xhttp_host: DEFAULT_XHTTP_HOST.to_owned(),
            xhttp_path: DEFAULT_XHTTP_PATH.to_owned(),
            xhttp_mode: DEFAULT_XHTTP_MODE.to_owned(),
            xhttp_security: DEFAULT_XHTTP_SECURITY.to_owned(),
            xhttp_alpn: DEFAULT_XHTTP_ALPN.to_owned(),
            xhttp_session_id: DEFAULT_XHTTP_SESSION_ID.to_owned(),
            xhttp_seq: DEFAULT_XHTTP_SEQ,
            vless_payload: DEFAULT_VLESS_PAYLOAD.to_vec(),
            vmess_payload: DEFAULT_VMESS_PAYLOAD.to_vec(),
            timeout: Duration::from_secs(8),
        }
    }
}

impl Stage137Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage137 --benchmark-iters")?, arg)?;
                }
                "--vless-uuid" => opts.vless_uuid = next_value(&mut iter, "stage137 --vless-uuid")?,
                "--vmess-uuid" => opts.vmess_uuid = next_value(&mut iter, "stage137 --vmess-uuid")?,
                "--vless-target" => {
                    opts.vless_target = next_value(&mut iter, "stage137 --vless-target")?
                }
                "--vmess-target" => {
                    opts.vmess_target = next_value(&mut iter, "stage137 --vmess-target")?
                }
                "--xhttp-host" => opts.xhttp_host = next_value(&mut iter, "stage137 --xhttp-host")?,
                "--xhttp-path" => opts.xhttp_path = next_value(&mut iter, "stage137 --xhttp-path")?,
                "--xhttp-mode" => opts.xhttp_mode = next_value(&mut iter, "stage137 --xhttp-mode")?,
                "--xhttp-security" => {
                    opts.xhttp_security = next_value(&mut iter, "stage137 --xhttp-security")?
                }
                "--xhttp-alpn" => opts.xhttp_alpn = next_value(&mut iter, "stage137 --xhttp-alpn")?,
                "--xhttp-session-id" => {
                    opts.xhttp_session_id = next_value(&mut iter, "stage137 --xhttp-session-id")?
                }
                "--xhttp-seq" => {
                    opts.xhttp_seq =
                        parse_u64(&next_value(&mut iter, "stage137 --xhttp-seq")?, arg)?;
                }
                "--vless-payload" => {
                    opts.vless_payload =
                        next_value(&mut iter, "stage137 --vless-payload")?.into_bytes()
                }
                "--vmess-payload" => {
                    opts.vmess_payload =
                        next_value(&mut iter, "stage137 --vmess-payload")?.into_bytes()
                }
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage137 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--vless-uuid=") => {
                    opts.vless_uuid = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--vmess-uuid=") => {
                    opts.vmess_uuid = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--vless-target=") => {
                    opts.vless_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--vmess-target=") => {
                    opts.vmess_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-host=") => {
                    opts.xhttp_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-path=") => {
                    opts.xhttp_path = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-mode=") => {
                    opts.xhttp_mode = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-security=") => {
                    opts.xhttp_security = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-alpn=") => {
                    opts.xhttp_alpn = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-session-id=") => {
                    opts.xhttp_session_id = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-seq=") => {
                    opts.xhttp_seq = parse_u64(arg.split_once('=').unwrap().1, "--xhttp-seq")?;
                }
                _ if arg.starts_with("--vless-payload=") => {
                    opts.vless_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--vmess-payload=") => {
                    opts.vmess_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    let timeout_ms = parse_u64(arg.split_once('=').unwrap().1, "--timeout-ms")?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage137 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage137 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.vless_uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage137 vless uuid is invalid: {err}")))?;
        vmess::vmess_cmd_key_from_uuid(&opts.vmess_uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage137 vmess uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.vless_target).map_err(|err| {
            RunnerOutput::usage(format!("stage137 vless target is invalid: {err}"))
        })?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.vmess_target).map_err(|err| {
            RunnerOutput::usage(format!("stage137 vmess target is invalid: {err}"))
        })?;
        opts.xhttp_options_for_seq(opts.xhttp_seq)
            .map_err(|err| RunnerOutput::usage(format!("stage137 xhttp options invalid: {err}")))?;
        if opts.xhttp_mode != "packet-up" {
            return Err(RunnerOutput::usage(
                "stage137 --xhttp-mode must remain packet-up",
            ));
        }
        if opts.xhttp_alpn != "h3" {
            return Err(RunnerOutput::usage(
                "stage137 --xhttp-alpn must remain h3 for the H3 gate",
            ));
        }
        Ok(opts)
    }

    pub(super) fn xhttp_options_for_seq(
        &self,
        seq: u64,
    ) -> Result<shared_transport::XHttpLifecycleOptions, dae_outbound::OutboundError> {
        shared_transport::XHttpLifecycleOptions::new(
            &self.xhttp_host,
            &self.xhttp_path,
            &self.xhttp_mode,
            &self.xhttp_security,
            &self.xhttp_alpn,
            &self.xhttp_session_id,
            seq,
        )
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

fn parse_u64(value: &str, flag: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
}
