use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage134Options {
    pub(super) execute_smoke: bool,
    pub(super) benchmark_iters: usize,
    pub(super) vless_uuid: String,
    pub(super) vmess_uuid: String,
    pub(super) vless_target: String,
    pub(super) vmess_target: String,
    pub(super) grpc_address: String,
    pub(super) grpc_service_name: String,
    pub(super) grpc_server_name: String,
    pub(super) grpc_dialer_id: String,
    pub(super) allow_insecure: bool,
    pub(super) vless_payload: Vec<u8>,
    pub(super) vmess_payload: Vec<u8>,
    pub(super) so_mark: u32,
    pub(super) mptcp: bool,
    pub(super) timeout: Duration,
}

impl Default for Stage134Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            vless_uuid: DEFAULT_VLESS_UUID.to_owned(),
            vmess_uuid: DEFAULT_VMESS_UUID.to_owned(),
            vless_target: DEFAULT_VLESS_TARGET.to_owned(),
            vmess_target: DEFAULT_VMESS_TARGET.to_owned(),
            grpc_address: DEFAULT_GRPC_ADDRESS.to_owned(),
            grpc_service_name: DEFAULT_GRPC_SERVICE_NAME.to_owned(),
            grpc_server_name: DEFAULT_GRPC_SERVER_NAME.to_owned(),
            grpc_dialer_id: DEFAULT_GRPC_DIALER_ID.to_owned(),
            allow_insecure: true,
            vless_payload: DEFAULT_VLESS_PAYLOAD.to_vec(),
            vmess_payload: DEFAULT_VMESS_PAYLOAD.to_vec(),
            so_mark: 1340,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage134Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage134 --benchmark-iters")?, arg)?;
                }
                "--vless-uuid" => opts.vless_uuid = next_value(&mut iter, "stage134 --vless-uuid")?,
                "--vmess-uuid" => opts.vmess_uuid = next_value(&mut iter, "stage134 --vmess-uuid")?,
                "--vless-target" => {
                    opts.vless_target = next_value(&mut iter, "stage134 --vless-target")?
                }
                "--vmess-target" => {
                    opts.vmess_target = next_value(&mut iter, "stage134 --vmess-target")?
                }
                "--grpc-address" => {
                    opts.grpc_address = next_value(&mut iter, "stage134 --grpc-address")?
                }
                "--grpc-service-name" => {
                    opts.grpc_service_name = next_value(&mut iter, "stage134 --grpc-service-name")?
                }
                "--grpc-server-name" => {
                    opts.grpc_server_name = next_value(&mut iter, "stage134 --grpc-server-name")?
                }
                "--grpc-dialer-id" => {
                    opts.grpc_dialer_id = next_value(&mut iter, "stage134 --grpc-dialer-id")?
                }
                "--allow-insecure" => opts.allow_insecure = true,
                "--no-allow-insecure" => opts.allow_insecure = false,
                "--vless-payload" => {
                    opts.vless_payload =
                        next_value(&mut iter, "stage134 --vless-payload")?.into_bytes()
                }
                "--vmess-payload" => {
                    opts.vmess_payload =
                        next_value(&mut iter, "stage134 --vmess-payload")?.into_bytes()
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage134 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage134 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--grpc-address=") => {
                    opts.grpc_address = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--grpc-service-name=") => {
                    opts.grpc_service_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--grpc-server-name=") => {
                    opts.grpc_server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--grpc-dialer-id=") => {
                    opts.grpc_dialer_id = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--vless-payload=") => {
                    opts.vless_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--vmess-payload=") => {
                    opts.vmess_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
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
                        "unsupported stage134 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage134 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.vless_uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage134 vless uuid is invalid: {err}")))?;
        vmess::vmess_cmd_key_from_uuid(&opts.vmess_uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage134 vmess uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.vless_target).map_err(|err| {
            RunnerOutput::usage(format!("stage134 vless target is invalid: {err}"))
        })?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.vmess_target).map_err(|err| {
            RunnerOutput::usage(format!("stage134 vmess target is invalid: {err}"))
        })?;
        if opts.grpc_address.is_empty() {
            return Err(RunnerOutput::usage(
                "stage134 --grpc-address must not be empty",
            ));
        }
        if opts.grpc_dialer_id.is_empty() {
            return Err(RunnerOutput::usage(
                "stage134 --grpc-dialer-id must not be empty",
            ));
        }
        Ok(opts)
    }

    pub(super) fn grpc_options(&self, address: &str) -> shared_transport::GrpcLifecycleOptions {
        shared_transport::GrpcLifecycleOptions::new(
            address,
            &self.grpc_service_name,
            &self.grpc_server_name,
            &self.grpc_dialer_id,
            self.allow_insecure,
            self.so_mark,
            self.mptcp,
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
