use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage52Options {
    pub(super) base: Stage50Options,
    pub(super) upstream_mptcp: bool,
    pub(super) benchmark_iters: u32,
    pub(super) dial_mode: TcpDialMode,
    pub(super) domain: String,
    pub(super) domain_is_real: bool,
}

impl Default for Stage52Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE52_ROOT);
        let base = Stage50Options {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            tproxy_port: DEFAULT_STAGE52_TPROXY_PORT,
            target_ip: DEFAULT_STAGE52_TARGET_IP.to_owned(),
            target_port: DEFAULT_STAGE52_TARGET_PORT,
            ..Stage50Options::default()
        };
        Self {
            base,
            upstream_mptcp: true,
            benchmark_iters: 1,
            dial_mode: TcpDialMode::DomainPlusPlus,
            domain: DEFAULT_STAGE52_DOMAIN.to_owned(),
            domain_is_real: true,
        }
    }
}

impl Stage52Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let default_param_object = PathBuf::from(DEFAULT_STAGE52_ROOT).join("bpf_bpfel.param.o");
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.base.root = PathBuf::from(next_value(&mut iter, "stage52 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.base.source_object =
                        PathBuf::from(next_value(&mut iter, "stage52 --object")?);
                }
                "--param-object" => {
                    opts.base.param_object =
                        PathBuf::from(next_value(&mut iter, "stage52 --param-object")?);
                }
                "--execute-smoke" => opts.base.execute_smoke = true,
                "--ack-root-gate" => opts.base.ack_root_gate = true,
                "--peer-section" => {
                    opts.base.peer_section = next_value(&mut iter, "stage52 --peer-section")?;
                }
                "--host-section" => {
                    opts.base.host_section = next_value(&mut iter, "stage52 --host-section")?;
                }
                "--lan-section" => {
                    opts.base.lan_section = next_value(&mut iter, "stage52 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.base.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage52 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.base.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage52 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => {
                    opts.base.target_ip = next_value(&mut iter, "stage52 --target-ip")?;
                }
                "--client-ip" => {
                    opts.base.client_ip = next_value(&mut iter, "stage52 --client-ip")?;
                }
                "--target-port" => {
                    opts.base.target_port =
                        parse_port(&next_value(&mut iter, "stage52 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.base.so_mark =
                        parse_u32(&next_value(&mut iter, "stage52 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.base.mptcp = true,
                "--no-mptcp" => opts.base.mptcp = false,
                "--upstream-mptcp" => opts.upstream_mptcp = true,
                "--upstream-plain-tcp" => opts.upstream_mptcp = false,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_u32(&next_value(&mut iter, "stage52 --benchmark-iters")?, arg)?;
                }
                "--dial-mode" => {
                    opts.dial_mode =
                        parse_tcp_dial_mode(&next_value(&mut iter, "stage52 --dial-mode")?)?;
                }
                "--domain" => opts.domain = next_value(&mut iter, "stage52 --domain")?,
                "--domain-real" => opts.domain_is_real = true,
                "--domain-not-real" => opts.domain_is_real = false,
                _ if arg.starts_with("--root=") => {
                    opts.base.root = PathBuf::from(value_after_equals(arg, "stage52 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.base.source_object =
                        PathBuf::from(value_after_equals(arg, "stage52 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.base.param_object =
                        PathBuf::from(value_after_equals(arg, "stage52 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.base.peer_section = value_after_equals(arg, "stage52 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.base.host_section = value_after_equals(arg, "stage52 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.base.lan_section = value_after_equals(arg, "stage52 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.base.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage52 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.base.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage52 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.base.target_ip = value_after_equals(arg, "stage52 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.base.client_ip = value_after_equals(arg, "stage52 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.base.target_port =
                        parse_port(&value_after_equals(arg, "stage52 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.base.so_mark =
                        parse_u32(&value_after_equals(arg, "stage52 --so-mark")?, arg)?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_u32(&value_after_equals(arg, "stage52 --benchmark-iters")?, arg)?;
                }
                _ if arg.starts_with("--dial-mode=") => {
                    opts.dial_mode =
                        parse_tcp_dial_mode(&value_after_equals(arg, "stage52 --dial-mode")?)?;
                }
                _ if arg.starts_with("--domain=") => {
                    opts.domain = value_after_equals(arg, "stage52 --domain")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage52-active-tcp-route-table-group-relay-admission argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage52 --benchmark-iters must be non-zero",
            ));
        }
        if opts.domain.is_empty() {
            return Err(RunnerOutput::usage("stage52 --domain must be non-empty"));
        }
        Ok(opts)
    }
}
