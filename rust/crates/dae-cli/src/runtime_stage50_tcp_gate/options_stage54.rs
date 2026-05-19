use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage54Options {
    pub(super) base: Stage50Options,
    pub(super) benchmark_iters: u32,
    pub(super) upstream_ip: String,
    pub(super) upstream_port: u16,
    pub(super) qname: String,
}

impl Default for Stage54Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE54_ROOT);
        let base = Stage50Options {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            tproxy_port: DEFAULT_STAGE54_TPROXY_PORT,
            target_ip: DEFAULT_STAGE54_TARGET_IP.to_owned(),
            target_port: DEFAULT_STAGE54_TARGET_PORT,
            ..Stage50Options::default()
        };
        Self {
            base,
            benchmark_iters: 2,
            upstream_ip: DEFAULT_STAGE54_UPSTREAM_IP.to_owned(),
            upstream_port: DEFAULT_STAGE54_UPSTREAM_PORT,
            qname: DEFAULT_STAGE54_QNAME.to_owned(),
        }
    }
}

impl Stage54Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let default_param_object = PathBuf::from(DEFAULT_STAGE54_ROOT).join("bpf_bpfel.param.o");
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.base.root = PathBuf::from(next_value(&mut iter, "stage54 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.base.source_object =
                        PathBuf::from(next_value(&mut iter, "stage54 --object")?);
                }
                "--param-object" => {
                    opts.base.param_object =
                        PathBuf::from(next_value(&mut iter, "stage54 --param-object")?);
                }
                "--execute-smoke" => opts.base.execute_smoke = true,
                "--ack-root-gate" => opts.base.ack_root_gate = true,
                "--peer-section" => {
                    opts.base.peer_section = next_value(&mut iter, "stage54 --peer-section")?;
                }
                "--host-section" => {
                    opts.base.host_section = next_value(&mut iter, "stage54 --host-section")?;
                }
                "--lan-section" => {
                    opts.base.lan_section = next_value(&mut iter, "stage54 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.base.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage54 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.base.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage54 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => {
                    opts.base.target_ip = next_value(&mut iter, "stage54 --target-ip")?;
                }
                "--client-ip" => {
                    opts.base.client_ip = next_value(&mut iter, "stage54 --client-ip")?;
                }
                "--target-port" => {
                    opts.base.target_port =
                        parse_port(&next_value(&mut iter, "stage54 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.base.so_mark =
                        parse_u32(&next_value(&mut iter, "stage54 --so-mark")?, arg)?;
                }
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_u32(&next_value(&mut iter, "stage54 --benchmark-iters")?, arg)?;
                }
                "--upstream-ip" => {
                    opts.upstream_ip = next_value(&mut iter, "stage54 --upstream-ip")?;
                }
                "--upstream-port" => {
                    opts.upstream_port =
                        parse_port(&next_value(&mut iter, "stage54 --upstream-port")?, arg)?;
                }
                "--qname" => opts.qname = next_value(&mut iter, "stage54 --qname")?,
                _ if arg.starts_with("--root=") => {
                    opts.base.root = PathBuf::from(value_after_equals(arg, "stage54 --root")?);
                    if opts.base.param_object == default_param_object {
                        opts.base.param_object = opts.base.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.base.source_object =
                        PathBuf::from(value_after_equals(arg, "stage54 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.base.param_object =
                        PathBuf::from(value_after_equals(arg, "stage54 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.base.peer_section = value_after_equals(arg, "stage54 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.base.host_section = value_after_equals(arg, "stage54 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.base.lan_section = value_after_equals(arg, "stage54 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.base.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage54 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.base.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage54 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.base.target_ip = value_after_equals(arg, "stage54 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.base.client_ip = value_after_equals(arg, "stage54 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.base.target_port =
                        parse_port(&value_after_equals(arg, "stage54 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.base.so_mark =
                        parse_u32(&value_after_equals(arg, "stage54 --so-mark")?, arg)?;
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_u32(&value_after_equals(arg, "stage54 --benchmark-iters")?, arg)?;
                }
                _ if arg.starts_with("--upstream-ip=") => {
                    opts.upstream_ip = value_after_equals(arg, "stage54 --upstream-ip")?;
                }
                _ if arg.starts_with("--upstream-port=") => {
                    opts.upstream_port =
                        parse_port(&value_after_equals(arg, "stage54 --upstream-port")?, arg)?;
                }
                _ if arg.starts_with("--qname=") => {
                    opts.qname = value_after_equals(arg, "stage54 --qname")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage54-active-dns-tproxy-cache-admission argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters < 2 {
            return Err(RunnerOutput::usage(
                "stage54 --benchmark-iters must be at least 2 to cover reload cache restore",
            ));
        }
        if opts.upstream_port == 0 {
            return Err(RunnerOutput::usage(
                "stage54 --upstream-port must be non-zero",
            ));
        }
        if opts.qname.is_empty() {
            return Err(RunnerOutput::usage("stage54 --qname must be non-empty"));
        }
        Ok(opts)
    }
}
