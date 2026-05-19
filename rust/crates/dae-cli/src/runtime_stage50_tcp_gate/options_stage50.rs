use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage50Options {
    pub(super) root: PathBuf,
    pub(super) source_object: PathBuf,
    pub(super) param_object: PathBuf,
    pub(super) execute_smoke: bool,
    pub(super) ack_root_gate: bool,
    pub(super) peer_section: String,
    pub(super) host_section: String,
    pub(super) lan_section: String,
    pub(super) tproxy_port: u16,
    pub(super) dae_netns_id: u32,
    pub(super) target_ip: String,
    pub(super) client_ip: String,
    pub(super) target_port: u16,
    pub(super) so_mark: u32,
    pub(super) mptcp: bool,
}

impl Default for Stage50Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE50_ROOT);
        Self {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            source_object: PathBuf::from(DEFAULT_STAGE50_SOURCE_OBJECT),
            execute_smoke: false,
            ack_root_gate: false,
            peer_section: DEFAULT_STAGE50_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE50_HOST_SECTION.to_owned(),
            lan_section: DEFAULT_STAGE50_LAN_SECTION.to_owned(),
            tproxy_port: DEFAULT_STAGE50_TPROXY_PORT,
            dae_netns_id: DEFAULT_STAGE50_DAE_NETNS_ID,
            target_ip: DEFAULT_STAGE50_TARGET_IP.to_owned(),
            client_ip: DEFAULT_STAGE50_CLIENT_IP.to_owned(),
            target_port: DEFAULT_STAGE50_TARGET_PORT,
            so_mark: 1234,
            mptcp: true,
        }
    }
}

impl Stage50Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.root = PathBuf::from(next_value(&mut iter, "stage50 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE50_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.source_object = PathBuf::from(next_value(&mut iter, "stage50 --object")?);
                }
                "--param-object" => {
                    opts.param_object =
                        PathBuf::from(next_value(&mut iter, "stage50 --param-object")?);
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage50 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage50 --host-section")?;
                }
                "--lan-section" => {
                    opts.lan_section = next_value(&mut iter, "stage50 --lan-section")?;
                }
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage50 --tproxy-port")?, arg)?;
                }
                "--dae-netns-id" => {
                    opts.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage50 --dae-netns-id")?, arg)?;
                }
                "--target-ip" => opts.target_ip = next_value(&mut iter, "stage50 --target-ip")?,
                "--client-ip" => opts.client_ip = next_value(&mut iter, "stage50 --client-ip")?,
                "--target-port" => {
                    opts.target_port =
                        parse_port(&next_value(&mut iter, "stage50 --target-port")?, arg)?;
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage50 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage50 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE50_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.source_object =
                        PathBuf::from(value_after_equals(arg, "stage50 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.param_object =
                        PathBuf::from(value_after_equals(arg, "stage50 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage50 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage50 --host-section")?;
                }
                _ if arg.starts_with("--lan-section=") => {
                    opts.lan_section = value_after_equals(arg, "stage50 --lan-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage50 --tproxy-port")?, arg)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage50 --dae-netns-id")?, arg)?;
                }
                _ if arg.starts_with("--target-ip=") => {
                    opts.target_ip = value_after_equals(arg, "stage50 --target-ip")?;
                }
                _ if arg.starts_with("--client-ip=") => {
                    opts.client_ip = value_after_equals(arg, "stage50 --client-ip")?;
                }
                _ if arg.starts_with("--target-port=") => {
                    opts.target_port =
                        parse_port(&value_after_equals(arg, "stage50 --target-port")?, arg)?;
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(&value_after_equals(arg, "stage50 --so-mark")?, arg)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage50-active-tcp-tproxy-ingress-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}
