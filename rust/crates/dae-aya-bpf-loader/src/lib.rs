use std::path::PathBuf;

use serde_json::json;

#[cfg(feature = "native-ebpf")]
const EMBEDDED_NATIVE_AYA_OBJECT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dae-native-bpf_bpfel.o"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl LoaderOutput {
    fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BpfLoaderLoadPinOptions {
    object: Option<PathBuf>,
    pin_root: PathBuf,
    tproxy_port: u16,
    control_plane_pid: u32,
    dae0_ifindex: u32,
    dae_netns_id: u32,
    dae0peer_mac: [u8; 6],
    has_bpf_get_current_task: bool,
}

pub fn run_with_args(args: impl IntoIterator<Item = impl Into<String>>) -> LoaderOutput {
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("bpf-loader") => run_bpf_loader_command(&args[1..]),
        Some("contract") if args.len() == 1 => run_contract(),
        Some("load-pin") => run_load_pin_command(&args[1..]),
        Some(command) => {
            LoaderOutput::usage(format!("unsupported dae-aya-bpf-loader command: {command}"))
        }
        None => LoaderOutput::usage("missing dae-aya-bpf-loader command"),
    }
}

pub fn run_bpf_loader_command(args: &[String]) -> LoaderOutput {
    match args.first().map(String::as_str) {
        Some("contract") if args.len() == 1 => run_contract(),
        Some("load-pin") => run_load_pin_command(&args[1..]),
        Some(subcommand) => {
            LoaderOutput::usage(format!("unsupported bpf-loader subcommand: {subcommand}"))
        }
        None => LoaderOutput::usage("missing bpf-loader subcommand"),
    }
}

fn run_contract() -> LoaderOutput {
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "name": "rust-aya-bpf-loader-go-adoption-contract-v1",
            "binary": "dae-aya-bpf-loader",
            "compiled_native_ebpf": cfg!(feature = "native-ebpf"),
            "scope": "Rust/Aya loads the existing C eBPF object and pins all maps/programs for Go control-plane adoption",
            "go_userspace_outbound_remains_authoritative": true,
            "go_bpf_loader_removed_when_opted_in": true,
            "kernel_ebpf_program_rewrite": false,
            "required_pins": {
                "maps": "pin_root/maps/<map_name>",
                "programs": "pin_root/programs/<program_name>"
            },
            "object_source": "optional --object path or embedded native Aya object built from control/kern/tproxy.c with DAE_AYA_EBPF_OBJECT",
            "param_source": {
                "tproxy_port": "host-order u16, converted to BPF big-endian PARAM",
                "control_plane_pid": "Go control-plane pid",
                "dae0_ifindex": "initialized dae0 ifindex",
                "dae_netns_id": "initialized dae netns id",
                "dae0peer_mac": "initialized dae0peer mac",
                "has_bpf_get_current_task": "Go feature probe result"
            }
        })
    ))
}

fn run_load_pin_command(args: &[String]) -> LoaderOutput {
    match parse_load_pin_options(args) {
        Ok(options) => run_load_pin(options),
        Err(err) => LoaderOutput::usage(err),
    }
}

#[cfg(feature = "native-ebpf")]
fn run_load_pin(options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    use dae_ebpf_support::{
        AyaUserspaceLoaderOptions, DaeParamInput, build_dae_param, load_aya_userspace_object,
        pin_aya_loaded_object_for_go_adoption,
    };

    let (object, mut cleanup_object) = match options.object {
        Some(object) => (object, None),
        None => match write_embedded_native_aya_object() {
            Ok((object, cleanup)) => (object, Some(cleanup)),
            Err(err) => return LoaderOutput::error(err),
        },
    };
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: options.control_plane_pid,
        dae0_ifindex: options.dae0_ifindex,
        dae_netns_id: options.dae_netns_id,
        dae0peer_mac: options.dae0peer_mac,
        has_bpf_get_current_task: options.has_bpf_get_current_task,
    });
    let map_pin_root = options.pin_root.join("maps");
    let mut loaded = match load_aya_userspace_object(AyaUserspaceLoaderOptions {
        object: &object,
        param: Some(param),
        map_pin_path: Some(&map_pin_root),
        allow_unsupported_maps: true,
        max_entries_overrides: &[],
        prepin_lpm_array_map: true,
    }) {
        Ok(loaded) => loaded,
        Err(err) => {
            if let Some(cleanup) = cleanup_object.take() {
                cleanup();
            }
            return LoaderOutput::error(err);
        }
    };
    let pin_report = match pin_aya_loaded_object_for_go_adoption(&mut loaded, &options.pin_root) {
        Ok(report) => report,
        Err(err) => {
            if let Some(cleanup) = cleanup_object.take() {
                cleanup();
            }
            return LoaderOutput::error(err);
        }
    };
    let object_source = if cleanup_object.is_some() {
        "embedded-native-aya"
    } else {
        "explicit"
    };
    if let Some(cleanup) = cleanup_object.take() {
        cleanup();
    }
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust-aya",
            "object": object,
            "object_source": object_source,
            "pin_root": pin_report.adoption_pin_root,
            "map_pin_root": pin_report.map_pin_root,
            "program_pin_root": pin_report.program_pin_root,
            "maps": pin_report.maps.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "programs": pin_report.programs.iter().map(|pin| json!({
                "name": pin.name,
                "path": pin.path,
            })).collect::<Vec<_>>(),
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
            "go_adoption_ready": true,
        })
    ))
}

#[cfg(feature = "native-ebpf")]
fn write_embedded_native_aya_object() -> Result<(PathBuf, impl FnOnce()), String> {
    let path = std::env::temp_dir().join(format!(
        "dae-native-bpf-{}-{}.o",
        std::process::id(),
        fastrand::u64(..)
    ));
    std::fs::write(&path, EMBEDDED_NATIVE_AYA_OBJECT).map_err(|err| {
        format!(
            "write embedded native Aya object {} failed: {err}",
            path.display()
        )
    })?;
    let cleanup_path = path.clone();
    Ok((path, move || {
        let _ = std::fs::remove_file(cleanup_path);
    }))
}

#[cfg(not(feature = "native-ebpf"))]
fn run_load_pin(_options: BpfLoaderLoadPinOptions) -> LoaderOutput {
    LoaderOutput::error("bpf-loader load-pin requires dae-aya-bpf-loader feature native-ebpf")
}

fn parse_load_pin_options(args: &[String]) -> Result<BpfLoaderLoadPinOptions, String> {
    let mut object = None;
    let mut pin_root = None;
    let mut tproxy_port = None;
    let mut control_plane_pid = None;
    let mut dae0_ifindex = None;
    let mut dae_netns_id = None;
    let mut dae0peer_mac = None;
    let mut has_bpf_get_current_task = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--object" => {
                object = Some(parse_next_path(&mut iter, "bpf-loader load-pin --object")?)
            }
            "--pin-root" => {
                pin_root = Some(parse_next_path(
                    &mut iter,
                    "bpf-loader load-pin --pin-root",
                )?)
            }
            "--tproxy-port" => {
                tproxy_port = Some(parse_next::<u16>(
                    &mut iter,
                    "bpf-loader load-pin --tproxy-port",
                )?)
            }
            "--control-plane-pid" => {
                control_plane_pid = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --control-plane-pid",
                )?)
            }
            "--dae0-ifindex" => {
                dae0_ifindex = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --dae0-ifindex",
                )?)
            }
            "--dae-netns-id" => {
                dae_netns_id = Some(parse_next::<u32>(
                    &mut iter,
                    "bpf-loader load-pin --dae-netns-id",
                )?)
            }
            "--dae0peer-mac" => {
                dae0peer_mac = Some(parse_mac(next_value(
                    &mut iter,
                    "bpf-loader load-pin --dae0peer-mac",
                )?)?)
            }
            "--has-bpf-get-current-task" => {
                has_bpf_get_current_task = Some(parse_bool(next_value(
                    &mut iter,
                    "bpf-loader load-pin --has-bpf-get-current-task",
                )?)?)
            }
            _ if arg.starts_with("--object=") => object = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--pin-root=") => pin_root = Some(parse_path_value(arg)?),
            _ if arg.starts_with("--tproxy-port=") => tproxy_port = Some(parse_value(arg)?),
            _ if arg.starts_with("--control-plane-pid=") => {
                control_plane_pid = Some(parse_value(arg)?)
            }
            _ if arg.starts_with("--dae0-ifindex=") => dae0_ifindex = Some(parse_value(arg)?),
            _ if arg.starts_with("--dae-netns-id=") => dae_netns_id = Some(parse_value(arg)?),
            _ if arg.starts_with("--dae0peer-mac=") => {
                dae0peer_mac = Some(parse_mac(split_value(arg)?)?)
            }
            _ if arg.starts_with("--has-bpf-get-current-task=") => {
                has_bpf_get_current_task = Some(parse_bool(split_value(arg)?)?)
            }
            _ => return Err(format!("unsupported bpf-loader load-pin argument: {arg}")),
        }
    }
    Ok(BpfLoaderLoadPinOptions {
        object,
        pin_root: pin_root.ok_or_else(|| "missing bpf-loader load-pin --pin-root".to_owned())?,
        tproxy_port: tproxy_port
            .ok_or_else(|| "missing bpf-loader load-pin --tproxy-port".to_owned())?,
        control_plane_pid: control_plane_pid
            .ok_or_else(|| "missing bpf-loader load-pin --control-plane-pid".to_owned())?,
        dae0_ifindex: dae0_ifindex
            .ok_or_else(|| "missing bpf-loader load-pin --dae0-ifindex".to_owned())?,
        dae_netns_id: dae_netns_id
            .ok_or_else(|| "missing bpf-loader load-pin --dae-netns-id".to_owned())?,
        dae0peer_mac: dae0peer_mac
            .ok_or_else(|| "missing bpf-loader load-pin --dae0peer-mac".to_owned())?,
        has_bpf_get_current_task: has_bpf_get_current_task
            .ok_or_else(|| "missing bpf-loader load-pin --has-bpf-get-current-task".to_owned())?,
    })
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<&'a str, String> {
    iter.next()
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn parse_next<'a, T: std::str::FromStr>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    next_value(iter, name)?
        .parse()
        .map_err(|err| format!("bad {name}: {err}"))
}

fn parse_next_path<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<PathBuf, String> {
    Ok(PathBuf::from(next_value(iter, name)?))
}

fn parse_value<T: std::str::FromStr>(arg: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    split_value(arg)?
        .parse()
        .map_err(|err| format!("bad {arg}: {err}"))
}

fn parse_path_value(arg: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(split_value(arg)?))
}

fn split_value(arg: &str) -> Result<&str, String> {
    arg.split_once('=')
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing value for {arg}"))
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("bad bool value: {value}")),
    }
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let mut mac = [0_u8; 6];
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != mac.len() {
        return Err(format!("bad mac address: {value}"));
    }
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!("bad mac address: {value}"));
        }
        mac[index] =
            u8::from_str_radix(part, 16).map_err(|err| format!("bad mac address: {err}"))?;
    }
    Ok(mac)
}

#[cfg(feature = "native-ebpf")]
fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn contract_declares_loader_only_scope() {
        let output = run_with_args(["bpf-loader", "contract"]);
        assert_eq!(output.exit_code, 0, "{}", output.stderr);
        let json: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            json["name"].as_str().unwrap(),
            "rust-aya-bpf-loader-go-adoption-contract-v1"
        );
        assert_eq!(json["binary"].as_str().unwrap(), "dae-aya-bpf-loader");
        assert!(
            json["go_userspace_outbound_remains_authoritative"]
                .as_bool()
                .unwrap()
        );
        assert!(!json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
    }

    #[test]
    fn load_pin_requires_full_param_set() {
        let output = run_with_args(["bpf-loader", "load-pin", "--pin-root", "/tmp/dae"]);
        assert_eq!(output.exit_code, 2);
        assert!(output.stderr.contains("--tproxy-port"));
    }

    #[test]
    fn parses_mac_and_bool_values() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(parse_bool("on").unwrap());
        assert!(!parse_bool("off").unwrap());
    }
}
