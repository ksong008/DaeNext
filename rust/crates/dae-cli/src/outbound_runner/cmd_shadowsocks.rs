use super::*;

pub(super) fn run_shadowsocks(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("contract") => run_shadowsocks_contract(),
        Some("link") => run_shadowsocks_link(&args[1..]),
        Some("cipher") => run_shadowsocks_cipher(&args[1..]),
        Some("metadata") => run_shadowsocks_metadata(&args[1..]),
        Some("ss2022-psk") => run_shadowsocks_ss2022_psk(&args[1..]),
        Some("replay-filter") => run_shadowsocks_replay_filter(&args[1..]),
        Some("smoke") => run_shadowsocks_smoke(&args[1..]),
        Some(subcommand) => RunnerOutput::usage(format!(
            "unsupported outbound shadowsocks subcommand: {subcommand}"
        )),
        None => RunnerOutput::usage("missing outbound shadowsocks subcommand"),
    }
}

pub(super) fn run_shadowsocks_contract() -> RunnerOutput {
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "name": "shadowsocks-native-optin",
            "default_go_path": shadowsocks::contract::DEFAULT_GO_PATH,
            "rust_adapter_mode": shadowsocks::contract::ADAPTER_MODE,
            "protocol_scope": shadowsocks::contract::PROTOCOL_SCOPE,
            "deferred_protocol_scope": shadowsocks::contract::DEFERRED_PROTOCOL_SCOPE,
            "live_smoke_required": shadowsocks::contract::LIVE_SMOKE_REQUIRED,
            "sip003": {
                "simple_obfs_aliases": shadowsocks::contract::SIMPLE_OBFS_ALIASES,
                "default_simple_obfs_host": shadowsocks::contract::SIMPLE_OBFS_DEFAULT_HOST,
                "path_without_slash_go_behavior": shadowsocks::contract::SIP003_PATH_WITHOUT_SLASH_GO_BEHAVIOR,
                "transport_native_data_plane_deferred_to_item": shadowsocks::contract::TRANSPORT_NATIVE_DATA_PLANE_DEFERRED_TO_ITEM,
            },
        })
    ))
}

pub(super) fn run_shadowsocks_link(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound shadowsocks link --link");
    };
    match ShadowsocksLink::parse(link) {
        Ok(parsed) => {
            let capability = match parsed.capability_label() {
                Ok(capability) => capability,
                Err(err) => return RunnerOutput::stdout_error(err.to_string()),
            };
            RunnerOutput::ok(format!(
                "{}\n",
                json!({
                    "input": link,
                    "server": parsed.server,
                    "port": parsed.port,
                    "cipher": parsed.cipher,
                    "password": parsed.password,
                    "udp": parsed.udp,
                    "protocol": parsed.protocol,
                    "capability": capability,
                    "export": parsed.export_url(),
                    "plugin": {
                        "name": parsed.plugin.name,
                        "tls": parsed.plugin.opts.tls,
                        "obfs": parsed.plugin.opts.obfs,
                        "host": parsed.plugin.opts.host,
                        "path": parsed.plugin.opts.path,
                    },
                })
            ))
        }
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_shadowsocks_cipher(args: &[String]) -> RunnerOutput {
    let Some(cipher) = string_arg(args, "--cipher") else {
        return RunnerOutput::usage("missing outbound shadowsocks cipher --cipher");
    };
    match shadowsocks::classify_cipher(cipher) {
        Ok(info) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "cipher": info.cipher,
                "go_protocol_dialer": info.go_protocol_dialer,
                "rust_capability_label": info.rust_capability_label,
                "export_userinfo_plain": info.export_userinfo_plain,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_shadowsocks_metadata(args: &[String]) -> RunnerOutput {
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound shadowsocks metadata --target");
    };
    match ShadowsocksMetadata::parse(target).and_then(|metadata| {
        let encoded = metadata.encode()?;
        Ok((metadata, encoded))
    }) {
        Ok((metadata, encoded)) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "target": target,
                "type": metadata.metadata_type().byte(),
                "hostname": metadata.hostname(),
                "port": metadata.port(),
                "hex": hex_encode(&encoded),
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_shadowsocks_ss2022_psk(args: &[String]) -> RunnerOutput {
    let Some(cipher) = string_arg(args, "--cipher") else {
        return RunnerOutput::usage("missing outbound shadowsocks ss2022-psk --cipher");
    };
    let Some(password) = string_arg(args, "--password") else {
        return RunnerOutput::usage("missing outbound shadowsocks ss2022-psk --password");
    };
    match shadowsocks::ss2022::validate_psk_list(cipher, password) {
        Ok(info) => RunnerOutput::ok(format!(
            "{}\n",
            json!({
                "cipher": info.cipher,
                "password": password,
                "psk_count": info.psk_count,
                "psk_key_lens": info.psk_key_lens,
                "upsk_index": info.upsk_index,
                "expected_key_len": info.expected_key_len,
            })
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

pub(super) fn run_shadowsocks_replay_filter(args: &[String]) -> RunnerOutput {
    let window = match u64_arg(args, "--window").unwrap_or(Ok(4)) {
        Ok(value) => value as usize,
        Err(message) => return RunnerOutput::usage(message),
    };
    let mut duplicate = shadowsocks::ss2022::SlidingWindowFilter::new(window);
    let first = duplicate.check_and_update(1);
    let duplicate_packet = duplicate.check_and_update(1);
    let mut old = shadowsocks::ss2022::SlidingWindowFilter::new(window);
    let mut monotonic = Vec::new();
    for packet_id in [10, 11, 12, 13, 14] {
        monotonic.push(old.check_and_update(packet_id));
    }
    let too_old = old.check_and_update(10);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "window": window,
            "first_packet_accepted": first,
            "duplicate_packet_accepted": duplicate_packet,
            "monotonic_accepts": monotonic,
            "too_old_packet_accepted": too_old,
        })
    ))
}

pub(super) fn run_shadowsocks_smoke(args: &[String]) -> RunnerOutput {
    let Some(link) = string_arg(args, "--link") else {
        return RunnerOutput::usage("missing outbound shadowsocks smoke --link");
    };
    let Some(target) = string_arg(args, "--target") else {
        return RunnerOutput::usage("missing outbound shadowsocks smoke --target");
    };
    let parsed = match ShadowsocksLink::parse(link) {
        Ok(parsed) => parsed,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let metadata = match ShadowsocksMetadata::parse(target).and_then(|metadata| {
        let encoded = metadata.encode()?;
        Ok((metadata, encoded))
    }) {
        Ok(value) => value,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let psk = if parsed.cipher.starts_with("2022-blake3-") {
        match shadowsocks::ss2022::validate_psk_list(&parsed.cipher, &parsed.password) {
            Ok(info) => Some(json!({
                "psk_count": info.psk_count,
                "upsk_index": info.upsk_index,
                "expected_key_len": info.expected_key_len,
            })),
            Err(err) => return RunnerOutput::stdout_error(err.to_string()),
        }
    } else {
        None
    };
    let mut replay = shadowsocks::ss2022::SlidingWindowFilter::new(4);
    let replay_ok = replay.check_and_update(1) && !replay.check_and_update(1);
    RunnerOutput::ok(format!(
        "{}\n",
        json!({
            "ok": true,
            "link": link,
            "target": target,
            "capability": parsed.capability_label().unwrap_or("shadowsocks"),
            "export": parsed.export_url(),
            "metadata_hex": hex_encode(&metadata.1),
            "metadata_authority": metadata.0.authority(),
            "ss2022_psk": psk,
            "replay_duplicate_rejected": replay_ok,
            "transport_data_plane_deferred_to_item": shadowsocks::contract::TRANSPORT_NATIVE_DATA_PLANE_DEFERRED_TO_ITEM,
        })
    ))
}
