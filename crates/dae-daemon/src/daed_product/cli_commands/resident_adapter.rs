use super::*;
pub(crate) fn run_resident_adapter_matrix_command(args: &[String]) -> DaedProductOutput {
    let config = match parse_resident_adapter_matrix_args(args) {
        Ok(config) => config,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match load_config_file(&config) {
        Ok(config_value) => DaedProductOutput::ok(format!(
            "{}\n",
            resident_live_adapter_config_assessment(&config_value, Some(&config))
        )),
        Err(err) => {
            DaedProductOutput::error(format!("resident adapter matrix config load failed: {err}"))
        }
    }
}

pub(crate) fn run_resident_adapter_udp_live_command(args: &[String]) -> DaedProductOutput {
    let (config, target, payload, response_hex) = match parse_resident_adapter_udp_live_args(args) {
        Ok(parsed) => parsed,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match load_config_file(&config) {
        Ok(config_value) => DaedProductOutput::ok(format!(
            "{}\n",
            resident_live_adapter_udp_probe(
                &config_value,
                target,
                &payload,
                Some(&config),
                response_hex,
            )
        )),
        Err(err) => DaedProductOutput::error(format!(
            "resident adapter UDP live config load failed: {err}"
        )),
    }
}

pub(crate) fn parse_resident_adapter_matrix_args(args: &[String]) -> Result<PathBuf, String> {
    let mut config = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-c" | "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-matrix requires a value after -c/--config".to_owned()
                    );
                };
                config = Some(PathBuf::from(value));
            }
            "--json" => {}
            other => {
                return Err(format!(
                    "resident-adapter-matrix unsupported argument: {other}"
                ));
            }
        }
        index += 1;
    }
    config.ok_or_else(|| "resident-adapter-matrix requires -c/--config".to_owned())
}

pub(crate) fn parse_resident_adapter_udp_live_args(
    args: &[String],
) -> Result<(PathBuf, SocketAddr, Vec<u8>, bool), String> {
    let mut config = None;
    let mut target = None;
    let mut payload = b"resident-udp-live".to_vec();
    let mut payload_set = false;
    let mut response_hex = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-c" | "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after -c/--config".to_owned(),
                    );
                };
                config = Some(PathBuf::from(value));
            }
            "--target" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after --target".to_owned()
                    );
                };
                target = Some(value.parse::<SocketAddr>().map_err(|err| {
                    format!(
                        "resident-adapter-udp-live target must be host:port or [ipv6]:port: {err}"
                    )
                })?);
            }
            "--payload" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after --payload".to_owned()
                    );
                };
                if value.is_empty() {
                    return Err("resident-adapter-udp-live payload cannot be empty".to_owned());
                }
                if payload_set {
                    return Err(
                        "resident-adapter-udp-live accepts only one payload source".to_owned()
                    );
                }
                payload = value.as_bytes().to_vec();
                payload_set = true;
            }
            "--payload-hex" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(
                        "resident-adapter-udp-live requires a value after --payload-hex".to_owned(),
                    );
                };
                if payload_set {
                    return Err(
                        "resident-adapter-udp-live accepts only one payload source".to_owned()
                    );
                }
                payload = decode_udp_live_payload_hex(value)?;
                payload_set = true;
            }
            "--json" => {}
            "--response-hex" => {
                response_hex = true;
            }
            other => {
                return Err(format!(
                    "resident-adapter-udp-live unsupported argument: {other}"
                ));
            }
        }
        index += 1;
    }
    Ok((
        config.ok_or_else(|| "resident-adapter-udp-live requires -c/--config".to_owned())?,
        target.ok_or_else(|| "resident-adapter-udp-live requires --target".to_owned())?,
        payload,
        response_hex,
    ))
}

fn decode_udp_live_payload_hex(value: &str) -> Result<Vec<u8>, String> {
    let nibbles = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if nibbles.is_empty() {
        return Err("resident-adapter-udp-live payload hex cannot be empty".to_owned());
    }
    if nibbles.len() % 2 != 0 {
        return Err("resident-adapter-udp-live payload hex must contain full bytes".to_owned());
    }
    let mut out = Vec::with_capacity(nibbles.len() / 2);
    for pair in nibbles.chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or_else(|| {
            format!(
                "resident-adapter-udp-live payload hex contains invalid digit: {}",
                pair[0] as char
            )
        })?;
        let low = hex_value(pair[1]).ok_or_else(|| {
            format!(
                "resident-adapter-udp-live payload hex contains invalid digit: {}",
                pair[1] as char
            )
        })?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_adapter_udp_live_accepts_hex_payload() {
        let (config, target, payload, response_hex) = parse_resident_adapter_udp_live_args(&[
            "-c".to_owned(),
            "/tmp/config.dae".to_owned(),
            "--target".to_owned(),
            "127.0.0.1:3478".to_owned(),
            "--payload-hex".to_owned(),
            "00 01 21 12 a4 42".to_owned(),
            "--response-hex".to_owned(),
        ])
        .unwrap();

        assert_eq!(config, PathBuf::from("/tmp/config.dae"));
        assert_eq!(target, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
        assert_eq!(payload, vec![0x00, 0x01, 0x21, 0x12, 0xa4, 0x42]);
        assert!(response_hex);
    }

    #[test]
    fn resident_adapter_udp_live_rejects_invalid_hex_payload() {
        let err = parse_resident_adapter_udp_live_args(&[
            "-c".to_owned(),
            "/tmp/config.dae".to_owned(),
            "--target".to_owned(),
            "127.0.0.1:3478".to_owned(),
            "--payload-hex".to_owned(),
            "001".to_owned(),
        ])
        .unwrap_err();

        assert!(err.contains("full bytes"));
    }

    #[test]
    fn resident_adapter_udp_live_rejects_multiple_payload_sources() {
        let err = parse_resident_adapter_udp_live_args(&[
            "-c".to_owned(),
            "/tmp/config.dae".to_owned(),
            "--target".to_owned(),
            "127.0.0.1:3478".to_owned(),
            "--payload".to_owned(),
            "probe".to_owned(),
            "--payload-hex".to_owned(),
            "00".to_owned(),
        ])
        .unwrap_err();

        assert!(err.contains("only one payload source"));
    }
}
