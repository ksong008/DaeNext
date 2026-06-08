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
    let (config, target, payload) = match parse_resident_adapter_udp_live_args(args) {
        Ok(parsed) => parsed,
        Err(err) => return DaedProductOutput::usage(err),
    };
    match load_config_file(&config) {
        Ok(config_value) => DaedProductOutput::ok(format!(
            "{}\n",
            resident_live_adapter_udp_probe(
                &config_value,
                target,
                payload.as_bytes(),
                Some(&config)
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
) -> Result<(PathBuf, SocketAddrV4, String), String> {
    let mut config = None;
    let mut target = None;
    let mut payload = "daex-resident-udp-live".to_owned();
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
                target = Some(value.parse::<SocketAddrV4>().map_err(|err| {
                    format!("resident-adapter-udp-live target must be IPv4 host:port: {err}")
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
                payload = value.clone();
            }
            "--json" => {}
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
    ))
}
