use super::*;
pub(crate) fn run_resetpass_command(args: &[String]) -> DaedProductOutput {
    let mut config_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut json_output = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    return DaedProductOutput::usage("missing resetpass --config value");
                };
                config_dir = value.into();
            }
            _ if arg.starts_with("--config=") => {
                config_dir = arg.split_once('=').unwrap().1.into();
            }
            "--json" => json_output = true,
            _ => return DaedProductOutput::usage(format!("unsupported resetpass argument: {arg}")),
        }
    }
    let state = config_dir.join("daed.db");
    match reset_all_user_passwords(&state) {
        Ok(report) if json_output => DaedProductOutput::ok(format!("{report}\n")),
        Ok(report) => {
            let mut out = String::new();
            let users = report["users"].as_array().cloned().unwrap_or_default();
            if users.is_empty() {
                out.push_str("No users found.\n");
            } else {
                for user in users {
                    out.push_str(&format!(
                        "Username: {}, Password: {}\n",
                        user["username"].as_str().unwrap_or(""),
                        user["password"].as_str().unwrap_or("")
                    ));
                }
            }
            DaedProductOutput::ok(out)
        }
        Err(err) => DaedProductOutput::error(format!("resetpass failed: {err}")),
    }
}
