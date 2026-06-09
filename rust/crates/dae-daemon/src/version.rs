pub fn version_from_env() -> String {
    std::env::var("DAE_DAEMON_VERSION")
        .ok()
        .filter(|version| !version.trim().is_empty())
        .or_else(|| option_env!("DAE_DAEMON_VERSION").map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}
