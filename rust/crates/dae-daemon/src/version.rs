pub fn version_from_env() -> String {
    std::env::var("DAE_DAEMON_VERSION").unwrap_or_else(|_| "unknown".to_owned())
}
