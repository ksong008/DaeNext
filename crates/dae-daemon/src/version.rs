pub fn version_from_env() -> String {
    std::env::var("DAE_DAEMON_VERSION")
        .ok()
        .filter(|version| !version.trim().is_empty())
        .or_else(|| compile_time_version().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

pub fn compile_time_version() -> Option<&'static str> {
    option_env!("DAE_DAEMON_VERSION").filter(|version| !version.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_product_identity_is_available() {
        let version = compile_time_version().unwrap_or("unknown");
        assert_ne!(version, "unknown");
        assert!(version.contains("daed rust-native product"), "{version}");
    }
}
