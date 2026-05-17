pub const APP_NAME: &str = "dae";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_name_matches_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/dial_mode_policy.json").unwrap();

        assert_eq!(APP_NAME, fixture["app_name"].as_str().unwrap());
    }
}
