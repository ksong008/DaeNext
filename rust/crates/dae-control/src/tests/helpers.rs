fn assert_domain_view(got: &DomainRoutingView, expected: &Value) {
    assert_eq!(got.step, expected["step"].as_str().unwrap());
    assert_eq!(got.owners, string_array(&expected["owners"]));
    let expected_ips = expected["ips"].as_array().unwrap();
    assert_eq!(got.ips.len(), expected_ips.len());
    for (got, expected) in got.ips.iter().zip(expected_ips) {
        assert_eq!(got.ip, expected["ip"].as_str().unwrap());
        assert_eq!(got.owners, string_array(&expected["owners"]));
        assert_eq!(
            got.merged,
            expected["merged"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u32)
                .collect::<Vec<_>>()
        );
        assert_eq!(got.present, expected["present"].as_bool().unwrap());
    }
}

fn assert_reload_state(step: &str, got: &ReloadCoreState, expected: &Value) {
    assert_eq!(step, expected["step"].as_str().unwrap());
    assert_eq!(got.is_reload, expected["is_reload"].as_bool().unwrap());
    assert_eq!(got.bpf_ejected, expected["bpf_ejected"].as_bool().unwrap());
    assert_eq!(
        got.defer_func_count,
        expected["defer_func_count"].as_u64().unwrap() as usize
    );
    assert_eq!(got.flip, expected["flip"].as_u64().unwrap() as u8);
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn bitmap<const N: usize>(words: [u32; N]) -> [u32; 32] {
    let mut bitmap = [0; 32];
    bitmap[..N].copy_from_slice(&words);
    bitmap
}

fn connectivity_event(
    key: ConnectivityKey,
    alive: bool,
    is_init: bool,
    dryrun: bool,
) -> ConnectivityEvent {
    ConnectivityEvent {
        key,
        alive,
        is_init,
        dryrun,
    }
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}
