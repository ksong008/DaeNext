use super::*;

pub(in crate::tests) fn make_group(count: usize, policy: SelectionPolicy) -> DialerGroup {
    DialerGroup::new(
        "test",
        (0..count)
            .map(|index| Dialer::new(format!("dialer{index}"), ""))
            .collect(),
        vec![Annotation::default(); count],
        policy,
        false,
        0,
    )
}

pub(in crate::tests) fn fixture(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

pub(in crate::tests) fn string_values(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect()
}

pub(in crate::tests) fn optional_string_vec(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    })
}

pub(in crate::tests) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(in crate::tests) fn hex_decode(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let high = hex_nibble(chunk[0]);
            let low = hex_nibble(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

pub(in crate::tests) fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("bad hex byte: {byte}"),
    }
}
