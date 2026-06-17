pub(super) fn string_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().map(String::as_str);
        }
        if let Some((key, value)) = arg.split_once('=')
            && key == name
        {
            return Some(value);
        }
    }
    None
}

pub(super) fn u64_arg(args: &[String], name: &str) -> Option<Result<u64, String>> {
    string_arg(args, name).map(|value| {
        value
            .parse::<u64>()
            .map_err(|err| format!("bad outbound socks5 {name}: {err}"))
    })
}

pub(super) fn bool_arg(args: &[String], name: &str) -> Option<bool> {
    string_arg(args, name).and_then(|value| match value {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    })
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("odd hex length".to_owned());
    }
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| Ok((hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?))
        .collect()
}

pub(super) fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("bad hex byte: {byte}")),
    }
}
