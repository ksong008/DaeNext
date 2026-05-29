use dae_config_util::is_valid_http_method;

use crate::SniffingError;

pub fn sniff_http(data: &[u8]) -> Result<String, SniffingError> {
    sniff_http_host(data).map(str::to_owned)
}

pub fn sniff_http_host(data: &[u8]) -> Result<&str, SniffingError> {
    if data.first().copied().map(is_printable_ascii) != Some(true) {
        return Err(SniffingError::NotApplicable);
    }

    let search = &data[..data.len().min(12)];
    let Some(space) = search.iter().position(|ch| *ch == b' ') else {
        return Err(SniffingError::NotApplicable);
    };
    let method = std::str::from_utf8(&search[..space]).map_err(|_| SniffingError::NotApplicable)?;
    if !is_valid_http_method(method) {
        return Err(SniffingError::NotApplicable);
    }

    for line in data.split(|ch| *ch == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|ch| *ch == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"host") {
            return std::str::from_utf8(&line[colon + 1..]).map_err(|_| SniffingError::NotFound);
        }
    }

    Err(SniffingError::NotFound)
}

fn is_printable_ascii(ch: u8) -> bool {
    (0x20..=0x7e).contains(&ch)
}
