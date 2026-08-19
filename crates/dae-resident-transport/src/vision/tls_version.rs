use super::*;
pub fn client_hello_advertises_tls13(extensions: Option<&[u8]>) -> Option<bool> {
    parse_supported_versions(extensions, parse_tls_client_hello_extension)
        .map(supported_versions_contains_tls13)
}

pub fn server_hello_selects_tls13(extensions: Option<&[u8]>) -> bool {
    parse_supported_versions(extensions, parse_tls_server_hello_extension)
        .map(supported_versions_contains_tls13)
        .unwrap_or(false)
}

pub fn parse_supported_versions<'a, F>(
    extensions: Option<&'a [u8]>,
    mut parse: F,
) -> Option<Vec<TlsVersion>>
where
    F: FnMut(&'a [u8]) -> tls_parser::IResult<&'a [u8], TlsExtension<'a>>,
{
    let mut input = extensions?;
    while !input.is_empty() {
        match parse(input) {
            Ok((_remaining, TlsExtension::SupportedVersions(versions))) => return Some(versions),
            Ok((remaining, _)) if remaining.len() < input.len() => input = remaining,
            _ => return None,
        }
    }
    None
}

pub fn supported_versions_contains_tls13(versions: Vec<TlsVersion>) -> bool {
    versions
        .into_iter()
        .any(|version| version == TlsVersion::Tls13)
}
