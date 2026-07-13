use std::net::SocketAddr;

use http::Uri;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use super::MasqueCodecError;

const TARGET_HOST_VARIABLE: &str = "{target_host}";
const TARGET_PORT_VARIABLE: &str = "{target_port}";

const URI_TEMPLATE_VALUE_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MasqueUriTemplate {
    raw: String,
}

impl MasqueUriTemplate {
    pub fn parse(raw: impl Into<String>) -> Result<Self, MasqueCodecError> {
        let raw = raw.into();
        validate_template(&raw)?;
        Ok(Self { raw })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn expand(&self, target: SocketAddr) -> Result<String, MasqueCodecError> {
        let host = target.ip().to_string();
        let encoded_host = utf8_percent_encode(&host, URI_TEMPLATE_VALUE_ENCODE_SET).to_string();
        let expanded = self
            .raw
            .replace(TARGET_HOST_VARIABLE, &encoded_host)
            .replace(TARGET_PORT_VARIABLE, &target.port().to_string());
        validate_expanded_uri(&expanded)?;
        Ok(expanded)
    }

    pub fn expand_request_uri(
        &self,
        target: SocketAddr,
        proxy_authority: &str,
    ) -> Result<Uri, MasqueCodecError> {
        let expanded = self.expand(target)?;
        let request_uri = if expanded.starts_with('/') {
            validate_proxy_authority(proxy_authority)?;
            format!("https://{proxy_authority}{expanded}")
        } else {
            expanded
        };
        request_uri.parse::<Uri>().map_err(|err| {
            MasqueCodecError::InvalidTemplate(format!("expanded request URI is invalid: {err}"))
        })
    }

    pub fn compact_allocations(&mut self) {
        self.raw.shrink_to_fit();
    }
}

fn validate_template(raw: &str) -> Result<(), MasqueCodecError> {
    if raw.is_empty() {
        return Err(invalid_template("template is empty"));
    }
    if raw.contains('#') {
        return Err(invalid_template("URI fragments are not allowed"));
    }
    if raw
        .chars()
        .any(|character| character.is_ascii_control() || character == ' ')
    {
        return Err(invalid_template(
            "spaces and ASCII control characters are not allowed",
        ));
    }
    if raw.matches(TARGET_HOST_VARIABLE).count() != 1
        || raw.matches(TARGET_PORT_VARIABLE).count() != 1
    {
        return Err(invalid_template(
            "template must contain exactly one {target_host} and one {target_port}",
        ));
    }
    let remainder = raw
        .replace(TARGET_HOST_VARIABLE, "")
        .replace(TARGET_PORT_VARIABLE, "");
    if remainder.contains('{') || remainder.contains('}') {
        return Err(invalid_template(
            "only {target_host} and {target_port} variables are supported",
        ));
    }
    let syntax_probe = raw
        .replace(TARGET_HOST_VARIABLE, "0")
        .replace(TARGET_PORT_VARIABLE, "0");
    validate_expanded_uri(&syntax_probe)
}

fn validate_expanded_uri(expanded: &str) -> Result<(), MasqueCodecError> {
    let uri = expanded
        .parse::<Uri>()
        .map_err(|err| invalid_template(format!("expanded URI syntax is invalid: {err}")))?;
    if expanded.starts_with('/') {
        if uri.path().is_empty() {
            return Err(invalid_template("origin-form URI has no path"));
        }
        return Ok(());
    }
    if uri.scheme_str() != Some("https") || uri.authority().is_none() {
        return Err(invalid_template(
            "template must be origin-form or an absolute https URI",
        ));
    }
    Ok(())
}

fn validate_proxy_authority(authority: &str) -> Result<(), MasqueCodecError> {
    let uri = format!("https://{authority}/")
        .parse::<Uri>()
        .map_err(|err| invalid_template(format!("invalid proxy authority: {err}")))?;
    if uri.authority().is_none() {
        return Err(invalid_template("proxy authority is missing"));
    }
    Ok(())
}

fn invalid_template(reason: impl ToString) -> MasqueCodecError {
    MasqueCodecError::InvalidTemplate(reason.to_string())
}

#[cfg(test)]
mod tests;
