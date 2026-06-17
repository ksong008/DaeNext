use std::fmt;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UrlOrEmpty {
    pub url: Option<String>,
    pub empty: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseUrlOrEmptyError {
    input: String,
}

impl fmt::Display for ParseUrlOrEmptyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse url: {}", self.input)
    }
}

impl std::error::Error for ParseUrlOrEmptyError {}

impl UrlOrEmpty {
    pub fn parse(input: &str) -> Result<Self, ParseUrlOrEmptyError> {
        if input.is_empty() {
            return Ok(Self {
                url: None,
                empty: true,
            });
        }

        validate_url_or_empty_parse(input)?;
        Ok(Self {
            url: Some(input.to_owned()),
            empty: false,
        })
    }
}

fn validate_url_or_empty_parse(input: &str) -> Result<(), ParseUrlOrEmptyError> {
    validate_percent_escapes(input)?;
    const BASE: &str = "dae://placeholder/";
    let base = url::Url::parse(BASE).expect("static URL base must parse");
    url::Url::options()
        .base_url(Some(&base))
        .parse(input)
        .map(|_| ())
        .map_err(|_| ParseUrlOrEmptyError {
            input: input.to_owned(),
        })
}

fn validate_percent_escapes(input: &str) -> Result<(), ParseUrlOrEmptyError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
        {
            return Err(ParseUrlOrEmptyError {
                input: input.to_owned(),
            });
        }
        index += 3;
    }
    Ok(())
}
