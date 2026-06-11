use crate::{ConfigDuration, UrlOrEmpty};

pub trait FuzzyDecode: Sized {
    fn fuzzy_decode(input: &str) -> Option<Self>;
}

pub fn fuzzy_decode<T: FuzzyDecode>(input: &str) -> Option<T> {
    T::fuzzy_decode(input)
}

impl FuzzyDecode for bool {
    fn fuzzy_decode(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().as_str() {
            "true" | "t" | "1" | "y" | "yes" | "on" => Some(true),
            "false" | "f" | "0" | "n" | "no" | "off" => Some(false),
            _ => None,
        }
    }
}

impl FuzzyDecode for String {
    fn fuzzy_decode(input: &str) -> Option<Self> {
        Some(input.to_owned())
    }
}

impl FuzzyDecode for ConfigDuration {
    fn fuzzy_decode(input: &str) -> Option<Self> {
        input.parse().ok()
    }
}

impl FuzzyDecode for UrlOrEmpty {
    fn fuzzy_decode(input: &str) -> Option<Self> {
        Self::parse(input).ok()
    }
}

impl FuzzyDecode for Vec<String> {
    fn fuzzy_decode(input: &str) -> Option<Self> {
        Some(input.split(',').map(str::to_owned).collect())
    }
}

impl FuzzyDecode for Vec<ConfigDuration> {
    fn fuzzy_decode(input: &str) -> Option<Self> {
        Some(vec![input.parse().ok()?])
    }
}

macro_rules! impl_signed {
    ($($ty:ty),* $(,)?) => {
        $(
            impl FuzzyDecode for $ty {
                fn fuzzy_decode(input: &str) -> Option<Self> {
                    let bits = (std::mem::size_of::<$ty>() * 8) as u32;
                    let value = parse_i128_base0(input, bits)?;
                    <$ty>::try_from(value).ok()
                }
            }
        )*
    };
}

macro_rules! impl_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl FuzzyDecode for $ty {
                fn fuzzy_decode(input: &str) -> Option<Self> {
                    let bits = (std::mem::size_of::<$ty>() * 8) as u32;
                    let value = parse_u128_base0(input, bits)?;
                    <$ty>::try_from(value).ok()
                }
            }
        )*
    };
}

impl_signed!(i8, i16, i32, i64, isize);
impl_unsigned!(u8, u16, u32, u64, usize);

fn parse_i128_base0(input: &str, bits: u32) -> Option<i128> {
    let (negative, digits, radix) = split_base0_numeric(input)?;
    let unsigned = i128::from_str_radix(digits, radix).ok()?;
    let value = if negative { -unsigned } else { unsigned };
    let min = -(1_i128 << (bits - 1));
    let max = (1_i128 << (bits - 1)) - 1;
    (min..=max).contains(&value).then_some(value)
}

fn parse_u128_base0(input: &str, bits: u32) -> Option<u128> {
    let (negative, digits, radix) = split_base0_numeric(input)?;
    if negative {
        return None;
    }
    let value = u128::from_str_radix(digits, radix).ok()?;
    let max = if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    };
    (value <= max).then_some(value)
}

fn split_base0_numeric(input: &str) -> Option<(bool, &str, u32)> {
    if input.is_empty() {
        return None;
    }

    let (negative, rest) = match input.as_bytes()[0] {
        b'+' => (false, &input[1..]),
        b'-' => (true, &input[1..]),
        _ => (false, input),
    };
    if rest.is_empty() {
        return None;
    }

    if let Some(digits) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        return (!digits.is_empty()).then_some((negative, digits, 16));
    }
    if let Some(digits) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
        return (!digits.is_empty()).then_some((negative, digits, 8));
    }
    if let Some(digits) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
        return (!digits.is_empty()).then_some((negative, digits, 2));
    }
    if rest.len() > 1 && rest.starts_with('0') {
        return Some((negative, rest, 8));
    }
    Some((negative, rest, 10))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn fuzzy_decode_matches_basic_golden_fixture() {
        let fixture = dae_golden::load_json("config/fuzzy/basic.json").unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            match case["name"].as_str().unwrap() {
                "bool-true-aliases" | "bool-false-aliases" => assert_bool_case(case),
                "bool-invalid" => assert_bool_invalid_case(case),
                "int-base-zero" => assert_int_case(case),
                "uint16-limit" => assert_uint16_case(case),
                "duration" => assert_duration_case(case),
                "string" => assert_string_case(case),
                "url-or-empty" => assert_url_or_empty_case(case),
                "string-slice" => assert_string_slice_case(case),
                "duration-slice-single" => assert_duration_slice_case(case),
                other => panic!("unhandled fuzzy fixture case {other}"),
            }
        }
    }

    fn assert_bool_case(case: &Value) {
        let want = case["want"].as_bool().unwrap();
        for input in case["inputs"].as_array().unwrap() {
            assert_eq!(fuzzy_decode::<bool>(input.as_str().unwrap()), Some(want));
        }
    }

    fn assert_bool_invalid_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            assert_eq!(fuzzy_decode::<bool>(input.as_str().unwrap()), None);
        }
    }

    fn assert_int_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            let want = input["want"].as_i64().unwrap();
            assert_eq!(fuzzy_decode::<i64>(value), Some(want));
        }
    }

    fn assert_uint16_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            let ok = input["ok"].as_bool().unwrap();
            let got = fuzzy_decode::<u16>(value);
            assert_eq!(got.is_some(), ok);
            if ok {
                assert_eq!(got.unwrap(), input["want"].as_u64().unwrap() as u16);
            }
        }
    }

    fn assert_duration_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            let ok = input["ok"].as_bool().unwrap();
            let got = fuzzy_decode::<ConfigDuration>(value);
            assert_eq!(got.is_some(), ok);
            if ok {
                assert_eq!(got.unwrap().to_string(), input["want"].as_str().unwrap());
            }
        }
    }

    fn assert_string_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            assert_eq!(
                fuzzy_decode::<String>(value).unwrap(),
                input["want"].as_str().unwrap()
            );
        }
    }

    fn assert_url_or_empty_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            let ok = input["ok"].as_bool().unwrap();
            let got = fuzzy_decode::<UrlOrEmpty>(value);
            assert_eq!(got.is_some(), ok);
            if ok {
                let got = got.unwrap();
                assert_eq!(got.empty, input["want"]["empty"].as_bool().unwrap());
                assert_eq!(got.url.as_deref(), input["want"]["url"].as_str());
            }
        }
    }

    fn assert_string_slice_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            let got = fuzzy_decode::<Vec<String>>(value).unwrap();
            let want: Vec<_> = input["want"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(got, want);
        }
    }

    fn assert_duration_slice_case(case: &Value) {
        for input in case["inputs"].as_array().unwrap() {
            let value = input["value"].as_str().unwrap();
            let ok = input["ok"].as_bool().unwrap();
            let got = fuzzy_decode::<Vec<ConfigDuration>>(value);
            assert_eq!(got.is_some(), ok);
            if ok {
                let got: Vec<_> = got
                    .unwrap()
                    .into_iter()
                    .map(|duration| duration.to_string())
                    .collect();
                let want: Vec<_> = input["want"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(got, want);
            }
        }
    }
}
