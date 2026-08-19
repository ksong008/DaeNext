use super::*;

pub(super) fn push_csv(target: &mut Vec<String>, set: &mut bool, value: &str) {
    if !*set {
        target.clear();
        *set = true;
    }
    target.extend(split_csv(value));
}

pub(super) fn push_optional_csv(target: &mut Option<Vec<String>>, set: &mut bool, value: &str) {
    if !*set {
        *target = Some(Vec::new());
        *set = true;
    }
    target.as_mut().unwrap().extend(split_csv(value));
}

pub(super) fn split_csv(value: &str) -> Vec<String> {
    value.split(',').map(str::to_owned).collect()
}

pub(super) fn parse_default_duration(value: &str) -> ConfigDuration {
    value.parse().unwrap_or_else(|_| {
        if value == "0" {
            ConfigDuration::default()
        } else {
            panic!("invalid hard-coded duration default {value}")
        }
    })
}
