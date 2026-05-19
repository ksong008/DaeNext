use super::*;

pub(super) fn reject_naked_param(param: &Param) -> Result<(), String> {
    if param.key.is_empty() {
        return Err(format!(
            "unsupported text without a key: {}",
            param.to_config_string(true, false)
        ));
    }
    Ok(())
}

pub(super) fn reject_function_value(param: &Param) -> Result<(), String> {
    if !param.and_functions.is_empty() {
        return Err(format!(
            "failed to parse \"{}\": value \"{}\" cannot be convert to string",
            param.key, param.val
        ));
    }
    Ok(())
}

pub(super) fn decode_param<T>(param: &Param, go_type: &str) -> Result<T, String>
where
    T: FuzzyDecode,
{
    reject_function_value(param)?;
    fuzzy_decode::<T>(&param.val).ok_or_else(|| {
        format!(
            "failed to parse \"{}\": value \"{}\" cannot be convert to {}",
            param.key, param.val, go_type
        )
    })
}

pub(super) fn dynamic_from_param(param: &Param) -> DynamicFunctionValue {
    if param.and_functions.is_empty() {
        DynamicFunctionValue::String(param.val.clone())
    } else {
        DynamicFunctionValue::FunctionList(param.and_functions.clone())
    }
}

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

pub(super) fn parse_default_duration(value: &str) -> GoDuration {
    value.parse().unwrap_or_else(|_| {
        if value == "0" {
            GoDuration::default()
        } else {
            panic!("invalid hard-coded Go duration default {value}")
        }
    })
}

pub(super) fn unexpected_item_error(section: &Section, item: &Item) -> String {
    match item {
        Item::RoutingRule(rule) => format!(
            "cannot use routing rule in this context: {}",
            rule.to_config_string(false, true, false)
        ),
        _ => format!(
            "unexpected type {:?} in section {}: {}",
            item.kind(),
            section.name,
            item.to_config_string(false, false)
        ),
    }
}
