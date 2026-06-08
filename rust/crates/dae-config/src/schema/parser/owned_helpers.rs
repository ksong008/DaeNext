use super::*;
pub(super) fn reject_naked_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("unsupported text without a key".to_owned());
    }
    Ok(())
}

pub(super) fn reject_function_value_parts(
    key: &str,
    val: &str,
    and_functions: &[Function],
) -> Result<(), String> {
    if !and_functions.is_empty() {
        return Err(format!(
            "failed to parse \"{}\": value \"{}\" cannot be convert to string",
            key, val
        ));
    }
    Ok(())
}

pub(super) fn decode_value<T>(key: &str, val: &str, go_type: &str) -> Result<T, String>
where
    T: FuzzyDecode,
{
    fuzzy_decode::<T>(val).ok_or_else(|| {
        format!(
            "failed to parse \"{}\": value \"{}\" cannot be convert to {}",
            key, val, go_type
        )
    })
}

pub(super) fn dynamic_from_parts(
    val: String,
    and_functions: Vec<Function>,
) -> DynamicFunctionValue {
    if and_functions.is_empty() {
        DynamicFunctionValue::String(val)
    } else {
        DynamicFunctionValue::FunctionList(and_functions)
    }
}

pub(super) fn unexpected_item_error_owned(section_name: &str, item: &Item) -> String {
    match item {
        Item::RoutingRule(rule) => format!(
            "cannot use routing rule in this context: {}",
            rule.to_config_string(false, true, false)
        ),
        _ => format!(
            "unexpected type {:?} in section {}: {}",
            item.kind(),
            section_name,
            item.to_config_string(false, false)
        ),
    }
}
