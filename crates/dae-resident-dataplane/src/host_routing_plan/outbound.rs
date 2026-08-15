use super::*;
pub(super) fn outbound_groups(config: &Config) -> Result<BTreeMap<String, u8>, String> {
    let mut groups = BTreeMap::new();
    groups.insert("direct".to_owned(), OutboundIndex::DIRECT.value());
    groups.insert("block".to_owned(), OutboundIndex::BLOCK.value());
    for (index, group) in config.group.iter().enumerate() {
        let outbound = index + OutboundIndex::USER_DEFINED_MIN.value() as usize;
        if outbound > OutboundIndex::USER_DEFINED_MAX.value() as usize {
            return Err("too many resident outbounds".to_owned());
        }
        if groups.insert(group.name.clone(), outbound as u8).is_some() {
            return Err(format!("duplicated outbound name: {}", group.name));
        }
    }
    Ok(groups)
}

pub(super) fn parse_outbound(
    function: &Function,
    groups: &BTreeMap<String, u8>,
) -> Result<OutboundSpec, String> {
    let mut mark = 0_u32;
    let mut must = false;
    for param in &function.params {
        match param.key.as_str() {
            "mark" => {
                mark = parse_u32_auto(&param.val)
                    .map_err(|err| format!("invalid outbound mark {}: {err}", param.val))?;
            }
            "" if param.val == "must" => must = true,
            "" => return Err(format!("unknown outbound param: {}", param.val)),
            key => return Err(format!("unknown outbound param key: {key}")),
        }
    }
    let id = match function.name.as_str() {
        "must_rules" => OutboundIndex::MUST_RULES.value(),
        name => *groups
            .get(name)
            .ok_or_else(|| format!("outbound group not found: {name}"))?,
    };
    Ok(OutboundSpec {
        id,
        mark,
        must,
        name: function.name.clone(),
    })
}

pub(super) fn dynamic_to_single_function(value: &DynamicFunctionValue) -> Result<Function, String> {
    match value {
        DynamicFunctionValue::String(name) => Ok(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        }),
        DynamicFunctionValue::Function(function) => Ok(function.clone()),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(functions[0].clone())
        }
        DynamicFunctionValue::FunctionList(functions) => Err(format!(
            "expected exactly 1 fallback function, got {}",
            functions.len()
        )),
        DynamicFunctionValue::Nil => Err("unsupported fallback type nil".to_owned()),
    }
}
