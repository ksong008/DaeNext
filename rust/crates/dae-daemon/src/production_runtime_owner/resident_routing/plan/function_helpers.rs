use super::*;
pub(super) fn aliased_function(function: &Function) -> Function {
    let mut function = function.clone();
    match function.name.as_str() {
        "dport" => function.name = "port".to_owned(),
        "dip" => function.name = "ip".to_owned(),
        _ => {}
    }
    function
}

pub(super) fn grouped_params(params: &[Param]) -> Vec<(String, Vec<String>)> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for param in params {
        if !groups.contains_key(&param.key) {
            order.push(param.key.clone());
        }
        groups
            .entry(param.key.clone())
            .or_default()
            .push(param.val.clone());
    }
    order
        .into_iter()
        .map(|key| {
            let values = groups.remove(&key).unwrap_or_default();
            (key, values)
        })
        .collect()
}

pub(super) fn match_set(
    value: [u8; 16],
    not: bool,
    match_type: u8,
    outbound: OutboundSpec,
    kind: &'static str,
) -> MatchSetBytes {
    let mut bytes = [0_u8; 24];
    bytes[..16].copy_from_slice(&value);
    bytes[16] = u8::from(not);
    bytes[17] = match_type;
    bytes[18] = outbound.id;
    bytes[19] = u8::from(outbound.must);
    bytes[20..24].copy_from_slice(&outbound.mark.to_ne_bytes());
    MatchSetBytes {
        bytes,
        kind,
        outbound: outbound.id,
        mark: outbound.mark,
        must: outbound.must,
    }
}

pub(super) fn logical_outbound(index: OutboundIndex) -> OutboundSpec {
    OutboundSpec {
        id: index.value(),
        mark: 0,
        must: false,
        name: index.to_string(),
    }
}
