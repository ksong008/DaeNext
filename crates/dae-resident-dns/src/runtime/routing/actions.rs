use super::*;

pub fn request_action_from_index(
    plan: &ResidentDnsPlan,
    outbound: DnsRequestOutboundIndex,
) -> Result<ResidentDnsRequestAction, String> {
    if outbound == DnsRequestOutboundIndex::ASIS {
        return Ok(ResidentDnsRequestAction::AsIs);
    }
    if outbound == DnsRequestOutboundIndex::REJECT {
        return Ok(ResidentDnsRequestAction::Reject);
    }
    if outbound == DnsRequestOutboundIndex::LOGICAL_OR
        || outbound == DnsRequestOutboundIndex::LOGICAL_AND
    {
        return Err(format!(
            "dns.routing.request returned internal logical outbound {outbound}"
        ));
    }
    plan.request_actions
        .get(outbound.value() as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "dns.routing.request selected unknown upstream index {}",
                outbound.value()
            )
        })
}

pub fn request_index_for_dynamic(
    value: &DynamicFunctionValue,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsRequestOutboundIndex, String> {
    let Some(function) = dynamic_to_optional_single_function(value)? else {
        return Ok(DnsRequestOutboundIndex::ASIS);
    };
    request_index_for_function(&function, upstreams, context)
}

pub fn request_index_for_function(
    function: &Function,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsRequestOutboundIndex, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "asis" => Ok(DnsRequestOutboundIndex::ASIS),
        "reject" => Ok(DnsRequestOutboundIndex::REJECT),
        tag => upstreams
            .tag_to_index
            .get(tag)
            .copied()
            .map(DnsRequestOutboundIndex)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

pub fn response_index_for_dynamic(
    value: &DynamicFunctionValue,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsResponseOutboundIndex, String> {
    let Some(function) = dynamic_to_optional_single_function(value)? else {
        return Ok(DnsResponseOutboundIndex::ACCEPT);
    };
    response_index_for_function(&function, upstreams, context)
}

pub fn response_index_for_function(
    function: &Function,
    upstreams: &ResidentDnsUpstreams,
    context: &str,
) -> Result<DnsResponseOutboundIndex, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "accept" => Ok(DnsResponseOutboundIndex::ACCEPT),
        "reject" => Ok(DnsResponseOutboundIndex::REJECT),
        tag => upstreams
            .tag_to_index
            .get(tag)
            .copied()
            .map(DnsResponseOutboundIndex)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

pub fn parse_request_action_function(
    function: &Function,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
    context: &str,
) -> Result<ResidentDnsRequestAction, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "asis" => Ok(ResidentDnsRequestAction::AsIs),
        "reject" => Ok(ResidentDnsRequestAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsRequestAction::Upstream)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

pub fn parse_response_action_function(
    function: &Function,
    upstreams: &BTreeMap<String, ResidentDnsUpstream>,
    context: &str,
) -> Result<ResidentDnsResponseAction, String> {
    if !function.params.is_empty() {
        return Err(format!("{context} does not admit action parameters"));
    }
    match function.name.as_str() {
        "accept" => Ok(ResidentDnsResponseAction::Accept),
        "reject" => Ok(ResidentDnsResponseAction::Reject),
        tag => upstreams
            .get(tag)
            .cloned()
            .map(ResidentDnsResponseAction::Upstream)
            .ok_or_else(|| format!("{context} references unknown upstream {tag:?}")),
    }
}

pub fn response_action_from_index(
    plan: &ResidentDnsPlan,
    outbound: DnsResponseOutboundIndex,
) -> Result<ResidentDnsResponseAction, String> {
    if outbound == DnsResponseOutboundIndex::ACCEPT {
        return Ok(ResidentDnsResponseAction::Accept);
    }
    if outbound == DnsResponseOutboundIndex::REJECT {
        return Ok(ResidentDnsResponseAction::Reject);
    }
    if outbound == DnsResponseOutboundIndex::LOGICAL_OR
        || outbound == DnsResponseOutboundIndex::LOGICAL_AND
    {
        return Err(format!(
            "dns.routing.response returned internal logical outbound {outbound}"
        ));
    }
    plan.response_actions
        .get(outbound.value() as usize)
        .cloned()
        .ok_or_else(|| {
            format!(
                "dns.routing.response selected unknown upstream index {}",
                outbound.value()
            )
        })
}

pub fn dynamic_to_optional_single_function(
    value: &DynamicFunctionValue,
) -> Result<Option<Function>, String> {
    match value {
        DynamicFunctionValue::Nil => Ok(None),
        DynamicFunctionValue::String(name) => Ok(Some(Function {
            name: name.clone(),
            not: false,
            params: Vec::new(),
        })),
        DynamicFunctionValue::Function(function) => Ok(Some(function.clone())),
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => {
            Ok(Some(functions[0].clone()))
        }
        DynamicFunctionValue::FunctionList(_) => {
            Err("default action function list is not admitted".to_owned())
        }
    }
}
