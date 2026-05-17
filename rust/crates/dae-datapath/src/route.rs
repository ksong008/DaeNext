#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRule {
    pub kind: String,
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
    pub matched: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteLoopResult {
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
    pub fallback: bool,
}

pub fn route_loop(rules: &[RouteRule]) -> Option<RouteLoopResult> {
    let fallback = rules
        .iter()
        .find(|rule| rule.kind == "Fallback" && rule.matched);
    for rule in rules {
        if !rule.matched {
            continue;
        }
        return Some(RouteLoopResult {
            outbound: rule.outbound,
            mark: rule.mark,
            must: rule.must,
            fallback: rule.kind == "Fallback",
        });
    }
    fallback.map(|rule| RouteLoopResult {
        outbound: rule.outbound,
        mark: rule.mark,
        must: rule.must,
        fallback: true,
    })
}
