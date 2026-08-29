use super::*;

pub(in crate::daed_product) fn render_generated_config(
    generated_at: &str,
    config: Option<&(i64, String, String, i64)>,
    dns: Option<&(i64, String, String, i64)>,
    routing: Option<&(i64, String, String, i64)>,
    groups: &Value,
    nodes: &Value,
) -> io::Result<String> {
    dae_product_runtime::render_runtime_config(
        generated_at,
        config.map(|(_, _, raw, _)| display_global_config_text(raw)),
        dns.map(|(_, _, raw, _)| raw.as_str()),
        routing.map(|(_, _, raw, _)| raw.as_str()),
        groups,
        nodes,
    )
}
