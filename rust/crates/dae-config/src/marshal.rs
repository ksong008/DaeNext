use crate::ast::{Function, RoutingRule, quote_string};
use crate::dynamic::DynamicFunctionValue;
use crate::error::ConfigError;
use crate::schema::{Config, Dns, DnsRuleSet, Global, Group, KeyableString, Routing};

pub fn marshal_config(config: &Config, indent_space: usize) -> Result<String, ConfigError> {
    let mut marshaller = Marshaller::new(indent_space);
    marshaller.marshal_config(config)?;
    Ok(marshaller.out)
}

struct Marshaller {
    indent_space: usize,
    out: String,
}

impl Marshaller {
    fn new(indent_space: usize) -> Self {
        Self {
            indent_space,
            out: String::with_capacity(4096),
        }
    }

    fn marshal_config(&mut self, config: &Config) -> Result<(), ConfigError> {
        self.section("global", 0, |this| this.marshal_global(&config.global))?;
        self.section("subscription", 0, |this| {
            this.marshal_keyable_string_list(&config.subscription, 1);
            Ok(())
        })?;
        self.section("node", 0, |this| {
            this.marshal_keyable_string_list(&config.node, 1);
            Ok(())
        })?;
        self.section("group", 0, |this| this.marshal_groups(&config.group))?;
        self.section("routing", 0, |this| {
            this.marshal_routing(&config.routing, 1)
        })?;
        self.section("dns", 0, |this| this.marshal_dns(&config.dns))?;
        Ok(())
    }

    fn marshal_global(&mut self, global: &Global) -> Result<(), ConfigError> {
        self.leaf("tproxy_port", global.tproxy_port, 1);
        self.leaf("tproxy_port_protect", global.tproxy_port_protect, 1);
        self.leaf("so_mark_from_dae", global.so_mark_from_dae, 1);
        self.leaf("log_level", &global.log_level, 1);
        self.string_slice_leaf("tcp_check_url", &global.tcp_check_url, 1);
        self.leaf("tcp_check_http_method", &global.tcp_check_http_method, 1);
        self.string_slice_leaf("udp_check_dns", &global.udp_check_dns, 1);
        self.leaf("check_interval", global.check_interval, 1);
        self.leaf("check_tolerance", global.check_tolerance, 1);
        self.leaf("udp_endpoint_pool_size", global.udp_endpoint_pool_size, 1);
        self.optional_string_slice_leaf("lan_interface", &global.lan_interface, 1);
        self.optional_string_slice_leaf("wan_interface", &global.wan_interface, 1);
        self.leaf("allow_insecure", global.allow_insecure, 1);
        self.leaf("dial_mode", &global.dial_mode, 1);
        self.leaf("disable_waiting_network", global.disable_waiting_network, 1);
        self.leaf(
            "enable_local_tcp_fast_redirect",
            global.enable_local_tcp_fast_redirect,
            1,
        );
        self.leaf(
            "auto_config_kernel_parameter",
            global.auto_config_kernel_parameter,
            1,
        );
        self.leaf(
            "auto_config_firewall_rule",
            global.auto_config_firewall_rule,
            1,
        );
        self.leaf("sniffing_timeout", global.sniffing_timeout, 1);
        self.leaf("tls_implementation", &global.tls_implementation, 1);
        self.leaf("utls_imitate", &global.utls_imitate, 1);
        self.leaf("tls_fragment", global.tls_fragment, 1);
        self.leaf("tls_fragment_length", &global.tls_fragment_length, 1);
        self.leaf("tls_fragment_interval", &global.tls_fragment_interval, 1);
        self.leaf("pprof_port", global.pprof_port, 1);
        self.leaf("mptcp", global.mptcp, 1);
        self.leaf("fallback_resolver", &global.fallback_resolver, 1);
        self.leaf("bandwidth_max_tx", &global.bandwidth_max_tx, 1);
        self.leaf("bandwidth_max_rx", &global.bandwidth_max_rx, 1);
        self.leaf("udphop_interval", global.udphop_interval, 1);
        Ok(())
    }

    fn marshal_groups(&mut self, groups: &[Group]) -> Result<(), ConfigError> {
        for group in groups {
            self.section(&group.name, 1, |this| this.marshal_group(group))?;
        }
        Ok(())
    }

    fn marshal_group(&mut self, group: &Group) -> Result<(), ConfigError> {
        for filter in &group.filter {
            self.function_list_leaf("filter", filter, 2);
        }
        self.dynamic_leaf("policy", &group.policy, 2)?;
        self.optional_string_slice_leaf("tcp_check_url", &group.tcp_check_url, 2);
        self.leaf("tcp_check_http_method", &group.tcp_check_http_method, 2);
        self.optional_string_slice_leaf("udp_check_dns", &group.udp_check_dns, 2);
        self.leaf("check_interval", group.check_interval, 2);
        self.leaf("check_tolerance", group.check_tolerance, 2);
        Ok(())
    }

    fn marshal_routing(&mut self, routing: &Routing, depth: usize) -> Result<(), ConfigError> {
        for rule in &routing.rules {
            self.routing_rule(rule, depth);
        }
        self.dynamic_leaf("fallback", &routing.fallback, depth)?;
        Ok(())
    }

    fn marshal_dns(&mut self, dns: &Dns) -> Result<(), ConfigError> {
        self.leaf("ipversion_prefer", dns.ipversion_prefer, 1);
        if !dns.fixed_domain_ttl.is_empty() {
            self.section("fixed_domain_ttl", 1, |this| {
                this.marshal_keyable_string_list(&dns.fixed_domain_ttl, 2);
                Ok(())
            })?;
        }
        if !dns.upstream.is_empty() {
            self.section("upstream", 1, |this| {
                this.marshal_keyable_string_list(&dns.upstream, 2);
                Ok(())
            })?;
        }
        self.section("routing", 1, |this| {
            this.section("request", 2, |this| {
                this.marshal_dns_rule_set(&dns.routing.request, 3)
            })?;
            this.section("response", 2, |this| {
                this.marshal_dns_rule_set(&dns.routing.response, 3)
            })?;
            Ok(())
        })?;
        self.leaf("bind", &dns.bind, 1);
        Ok(())
    }

    fn marshal_dns_rule_set(
        &mut self,
        rule_set: &DnsRuleSet,
        depth: usize,
    ) -> Result<(), ConfigError> {
        for rule in &rule_set.rules {
            self.routing_rule(rule, depth);
        }
        self.dynamic_leaf("fallback", &rule_set.fallback, depth)?;
        Ok(())
    }

    fn section<F>(&mut self, name: &str, depth: usize, f: F) -> Result<(), ConfigError>
    where
        F: FnOnce(&mut Self) -> Result<(), ConfigError>,
    {
        self.write_indent(depth);
        self.out.push_str(name);
        self.out.push_str(" {\n");
        f(self)?;
        self.write_line(depth, "}");
        Ok(())
    }

    fn leaf(&mut self, key: &str, value: impl ToString, depth: usize) {
        self.write_indent(depth);
        self.out.push_str(key);
        self.out.push(':');
        self.out.push_str(&quote_string(&value.to_string()));
        self.out.push('\n');
    }

    fn string_slice_leaf(&mut self, key: &str, values: &[String], depth: usize) {
        if values.is_empty() {
            return;
        }
        self.leaf(key, values.join(","), depth);
    }

    fn optional_string_slice_leaf(
        &mut self,
        key: &str,
        values: &Option<Vec<String>>,
        depth: usize,
    ) {
        if let Some(values) = values {
            self.string_slice_leaf(key, values, depth);
        }
    }

    fn dynamic_leaf(
        &mut self,
        key: &str,
        value: &DynamicFunctionValue,
        depth: usize,
    ) -> Result<(), ConfigError> {
        match value {
            DynamicFunctionValue::Nil => Err(ConfigError::Marshal(format!(
                "unknown leaf type for {key}: nil dynamic value"
            ))),
            DynamicFunctionValue::String(value) => {
                self.leaf(key, value, depth);
                Ok(())
            }
            DynamicFunctionValue::Function(function) => {
                self.write_indent(depth);
                self.out.push_str(key);
                self.out.push(':');
                self.out
                    .push_str(&function.to_config_string(true, true, false));
                self.out.push('\n');
                Ok(())
            }
            DynamicFunctionValue::FunctionList(functions) => {
                self.function_list_leaf(key, functions, depth);
                Ok(())
            }
        }
    }

    fn function_list_leaf(&mut self, key: &str, functions: &[Function], depth: usize) {
        self.write_indent(depth);
        self.out.push_str(key);
        self.out.push(':');
        for (index, function) in functions.iter().enumerate() {
            if index > 0 {
                self.out.push_str("&&");
            }
            self.out
                .push_str(&function.to_config_string(true, true, false));
        }
        self.out.push('\n');
    }

    fn routing_rule(&mut self, rule: &RoutingRule, depth: usize) {
        self.write_line(depth, &rule.to_config_string(false, true, true));
    }

    fn marshal_keyable_string_list(&mut self, values: &[KeyableString], depth: usize) {
        for value in values {
            if let Some((tag, after_tag)) = split_link_like_tag(value) {
                self.write_line(depth, &format!("{tag}:{}", quote_string(after_tag)));
            } else {
                self.write_line(depth, &quote_string(value));
            }
        }
    }

    fn write_line(&mut self, depth: usize, line: &str) {
        self.write_indent(depth);
        self.out.push_str(line);
        self.out.push('\n');
    }

    fn write_indent(&mut self, depth: usize) {
        for _ in 0..depth * self.indent_space {
            self.out.push(' ');
        }
    }
}

fn split_link_like_tag(value: &str) -> Option<(&str, &str)> {
    let index = value.find(':')?;
    if value[index + 1..].starts_with("//") {
        return None;
    }
    Some((&value[..index], &value[index + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::MARSHAL_EXAMPLE_ROUNDTRIP;
    use crate::merger::merge_config_file;
    use crate::parser::parse_config;
    use crate::schema::build_config;

    #[test]
    fn marshals_example_like_go_and_roundtrips_without_annotations() {
        let tree = TempTree::new();
        tree.write_mode(
            "example.dae",
            include_str!("../../../../example.dae"),
            0o640,
        );
        let merged = merge_config_file(tree.path("example.dae")).unwrap();
        let config = build_config(&merged.sections).unwrap();
        let text = marshal_config(&config, 2).unwrap();
        let fixture = dae_golden::load_json(MARSHAL_EXAMPLE_ROUNDTRIP).unwrap();
        assert_eq!(text, fixture["marshal"]["text"].as_str().unwrap());

        tree.write_mode("roundtrip.dae", &text, 0o640);
        let roundtrip = merge_config_file(tree.path("roundtrip.dae")).unwrap();
        let roundtrip = build_config(&roundtrip.sections).unwrap();
        assert_eq!(without_annotations(config), without_annotations(roundtrip));
    }

    #[test]
    fn keyable_string_tag_split_matches_go_helper_contract() {
        assert_eq!(
            split_link_like_tag("tag:https://example.com"),
            Some(("tag", "https://example.com"))
        );
        assert_eq!(split_link_like_tag("https://example.com"), None);
        assert_eq!(
            split_link_like_tag("persist_sub:https-file://example.com/sub"),
            Some(("persist_sub", "https-file://example.com/sub"))
        );
    }

    #[test]
    fn marshaled_text_is_parseable() {
        let tree = TempTree::new();
        tree.write_mode(
            "example.dae",
            include_str!("../../../../example.dae"),
            0o640,
        );
        let merged = merge_config_file(tree.path("example.dae")).unwrap();
        let config = build_config(&merged.sections).unwrap();
        let text = marshal_config(&config, 2).unwrap();
        let sections = parse_config(&text).unwrap();
        assert!(sections.iter().any(|section| section.name == "routing"));
    }

    fn without_annotations(mut config: Config) -> Config {
        for group in &mut config.group {
            group.filter_annotation.clear();
        }
        config
    }

    struct TempTree {
        root: std::path::PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "dae-config-marshal-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn path(&self, rel: &str) -> std::path::PathBuf {
            self.root.join(rel)
        }

        fn write_mode(&self, rel: &str, text: &str, mode: u32) {
            let path = self.path(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
