#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    pub name: String,
    pub items: Vec<Item>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    Param(Param),
    Section(Box<Section>),
    RoutingRule(RoutingRule),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    Param,
    Section,
    RoutingRule,
}

impl Item {
    pub const fn kind(&self) -> ItemKind {
        match self {
            Self::Param(_) => ItemKind::Param,
            Self::Section(_) => ItemKind::Section,
            Self::RoutingRule(_) => ItemKind::RoutingRule,
        }
    }

    pub fn to_config_string(&self, compact: bool, quote_val: bool) -> String {
        match self {
            Self::Param(param) => {
                format!(
                    "type: Param\n\t{}",
                    param.to_config_string(compact, quote_val)
                )
            }
            Self::Section(section) => {
                let body = section.to_config_string(compact, quote_val);
                format!("type: Section\n\t{}", body.replace('\n', "\n\t"))
            }
            Self::RoutingRule(rule) => {
                format!(
                    "type: RoutingRule\n\t{}",
                    rule.to_config_string(false, compact, quote_val)
                )
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Param {
    pub key: String,
    pub val: String,
    pub and_functions: Vec<Function>,
    pub annotation: Vec<Param>,
}

impl Param {
    pub fn to_config_string(&self, compact: bool, quote_val: bool) -> String {
        let quote = |value: &str| {
            if quote_val {
                quote_string(value)
            } else {
                value.to_owned()
            }
        };
        if self.key.is_empty() {
            return quote(&self.val);
        }
        if !self.and_functions.is_empty() {
            let sep = if compact { "&&" } else { " && " };
            let value = self
                .and_functions
                .iter()
                .map(|function| function.to_config_string(compact, quote_val, false))
                .collect::<Vec<_>>()
                .join(sep);
            let colon = if compact { ":" } else { ": " };
            return format!("{}{}{}", self.key, colon, value);
        }
        let colon = if compact { ":" } else { ": " };
        format!("{}{}{}", self.key, colon, quote(&self.val))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Function {
    pub name: String,
    pub not: bool,
    pub params: Vec<Param>,
}

impl Function {
    pub fn to_config_string(&self, compact: bool, quote_val: bool, omit_empty: bool) -> String {
        let mut out = String::new();
        if self.not {
            out.push('!');
        }
        out.push_str(&self.name);
        if omit_empty && self.params.is_empty() {
            return out;
        }

        let sep = if compact { "," } else { ", " };
        out.push('(');
        out.push_str(
            &self
                .params
                .iter()
                .take(5)
                .map(|param| param.to_config_string(compact, quote_val))
                .collect::<Vec<_>>()
                .join(sep),
        );
        if self.params.len() > 5 {
            if !self.params[..5].is_empty() {
                out.push_str(sep);
            }
            out.push_str("...");
        }
        out.push(')');
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingRule {
    pub and_functions: Vec<Function>,
    pub outbound: Function,
}

impl RoutingRule {
    pub fn to_config_string(
        &self,
        replace_param_with_n: bool,
        compact: bool,
        quote_val: bool,
    ) -> String {
        let and_sep = if compact { "&&" } else { " && " };
        let params_sep = if compact { "," } else { ", " };
        let left = self
            .and_functions
            .iter()
            .map(|function| {
                let params = if replace_param_with_n {
                    format!("[n = {}]", function.params.len())
                } else {
                    function
                        .params
                        .iter()
                        .map(|param| param.to_config_string(compact, quote_val))
                        .collect::<Vec<_>>()
                        .join(params_sep)
                };
                let not = if function.not { "!" } else { "" };
                format!("{not}{}({params})", function.name)
            })
            .collect::<Vec<_>>()
            .join(and_sep);
        let arrow = if compact { "->" } else { " -> " };
        format!(
            "{left}{arrow}{}",
            self.outbound.to_config_string(compact, quote_val, true)
        )
    }
}

impl Section {
    pub fn to_config_string(&self, compact: bool, quote_val: bool) -> String {
        let mut out = format!("section: {}", self.name);
        for item in &self.items {
            out.push('\n');
            out.push_str(
                &item
                    .to_config_string(compact, quote_val)
                    .replace('\n', "\n\t"),
            );
        }
        out
    }
}

pub fn quote_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
