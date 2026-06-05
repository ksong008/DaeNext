use crate::ast::Section;
use crate::ast::{Function, Item, Param, RoutingRule};
use crate::error::ConfigError;

pub fn parse_config(_input: &str) -> Result<Vec<Section>, ConfigError> {
    let tokens = Lexer::new(_input).tokenize()?;
    Parser::new(_input, tokens).parse_sections()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Literal(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Bang,
    AndAnd,
    Arrow,
    Eof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    offset: usize,
}

struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            offset: 0,
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>, ConfigError> {
        let mut tokens = Vec::new();
        while self.offset < self.bytes.len() {
            self.skip_ws_and_comments();
            if self.offset >= self.bytes.len() {
                break;
            }

            let offset = self.offset;
            let token = match self.bytes[self.offset] {
                b'{' => {
                    self.offset += 1;
                    TokenKind::LBrace
                }
                b'}' => {
                    self.offset += 1;
                    TokenKind::RBrace
                }
                b'(' => {
                    self.offset += 1;
                    TokenKind::LParen
                }
                b')' => {
                    self.offset += 1;
                    TokenKind::RParen
                }
                b'[' => {
                    self.offset += 1;
                    TokenKind::LBracket
                }
                b']' => {
                    self.offset += 1;
                    TokenKind::RBracket
                }
                b':' => {
                    self.offset += 1;
                    TokenKind::Colon
                }
                b',' => {
                    self.offset += 1;
                    TokenKind::Comma
                }
                b'!' => {
                    self.offset += 1;
                    TokenKind::Bang
                }
                b'&' if self.peek_byte(1) == Some(b'&') => {
                    self.offset += 2;
                    TokenKind::AndAnd
                }
                b'-' if self.peek_byte(1) == Some(b'>') => {
                    self.offset += 2;
                    TokenKind::Arrow
                }
                b'\'' | b'"' => TokenKind::Literal(self.read_quoted()?),
                _ => TokenKind::Literal(self.read_bare()?),
            };
            tokens.push(Token {
                kind: token,
                offset,
            });
        }
        tokens.push(Token {
            kind: TokenKind::Eof,
            offset: self.offset,
        });
        Ok(tokens)
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                self.offset += 1;
            }
            if self.bytes.get(self.offset) != Some(&b'#') {
                return;
            }
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| *byte != b'\n')
            {
                self.offset += 1;
            }
        }
    }

    fn peek_byte(&self, ahead: usize) -> Option<u8> {
        self.bytes.get(self.offset + ahead).copied()
    }

    fn read_quoted(&mut self) -> Result<String, ConfigError> {
        let quote = self.bytes[self.offset];
        self.offset += 1;
        let start = self.offset;
        while self.offset < self.bytes.len() && self.bytes[self.offset] != quote {
            self.offset += 1;
        }
        if self.offset >= self.bytes.len() {
            return Err(parse_error(
                self.input,
                start,
                "unterminated quoted literal",
            ));
        }
        let value = self.input[start..self.offset].to_owned();
        self.offset += 1;
        Ok(value)
    }

    fn read_bare(&mut self) -> Result<String, ConfigError> {
        let start = self.offset;
        while self.offset < self.bytes.len() && !self.is_bare_delimiter(self.offset) {
            self.offset += 1;
        }
        if self.offset == start {
            return Err(parse_error(self.input, start, "unexpected character"));
        }
        Ok(self.input[start..self.offset].to_owned())
    }

    fn is_bare_delimiter(&self, offset: usize) -> bool {
        let byte = self.bytes[offset];
        byte.is_ascii_whitespace()
            || matches!(
                byte,
                b'{' | b'}' | b'(' | b')' | b'[' | b']' | b':' | b',' | b'!' | b'#'
            )
            || (byte == b'&' && self.bytes.get(offset + 1) == Some(&b'&'))
            || (byte == b'-' && self.bytes.get(offset + 1) == Some(&b'>'))
    }
}

struct Parser<'a> {
    input: &'a str,
    tokens: Vec<Token>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            input,
            tokens,
            pos: 0,
        }
    }

    fn parse_sections(&mut self) -> Result<Vec<Section>, ConfigError> {
        let mut sections = Vec::new();
        while !self.at(TokenKindName::Eof) {
            sections.push(self.parse_section()?);
        }
        Ok(sections)
    }

    fn parse_section(&mut self) -> Result<Section, ConfigError> {
        let name = self.expect_literal("section name")?;
        self.expect(TokenKindName::LBrace)?;
        let mut items = Vec::new();
        while !self.at(TokenKindName::RBrace) {
            if self.at(TokenKindName::Eof) {
                return Err(self.error_here("expected section closing brace"));
            }
            items.push(self.parse_item()?);
        }
        self.expect(TokenKindName::RBrace)?;
        Ok(Section { name, items })
    }

    fn parse_item(&mut self) -> Result<Item, ConfigError> {
        if self.starts_section() {
            return Ok(Item::Section(Box::new(self.parse_section()?)));
        }

        if self.starts_function_expr_at(self.pos) {
            let and_functions = self.parse_function_expr()?;
            self.expect(TokenKindName::Arrow)?;
            let outbound = self.parse_outbound()?;
            return Ok(Item::RoutingRule(RoutingRule {
                and_functions,
                outbound,
            }));
        }

        if self.at_literal() {
            if self.at_name(TokenKindName::Colon, 1) {
                return Ok(Item::Param(self.parse_declaration()?));
            }
            return Ok(Item::Param(Param {
                key: String::new(),
                val: self.expect_literal("literal item")?,
                and_functions: Vec::new(),
                annotation: Vec::new(),
            }));
        }

        Err(self.error_here("expected item"))
    }

    fn parse_declaration(&mut self) -> Result<Param, ConfigError> {
        let key = self.expect_literal("parameter key")?;
        self.expect(TokenKindName::Colon)?;
        let mut param = if self.starts_function_expr_at(self.pos) {
            Param {
                key,
                val: String::new(),
                and_functions: self.parse_function_expr()?,
                annotation: Vec::new(),
            }
        } else {
            Param {
                key,
                val: self.parse_literal_expr()?,
                and_functions: Vec::new(),
                annotation: Vec::new(),
            }
        };
        if self.at(TokenKindName::LBracket) {
            self.expect(TokenKindName::LBracket)?;
            if self.at(TokenKindName::RBracket) {
                return Err(self.error_here("empty annotation"));
            }
            param.annotation = self.parse_param_list()?;
            self.expect(TokenKindName::RBracket)?;
        }
        Ok(param)
    }

    fn parse_literal_expr(&mut self) -> Result<String, ConfigError> {
        let mut value = self.expect_literal("literal")?;
        while self.at(TokenKindName::Comma) {
            self.expect(TokenKindName::Comma)?;
            value.push(',');
            value.push_str(&self.expect_literal("literal")?);
        }
        Ok(value)
    }

    fn parse_function_expr(&mut self) -> Result<Vec<Function>, ConfigError> {
        let mut functions = vec![self.parse_function()?];
        while self.at(TokenKindName::AndAnd) {
            self.expect(TokenKindName::AndAnd)?;
            functions.push(self.parse_function()?);
        }
        Ok(functions)
    }

    fn parse_function(&mut self) -> Result<Function, ConfigError> {
        let not = if self.at(TokenKindName::Bang) {
            self.expect(TokenKindName::Bang)?;
            true
        } else {
            false
        };
        let name = self.expect_literal("function name")?;
        self.expect(TokenKindName::LParen)?;
        if self.at(TokenKindName::RParen) {
            return Err(self.error_here("empty parameter list is not supported."));
        }
        let params = self.parse_param_list()?;
        self.expect(TokenKindName::RParen)?;
        Ok(Function { name, not, params })
    }

    fn parse_param_list(&mut self) -> Result<Vec<Param>, ConfigError> {
        let mut params = vec![self.parse_function_param()?];
        while self.at(TokenKindName::Comma) {
            self.expect(TokenKindName::Comma)?;
            params.push(self.parse_function_param()?);
        }
        Ok(params)
    }

    fn parse_function_param(&mut self) -> Result<Param, ConfigError> {
        let first = self.expect_literal("function parameter")?;
        if self.at(TokenKindName::Colon) {
            self.expect(TokenKindName::Colon)?;
            Ok(Param {
                key: first,
                val: self.parse_function_param_value()?,
                and_functions: Vec::new(),
                annotation: Vec::new(),
            })
        } else {
            Ok(Param {
                key: String::new(),
                val: first,
                and_functions: Vec::new(),
                annotation: Vec::new(),
            })
        }
    }

    fn parse_function_param_value(&mut self) -> Result<String, ConfigError> {
        let mut value = String::new();
        let mut has_literal = false;
        loop {
            match &self.peek().kind {
                TokenKind::Literal(part) => {
                    value.push_str(part);
                    self.pos += 1;
                    has_literal = true;
                }
                TokenKind::Colon => {
                    self.pos += 1;
                    value.push(':');
                }
                TokenKind::Bang => {
                    self.pos += 1;
                    value.push('!');
                }
                _ => break,
            }
        }
        if has_literal {
            Ok(value)
        } else {
            Err(self.error_here("expected function parameter value"))
        }
    }

    fn parse_outbound(&mut self) -> Result<Function, ConfigError> {
        if self.starts_function_expr_at(self.pos) {
            return self.parse_function();
        }
        Ok(Function {
            name: self.expect_literal("outbound")?,
            not: false,
            params: Vec::new(),
        })
    }

    fn starts_section(&self) -> bool {
        self.at_literal() && self.at_name(TokenKindName::LBrace, 1)
    }

    fn starts_function_expr_at(&self, pos: usize) -> bool {
        let mut pos = pos;
        if matches!(
            self.tokens.get(pos).map(|token| &token.kind),
            Some(TokenKind::Bang)
        ) {
            pos += 1;
        }
        matches!(
            (
                self.tokens.get(pos).map(|token| &token.kind),
                self.tokens.get(pos + 1).map(|token| &token.kind)
            ),
            (Some(TokenKind::Literal(_)), Some(TokenKind::LParen))
        )
    }

    fn expect_literal(&mut self, expected: &str) -> Result<String, ConfigError> {
        let pos = self.pos;
        match std::mem::replace(&mut self.tokens[pos].kind, TokenKind::Eof) {
            TokenKind::Literal(value) => {
                self.pos += 1;
                Ok(value)
            }
            other => {
                self.tokens[pos].kind = other;
                Err(self.error_here(&format!("expected {expected}")))
            }
        }
    }

    fn expect(&mut self, expected: TokenKindName) -> Result<(), ConfigError> {
        if self.at(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error_here(&format!("expected {}", expected.name())))
        }
    }

    fn at(&self, expected: TokenKindName) -> bool {
        self.at_name(expected, 0)
    }

    fn at_name(&self, expected: TokenKindName, ahead: usize) -> bool {
        matches!(
            (
                expected,
                self.tokens.get(self.pos + ahead).map(|token| &token.kind)
            ),
            (TokenKindName::LBrace, Some(TokenKind::LBrace))
                | (TokenKindName::RBrace, Some(TokenKind::RBrace))
                | (TokenKindName::LParen, Some(TokenKind::LParen))
                | (TokenKindName::RParen, Some(TokenKind::RParen))
                | (TokenKindName::LBracket, Some(TokenKind::LBracket))
                | (TokenKindName::RBracket, Some(TokenKind::RBracket))
                | (TokenKindName::Colon, Some(TokenKind::Colon))
                | (TokenKindName::Comma, Some(TokenKind::Comma))
                | (TokenKindName::Bang, Some(TokenKind::Bang))
                | (TokenKindName::AndAnd, Some(TokenKind::AndAnd))
                | (TokenKindName::Arrow, Some(TokenKind::Arrow))
                | (TokenKindName::Eof, Some(TokenKind::Eof))
        )
    }

    fn at_literal(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Literal(_))
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn error_here(&self, message: &str) -> ConfigError {
        parse_error(self.input, self.peek().offset, message)
    }
}

#[derive(Clone, Copy)]
enum TokenKindName {
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Bang,
    AndAnd,
    Arrow,
    Eof,
}

impl TokenKindName {
    const fn name(self) -> &'static str {
        match self {
            Self::LBrace => "{",
            Self::RBrace => "}",
            Self::LParen => "(",
            Self::RParen => ")",
            Self::LBracket => "[",
            Self::RBracket => "]",
            Self::Colon => ":",
            Self::Comma => ",",
            Self::Bang => "!",
            Self::AndAnd => "&&",
            Self::Arrow => "->",
            Self::Eof => "end of file",
        }
    }
}

fn parse_error(input: &str, offset: usize, message: &str) -> ConfigError {
    let safe_offset = offset.min(input.len());
    let line_start = input[..safe_offset]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = input[safe_offset..]
        .find('\n')
        .map(|index| safe_offset + index)
        .unwrap_or(input.len());
    let line = input[..safe_offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = input[line_start..safe_offset].chars().count();
    let text = &input[line_start..line_end];
    let caret_padding = " ".repeat(column);

    ConfigError::Parse(format!(
        "line {line}:{column} {text}\n{caret_padding}^: {message}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ItemKind;
    use crate::fixtures::PARSER_AST_BASIC;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    #[test]
    fn parses_quoted_keyable_tags_with_config_delimiters() {
        let sections = parse_config(
            r#"
node {
  "9.[region]edge": "scheme://token@example.invalid:443?mode=test&type=stream#edge"
  "name with space": "opaque://example.invalid"
  "name#fragment": "endpoint://example.invalid"
}
dns {
  upstream {
    "dns.[region]": "udp://1.1.1.1:53"
  }
}
"#,
        )
        .unwrap();

        let Item::Param(first_node) = &sections[0].items[0] else {
            panic!("first node should be a param");
        };
        assert_eq!(first_node.key, "9.[region]edge");
        assert_eq!(
            first_node.val,
            "scheme://token@example.invalid:443?mode=test&type=stream#edge"
        );
        let Item::Param(space_node) = &sections[0].items[1] else {
            panic!("second node should be a param");
        };
        assert_eq!(space_node.key, "name with space");
        let Item::Param(fragment_node) = &sections[0].items[2] else {
            panic!("third node should be a param");
        };
        assert_eq!(fragment_node.key, "name#fragment");

        let Item::Section(upstream) = &sections[1].items[0] else {
            panic!("upstream should be a nested section");
        };
        let Item::Param(dns_upstream) = &upstream.items[0] else {
            panic!("dns upstream should be a param");
        };
        assert_eq!(dns_upstream.key, "dns.[region]");
        assert_eq!(dns_upstream.val, "udp://1.1.1.1:53");
    }

    #[test]
    fn parses_ast_basic_success_case() {
        let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
        let input = fixture["cases"][0]["input"].as_str().unwrap();
        let sections = parse_config(input).unwrap();

        assert_eq!(sections.len(), 5);
        assert_eq!(sections[0].name, "include");
        assert_eq!(sections[1].name, "global");
        assert_eq!(sections[2].name, "node");
        assert_eq!(sections[3].name, "group");
        assert_eq!(sections[4].name, "routing");

        let Item::Param(include) = &sections[0].items[0] else {
            panic!("include item should be param");
        };
        assert_eq!(include.key, "");
        assert_eq!(include.val, "child.dae");

        let Item::Param(tcp_check_url) = &sections[1].items[0] else {
            panic!("tcp_check_url item should be param");
        };
        assert_eq!(tcp_check_url.key, "tcp_check_url");
        assert_eq!(
            tcp_check_url.val,
            "https://connectivity.example/generate_204,1.1.1.1"
        );

        assert_eq!(sections[3].items[0].kind(), ItemKind::Section);
        let Item::Section(group) = &sections[3].items[0] else {
            panic!("group item should be a nested section");
        };
        assert_eq!(group.name, "test_group");

        let Item::Param(filter) = &group.items[0] else {
            panic!("filter item should be param");
        };
        assert_eq!(filter.key, "filter");
        assert_eq!(filter.and_functions.len(), 2);
        assert_eq!(filter.and_functions[0].name, "name");
        assert!(filter.and_functions[0].not);
        assert_eq!(filter.and_functions[0].params[0].key, "keyword");
        assert_eq!(filter.and_functions[0].params[0].val, "hk");
        assert_eq!(filter.and_functions[1].name, "subtag");
        assert_eq!(filter.annotation[0].key, "add_latency");
        assert_eq!(filter.annotation[0].val, "-500ms");

        let Item::Param(policy) = &group.items[1] else {
            panic!("policy item should be param");
        };
        assert_eq!(policy.and_functions[0].name, "fixed");
        assert_eq!(policy.and_functions[0].params[0].val, "0");

        let Item::RoutingRule(rule) = &sections[4].items[1] else {
            panic!("second routing item should be rule");
        };
        assert_eq!(rule.and_functions[0].name, "domain");
        assert_eq!(rule.and_functions[0].params[0].key, "suffix");
        assert_eq!(rule.outbound.name, "proxy");
        assert_eq!(rule.outbound.params[0].key, "mark");
        assert_eq!(rule.outbound.params[0].val, "1");
    }

    #[test]
    fn parses_bare_function_param_values_with_delimiter_fragments() {
        let sections = parse_config(
            r#"
routing {
    sample(scope:set-alpha-!beta, source:sample-set:item@scope) -> outlet
}
"#,
        )
        .unwrap();

        let Item::RoutingRule(rule) = &sections[0].items[0] else {
            panic!("routing item should be a rule");
        };
        let params = &rule.and_functions[0].params;
        assert_eq!(params[0].key, "scope");
        assert_eq!(params[0].val, "set-alpha-!beta");
        assert_eq!(params[1].key, "source");
        assert_eq!(params[1].val, "sample-set:item@scope");
    }

    #[test]
    fn parses_delimiter_fragments_in_generic_function_values_only_until_structure_boundaries() {
        let sections = parse_config(
            r#"
group {
    sample {
        filter: name(label:!edge:alpha) && subtag(scope:default)
        policy: fixed(0)
    }
}
"#,
        )
        .unwrap();

        let Item::Section(group) = &sections[0].items[0] else {
            panic!("group item should be a nested section");
        };
        let Item::Param(filter) = &group.items[0] else {
            panic!("filter item should be a param");
        };
        assert_eq!(filter.and_functions.len(), 2);
        assert_eq!(filter.and_functions[0].name, "name");
        assert_eq!(filter.and_functions[0].params[0].key, "label");
        assert_eq!(filter.and_functions[0].params[0].val, "!edge:alpha");
        assert_eq!(filter.and_functions[1].name, "subtag");
        assert_eq!(filter.and_functions[1].params[0].key, "scope");
        assert_eq!(filter.and_functions[1].params[0].val, "default");
    }

    #[test]
    fn parses_ast_basic_projection_matches_go_golden() {
        let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
        let case = &fixture["cases"][0];
        let input = case["input"].as_str().unwrap();
        let sections = parse_config(input).unwrap();

        assert_eq!(project_sections(&sections), case["sections"]);
    }

    #[test]
    fn parses_example_dae_projection_and_strings_match_go_golden() {
        let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
        let example = include_str!("../../../../example.dae");
        let example_bytes = include_bytes!("../../../../example.dae");
        let sections = parse_config(example).unwrap();
        let want = &fixture["example_dae"];
        let section_strings = project_section_strings(&sections);
        let joined = section_strings.join(want["section_string_join_separator"].as_str().unwrap());

        assert_eq!(hex_sha256(example_bytes), want["input_sha256"]);
        assert_eq!(
            sections.len(),
            want["section_count"].as_u64().unwrap() as usize
        );
        assert_eq!(
            count_items_recursive(&sections),
            want["item_count_recursive"].as_u64().unwrap() as usize
        );
        assert_eq!(project_sections(&sections), want["sections"]);
        assert_eq!(json!(section_strings), want["section_strings"]);
        assert_eq!(
            hex_sha256(joined.as_bytes()),
            want["section_strings_sha256"]
        );
    }

    #[test]
    fn rejects_ast_basic_error_cases() {
        let fixture = dae_golden::load_json(PARSER_AST_BASIC).unwrap();
        for case in &fixture["cases"].as_array().unwrap()[1..] {
            let input = case["input"].as_str().unwrap();
            assert!(parse_config(input).is_err(), "{}", case["name"]);
        }
    }

    #[test]
    fn parses_example_and_marshal_golden_text() {
        let example = include_str!("../../../../example.dae");
        let sections = parse_config(example).unwrap();
        assert!(sections.iter().any(|section| section.name == "global"));
        assert!(sections.iter().any(|section| section.name == "routing"));

        let fixture = dae_golden::load_json(crate::fixtures::MARSHAL_EXAMPLE_ROUNDTRIP).unwrap();
        let text = fixture["marshal"]["text"].as_str().unwrap();
        let sections = parse_config(text).unwrap();
        assert_eq!(sections[0].name, "global");
        assert_eq!(sections.last().unwrap().name, "dns");
    }

    fn project_sections(sections: &[Section]) -> Value {
        Value::Array(sections.iter().map(project_section).collect())
    }

    fn project_section_strings(sections: &[Section]) -> Vec<String> {
        sections
            .iter()
            .map(|section| section.to_config_string(false, false))
            .collect()
    }

    fn count_items_recursive(sections: &[Section]) -> usize {
        sections.iter().map(count_section_items).sum()
    }

    fn count_section_items(section: &Section) -> usize {
        section
            .items
            .iter()
            .map(|item| {
                1 + match item {
                    Item::Section(section) => count_section_items(section),
                    Item::Param(_) | Item::RoutingRule(_) => 0,
                }
            })
            .sum()
    }

    fn hex_sha256(input: &[u8]) -> String {
        format!("{:x}", Sha256::digest(input))
    }

    fn project_section(section: &Section) -> Value {
        json!({
            "name": section.name,
            "items": section.items.iter().map(project_item).collect::<Vec<_>>(),
        })
    }

    fn project_item(item: &Item) -> Value {
        match item {
            Item::Param(param) => json!({
                "item_type": "Param",
                "value_kind": "Param",
                "param": project_param(param),
            }),
            Item::Section(section) => json!({
                "item_type": "Param",
                "value_kind": "Section",
                "section": project_section(section),
            }),
            Item::RoutingRule(rule) => json!({
                "item_type": "RoutingRule",
                "value_kind": "RoutingRule",
                "routing_rule": project_routing_rule(rule),
            }),
        }
    }

    fn project_param(param: &Param) -> Value {
        let mut out = serde_json::Map::from_iter([
            ("key".to_owned(), json!(param.key)),
            ("val".to_owned(), json!(param.val)),
        ]);
        if !param.and_functions.is_empty() {
            out.insert(
                "and_functions".to_owned(),
                Value::Array(param.and_functions.iter().map(project_function).collect()),
            );
        }
        if !param.annotation.is_empty() {
            out.insert(
                "annotation".to_owned(),
                Value::Array(param.annotation.iter().map(project_param).collect()),
            );
        }
        Value::Object(out)
    }

    fn project_function(function: &Function) -> Value {
        json!({
            "name": function.name,
            "not": function.not,
            "params": function.params.iter().map(project_param).collect::<Vec<_>>(),
        })
    }

    fn project_routing_rule(rule: &RoutingRule) -> Value {
        json!({
            "and_functions": rule.and_functions.iter().map(project_function).collect::<Vec<_>>(),
            "outbound": project_function(&rule.outbound),
        })
    }
}
