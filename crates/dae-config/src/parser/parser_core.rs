use super::*;
pub(super) struct Parser<'a> {
    pub(super) input: &'a str,
    pub(super) tokens: Vec<Token>,
    pub(super) pos: usize,
    section_depth: usize,
    ast_nodes: usize,
}

/// Maximum nesting depth for sections.  `parse_section` recurses for nested
/// sections; without a bound, a deeply nested configuration would overflow
/// the stack (user-controlled input on the validate/reload path).
const MAX_SECTION_DEPTH: usize = 128;

impl<'a> Parser<'a> {
    pub(super) fn new(input: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            input,
            tokens,
            pos: 0,
            section_depth: 0,
            ast_nodes: 0,
        }
    }

    pub(super) fn parse_sections(&mut self) -> Result<Vec<Section>, ConfigError> {
        let mut sections = Vec::new();
        while !self.at(TokenKindName::Eof) {
            sections.push(self.parse_section()?);
        }
        Ok(sections)
    }

    pub(super) fn parse_section(&mut self) -> Result<Section, ConfigError> {
        self.charge_ast_node()?;
        if self.section_depth >= MAX_SECTION_DEPTH {
            return Err(self.error_here(&format!(
                "section nesting exceeds limit of {MAX_SECTION_DEPTH}"
            )));
        }
        self.section_depth += 1;
        let result = self.parse_section_inner();
        self.section_depth -= 1;
        result
    }

    fn parse_section_inner(&mut self) -> Result<Section, ConfigError> {
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

    pub(super) fn parse_item(&mut self) -> Result<Item, ConfigError> {
        self.charge_ast_node()?;
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

    fn charge_ast_node(&mut self) -> Result<(), ConfigError> {
        if self.ast_nodes >= MAX_CONFIG_AST_NODES {
            return Err(self.error_here(&format!(
                "section/item count exceeds limit of {MAX_CONFIG_AST_NODES}"
            )));
        }
        self.ast_nodes += 1;
        Ok(())
    }

    pub(super) fn parse_declaration(&mut self) -> Result<Param, ConfigError> {
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

    pub(super) fn parse_literal_expr(&mut self) -> Result<String, ConfigError> {
        let mut value = self.expect_literal("literal")?;
        while self.at(TokenKindName::Comma) {
            self.expect(TokenKindName::Comma)?;
            value.push(',');
            value.push_str(&self.expect_literal("literal")?);
        }
        Ok(value)
    }

    pub(super) fn parse_function_expr(&mut self) -> Result<Vec<Function>, ConfigError> {
        let mut functions = vec![self.parse_function()?];
        while self.at(TokenKindName::AndAnd) {
            self.expect(TokenKindName::AndAnd)?;
            functions.push(self.parse_function()?);
        }
        Ok(functions)
    }

    pub(super) fn parse_function(&mut self) -> Result<Function, ConfigError> {
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

    pub(super) fn parse_param_list(&mut self) -> Result<Vec<Param>, ConfigError> {
        let mut params = vec![self.parse_function_param()?];
        while self.at(TokenKindName::Comma) {
            self.expect(TokenKindName::Comma)?;
            params.push(self.parse_function_param()?);
        }
        Ok(params)
    }

    pub(super) fn parse_function_param(&mut self) -> Result<Param, ConfigError> {
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

    pub(super) fn parse_function_param_value(&mut self) -> Result<String, ConfigError> {
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

    pub(super) fn parse_outbound(&mut self) -> Result<Function, ConfigError> {
        if self.starts_function_expr_at(self.pos) {
            return self.parse_function();
        }
        Ok(Function {
            name: self.expect_literal("outbound")?,
            not: false,
            params: Vec::new(),
        })
    }

    pub(super) fn starts_section(&self) -> bool {
        self.at_literal() && self.at_name(TokenKindName::LBrace, 1)
    }

    pub(super) fn starts_function_expr_at(&self, pos: usize) -> bool {
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

    pub(super) fn expect_literal(&mut self, expected: &str) -> Result<String, ConfigError> {
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

    pub(super) fn expect(&mut self, expected: TokenKindName) -> Result<(), ConfigError> {
        if self.at(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error_here(&format!("expected {}", expected.name())))
        }
    }

    pub(super) fn at(&self, expected: TokenKindName) -> bool {
        self.at_name(expected, 0)
    }

    pub(super) fn at_name(&self, expected: TokenKindName, ahead: usize) -> bool {
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

    pub(super) fn at_literal(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Literal(_))
    }

    pub(super) fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    pub(super) fn error_here(&self, message: &str) -> ConfigError {
        parse_error(self.input, self.peek().offset, message)
    }
}
