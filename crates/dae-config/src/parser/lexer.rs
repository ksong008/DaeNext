use super::*;
pub(super) struct Lexer<'a> {
    pub(super) input: &'a str,
    pub(super) bytes: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> Lexer<'a> {
    pub(super) fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            offset: 0,
        }
    }

    pub(super) fn tokenize(mut self) -> Result<Vec<Token>, ConfigError> {
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

    pub(super) fn skip_ws_and_comments(&mut self) {
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

    pub(super) fn peek_byte(&self, ahead: usize) -> Option<u8> {
        self.bytes.get(self.offset + ahead).copied()
    }

    pub(super) fn read_quoted(&mut self) -> Result<String, ConfigError> {
        let quote = self.bytes[self.offset];
        self.offset += 1;
        let start = self.offset;
        // Double-quoted literals are unescaped symmetrically with
        // crate::ast::quote_string (\\, \", \n, \r, \t) so that
        // parse(marshal(value)) == value. Single-quoted literals keep their
        // bytes verbatim (no escape processing), preserving the previous
        // behavior for single-quoted values.
        let mut value = String::new();
        let mut run_start = start;
        while self.offset < self.bytes.len() {
            let byte = self.bytes[self.offset];
            if byte == quote {
                value.push_str(&self.input[run_start..self.offset]);
                self.offset += 1;
                return Ok(value);
            }
            if quote == b'"' && byte == b'\\' {
                value.push_str(&self.input[run_start..self.offset]);
                self.offset += 1;
                if self.offset >= self.bytes.len() {
                    return Err(parse_error(
                        self.input,
                        start,
                        "unterminated quoted literal",
                    ));
                }
                let escaped = self.bytes[self.offset];
                self.offset += 1;
                match escaped {
                    b'\\' => value.push('\\'),
                    b'"' => value.push('"'),
                    b'n' => value.push('\n'),
                    b'r' => value.push('\r'),
                    b't' => value.push('\t'),
                    // quote_string never emits any other escape; keep the
                    // backslash and the character verbatim so hand-written
                    // configs with stray backslashes are unchanged.  `escaped`
                    // may be the first byte of a multi-byte UTF-8 character:
                    // treat it as a full `char` and advance past all its bytes
                    // so the next `run_start` slice stays on a char boundary
                    // (a single-byte advance would slice mid-character later).
                    other => {
                        let ch = self.input[self.offset - 1..]
                            .chars()
                            .next()
                            .unwrap_or(other as char);
                        value.push('\\');
                        value.push(ch);
                        self.offset += ch.len_utf8() - 1;
                    }
                }
                run_start = self.offset;
                continue;
            }
            self.offset += 1;
        }
        Err(parse_error(
            self.input,
            start,
            "unterminated quoted literal",
        ))
    }

    pub(super) fn read_bare(&mut self) -> Result<String, ConfigError> {
        let start = self.offset;
        while self.offset < self.bytes.len() && !self.is_bare_delimiter(self.offset) {
            self.offset += 1;
        }
        if self.offset == start {
            return Err(parse_error(self.input, start, "unexpected character"));
        }
        Ok(self.input[start..self.offset].to_owned())
    }

    pub(super) fn is_bare_delimiter(&self, offset: usize) -> bool {
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
