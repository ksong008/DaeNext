#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TokenKind {
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
pub(super) struct Token {
    pub(super) kind: TokenKind,
    pub(super) offset: usize,
}
#[derive(Clone, Copy)]
pub(super) enum TokenKindName {
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
    pub(super) const fn name(self) -> &'static str {
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
