use crate::ast::Section;
use crate::ast::{Function, Item, Param, RoutingRule};
use crate::error::ConfigError;

mod entry;
pub use self::entry::*;
mod token;
use self::token::*;
mod lexer;
use self::lexer::*;
mod parser_core;
use self::parser_core::*;
mod error;
use self::error::*;
#[cfg(test)]
mod tests;

const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONFIG_TOKENS: usize = 512 * 1024;
const MAX_CONFIG_TOKEN_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_AST_NODES: usize = 256 * 1024;
