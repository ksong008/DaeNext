use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;

use dae_config_util::{FuzzyDecode, GoDuration, fuzzy_decode, is_valid_http_method};

use crate::ast::{Function, Item, Param, RoutingRule, Section};
use crate::dynamic::DynamicFunctionValue;
use crate::error::ConfigError;

mod build;
mod parser;
mod patch;
mod types;
mod utils;

#[cfg(test)]
mod tests;

pub use build::build_config;
pub use types::*;
