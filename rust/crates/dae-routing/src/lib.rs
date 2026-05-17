pub mod domain;
pub mod error;
pub mod prefix;
pub mod trie;
pub mod userspace;

pub use domain::{DomainKey, DomainMatcher};
pub use error::RoutingError;
pub use prefix::{IpPrefix, parse_prefixes_to_strings};
pub use trie::{Trie, ValidChars};
pub use userspace::{Query, RoutingMatcher};
