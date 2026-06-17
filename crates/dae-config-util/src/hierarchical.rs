use std::fmt;

use serde_json::{Map, Value};

use crate::{ConfigDuration, FuzzyDecode, UrlOrEmpty};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayHierarchicalKey;

impl fmt::Display for OverlayHierarchicalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("overlay hierarchical key")
    }
}

impl std::error::Error for OverlayHierarchicalKey {}

pub fn set_value_hierarchical_map(
    map: &mut Map<String, Value>,
    key: &str,
    value: Value,
) -> Result<(), OverlayHierarchicalKey> {
    let parts: Vec<_> = key.split('.').collect();
    set_map_path(map, &parts, value)
}

fn set_map_path(
    map: &mut Map<String, Value>,
    parts: &[&str],
    value: Value,
) -> Result<(), OverlayHierarchicalKey> {
    if parts.len() == 1 {
        map.insert(parts[0].to_owned(), value);
        return Ok(());
    }

    let entry = map
        .entry(parts[0].to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(next) = entry else {
        return Err(OverlayHierarchicalKey);
    };
    set_map_path(next, &parts[1..], value)
}

pub trait TaggedStruct {
    fn field_mut(&mut self, tag: &str) -> Option<TaggedFieldMut<'_>>;
}

pub enum TaggedFieldMut<'a> {
    Struct(&'a mut dyn TaggedStruct),
    Bool(&'a mut bool),
    String(&'a mut String),
    Duration(&'a mut ConfigDuration),
    StringSlice(&'a mut Option<Vec<String>>),
    UrlOrEmpty(&'a mut UrlOrEmpty),
}

impl TaggedFieldMut<'_> {
    fn kind(&self) -> &'static str {
        match self {
            Self::Struct(_) => "struct",
            Self::Bool(_) => "bool",
            Self::String(_) => "string",
            Self::Duration(_) => "int64",
            Self::StringSlice(_) => "slice",
            Self::UrlOrEmpty(_) => "struct",
        }
    }

    fn set_from_str(self, value: &str) -> bool {
        match self {
            Self::Struct(_) => false,
            Self::Bool(target) => {
                let Some(value) = bool::fuzzy_decode(value) else {
                    return false;
                };
                *target = value;
                true
            }
            Self::String(target) => {
                let Some(value) = String::fuzzy_decode(value) else {
                    return false;
                };
                *target = value;
                true
            }
            Self::Duration(target) => {
                let Some(value) = ConfigDuration::fuzzy_decode(value) else {
                    return false;
                };
                *target = value;
                true
            }
            Self::StringSlice(target) => {
                let Some(value) = Vec::<String>::fuzzy_decode(value) else {
                    return false;
                };
                *target = Some(value);
                true
            }
            Self::UrlOrEmpty(target) => {
                let Some(value) = UrlOrEmpty::fuzzy_decode(value) else {
                    return false;
                };
                *target = value;
                true
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HierarchicalStructError {
    UnexpectedKey {
        key: String,
        last_key: String,
        kind: &'static str,
        member: String,
    },
    TypeMismatch {
        kind: &'static str,
        value: String,
    },
}

impl fmt::Display for HierarchicalStructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedKey {
                key,
                last_key,
                kind,
                member,
            } => write!(
                f,
                "unexpected key \"{key}\": \"{last_key}\" ({kind} type) has no member \"{member}\""
            ),
            Self::TypeMismatch { kind, value } => {
                write!(
                    f,
                    "type does not match: type \"{kind}\" and value \"{value}\""
                )
            }
        }
    }
}

impl std::error::Error for HierarchicalStructError {}

pub fn set_value_hierarchical_struct(
    root: &mut dyn TaggedStruct,
    key: &str,
    value: &str,
) -> Result<(), HierarchicalStructError> {
    let parts: Vec<_> = key.split('.').collect();
    let mut current = root;
    let mut last_key = "";

    for (index, part) in parts.iter().enumerate() {
        let is_last = index == parts.len() - 1;
        let Some(field) = current.field_mut(part) else {
            return Err(HierarchicalStructError::UnexpectedKey {
                key: key.to_owned(),
                last_key: last_key.to_owned(),
                kind: "struct",
                member: (*part).to_owned(),
            });
        };

        if is_last {
            let kind = field.kind();
            if field.set_from_str(value) {
                return Ok(());
            }
            return Err(HierarchicalStructError::TypeMismatch {
                kind,
                value: value.to_owned(),
            });
        }

        match field {
            TaggedFieldMut::Struct(next) => {
                current = next;
                last_key = part;
            }
            other => {
                return Err(HierarchicalStructError::UnexpectedKey {
                    key: key.to_owned(),
                    last_key: last_key.to_owned(),
                    kind: other.kind(),
                    member: parts[index + 1].to_owned(),
                });
            }
        }
    }

    Err(HierarchicalStructError::UnexpectedKey {
        key: key.to_owned(),
        last_key: String::new(),
        kind: "struct",
        member: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hierarchical_map_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/utils/common.json").unwrap();

        for case in fixture["hierarchical_map"].as_array().unwrap() {
            let mut map = match case["name"].as_str().unwrap() {
                "set-new-path" => Map::new(),
                "extend-existing-map" => {
                    let Value::Object(map) = json!({"global": {"mptcp": true}}) else {
                        unreachable!()
                    };
                    map
                }
                "existing-non-map-error" => {
                    let Value::Object(map) = json!({"global": "not-map"}) else {
                        unreachable!()
                    };
                    map
                }
                other => panic!("unhandled hierarchical map fixture case {other}"),
            };

            let got = set_value_hierarchical_map(
                &mut map,
                case["key"].as_str().unwrap(),
                case["value"].clone(),
            );
            assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap());
            match got {
                Ok(()) => assert_eq!(Value::Object(map), case["map"]),
                Err(err) => assert_eq!(err.to_string(), case["error"].as_str().unwrap()),
            }
        }
    }

    #[test]
    fn hierarchical_struct_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/utils/common.json").unwrap();

        for case in fixture["hierarchical_struct"].as_array().unwrap() {
            let mut config = DemoConfig::default();
            let got = set_value_hierarchical_struct(
                &mut config,
                case["key"].as_str().unwrap(),
                case["value"].as_str().unwrap(),
            );
            assert_eq!(got.is_ok(), case["ok"].as_bool().unwrap());
            match got {
                Ok(()) => assert_eq!(config.snapshot(), case["after"]),
                Err(err) => assert_eq!(err.to_string(), case["error"].as_str().unwrap()),
            }
        }
    }

    #[derive(Default)]
    struct DemoConfig {
        global: DemoGlobal,
    }

    #[derive(Default)]
    struct DemoGlobal {
        mptcp: bool,
        duration: ConfigDuration,
        labels: Option<Vec<String>>,
        url: UrlOrEmpty,
    }

    impl TaggedStruct for DemoConfig {
        fn field_mut(&mut self, tag: &str) -> Option<TaggedFieldMut<'_>> {
            match tag {
                "global" => Some(TaggedFieldMut::Struct(&mut self.global)),
                _ => None,
            }
        }
    }

    impl TaggedStruct for DemoGlobal {
        fn field_mut(&mut self, tag: &str) -> Option<TaggedFieldMut<'_>> {
            match tag {
                "mptcp" => Some(TaggedFieldMut::Bool(&mut self.mptcp)),
                "duration" => Some(TaggedFieldMut::Duration(&mut self.duration)),
                "labels" => Some(TaggedFieldMut::StringSlice(&mut self.labels)),
                "url" => Some(TaggedFieldMut::UrlOrEmpty(&mut self.url)),
                _ => None,
            }
        }
    }

    impl DemoConfig {
        fn snapshot(&self) -> Value {
            json!({
                "global": {
                    "mptcp": self.global.mptcp,
                    "duration": self.global.duration.to_string(),
                    "labels": self.global.labels,
                    "url": {
                        "empty": self.global.url.empty,
                        "url": self.global.url.url,
                    },
                },
            })
        }
    }
}
