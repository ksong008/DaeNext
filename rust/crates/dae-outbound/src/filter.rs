use regex::Regex;

use crate::annotation::Annotation;
use crate::dialer::Dialer;
use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterParam {
    pub key: String,
    pub value: String,
}

impl FilterParam {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Filter {
    pub name: String,
    pub not: bool,
    pub params: Vec<FilterParam>,
}

#[derive(Clone, Debug)]
struct CompiledFilterParam {
    key: String,
    value: String,
    regex: Option<Regex>,
}

#[derive(Clone, Debug)]
struct CompiledFilter {
    name: String,
    not: bool,
    params: Vec<CompiledFilterParam>,
}

impl Filter {
    pub fn new(name: impl Into<String>, params: Vec<FilterParam>) -> Self {
        Self {
            name: name.into(),
            not: false,
            params,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchedDialer {
    pub index: usize,
    pub name: String,
    pub subscription_tag: String,
    pub annotation: Annotation,
}

#[derive(Clone, Debug, Default)]
pub struct DialerSet {
    pub dialers: Vec<Dialer>,
}

impl DialerSet {
    pub fn filter_and_annotate(
        &self,
        filter_groups: &[Vec<Filter>],
        annotations: &[Annotation],
    ) -> Result<Vec<MatchedDialer>, OutboundError> {
        if filter_groups.len() != annotations.len() {
            return Err(OutboundError::UnsupportedPolicy(
                "unmatched annotations length".to_owned(),
            ));
        }
        if filter_groups.is_empty() {
            return Ok(self
                .dialers
                .iter()
                .enumerate()
                .map(|(index, dialer)| MatchedDialer {
                    index,
                    name: dialer.name.clone(),
                    subscription_tag: dialer.subscription_tag.clone(),
                    annotation: Annotation::default(),
                })
                .collect());
        }
        if self.dialers.is_empty() {
            return Ok(Vec::new());
        }

        let compiled_groups = compile_filter_groups(filter_groups)?;
        let mut matched = Vec::new();
        'next_dialer: for (index, dialer) in self.dialers.iter().enumerate() {
            for (group_index, group) in compiled_groups.iter().enumerate() {
                if self.filter_group_hit(dialer, group)? {
                    matched.push(MatchedDialer {
                        index,
                        name: dialer.name.clone(),
                        subscription_tag: dialer.subscription_tag.clone(),
                        annotation: annotations[group_index],
                    });
                    continue 'next_dialer;
                }
            }
        }
        Ok(matched)
    }

    fn filter_group_hit(
        &self,
        dialer: &Dialer,
        filters: &[CompiledFilter],
    ) -> Result<bool, OutboundError> {
        if filters.is_empty() {
            return Ok(true);
        }
        for filter in filters {
            let sub_hit = match filter.name.as_str() {
                "name" => filter_params_match(&dialer.name, "name", &filter.params)?,
                "subtag" => {
                    filter_params_match(&dialer.subscription_tag, "subtag", &filter.params)?
                }
                "link" => return Err(OutboundError::UnsupportedFilterInput("link".to_owned())),
                other => return Err(OutboundError::UnsupportedFilterInput(other.to_owned())),
            };
            if sub_hit == filter.not {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn compile_filter_groups(
    filter_groups: &[Vec<Filter>],
) -> Result<Vec<Vec<CompiledFilter>>, OutboundError> {
    filter_groups
        .iter()
        .map(|group| {
            group
                .iter()
                .map(|filter| {
                    let params = filter
                        .params
                        .iter()
                        .map(|param| {
                            let regex = match (filter.name.as_str(), param.key.as_str()) {
                                ("name", "regex") | ("subtag", "regex") => {
                                    Some(Regex::new(&param.value).map_err(|_| {
                                        OutboundError::BadRegex(param.value.clone())
                                    })?)
                                }
                                _ => None,
                            };
                            Ok(CompiledFilterParam {
                                key: param.key.clone(),
                                value: param.value.clone(),
                                regex,
                            })
                        })
                        .collect::<Result<Vec<_>, OutboundError>>()?;
                    Ok(CompiledFilter {
                        name: filter.name.clone(),
                        not: filter.not,
                        params,
                    })
                })
                .collect()
        })
        .collect()
}

fn filter_params_match(
    input: &str,
    filter_name: &str,
    params: &[CompiledFilterParam],
) -> Result<bool, OutboundError> {
    for param in params {
        match (filter_name, param.key.as_str()) {
            ("name", "regex") | ("subtag", "regex") => {
                if param.regex.as_ref().unwrap().is_match(input) {
                    return Ok(true);
                }
            }
            ("name", "keyword") => {
                if input.contains(&param.value) {
                    return Ok(true);
                }
            }
            ("name", "") | ("subtag", "") => {
                if input == param.value {
                    return Ok(true);
                }
            }
            (_, key) => {
                return Err(OutboundError::UnsupportedFilterKey {
                    input: filter_name.to_owned(),
                    key: key.to_owned(),
                });
            }
        }
    }
    Ok(false)
}
