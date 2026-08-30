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
enum CompiledFilterParam {
    Exact(String),
    Keyword(String),
    Regex(Regex),
}

#[derive(Clone, Debug)]
struct CompiledFilter {
    input: CompiledFilterInput,
    not: bool,
    params: Vec<CompiledFilterParam>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompiledFilterInput {
    Name,
    SubscriptionTag,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedDialerRef<'a> {
    pub index: usize,
    pub name: &'a str,
    pub subscription_tag: &'a str,
    pub annotation: Annotation,
}

#[derive(Clone, Debug, Default)]
pub struct CompiledFilterGroups {
    groups: Vec<Vec<CompiledFilter>>,
}

impl CompiledFilterGroups {
    pub fn compile(filter_groups: &[Vec<Filter>]) -> Result<Self, OutboundError> {
        let mut groups = Vec::with_capacity(filter_groups.len());
        for group in filter_groups {
            let mut compiled_group = Vec::with_capacity(group.len());
            for filter in group {
                let input = match filter.name.as_str() {
                    "name" => CompiledFilterInput::Name,
                    "subtag" => CompiledFilterInput::SubscriptionTag,
                    "link" => {
                        return Err(OutboundError::UnsupportedFilterInput("link".to_owned()));
                    }
                    other => return Err(OutboundError::UnsupportedFilterInput(other.to_owned())),
                };
                let mut params = Vec::with_capacity(filter.params.len());
                for param in &filter.params {
                    let compiled = match (input, param.key.as_str()) {
                        (CompiledFilterInput::Name, "regex")
                        | (CompiledFilterInput::SubscriptionTag, "regex") => {
                            CompiledFilterParam::Regex(
                                Regex::new(&param.value)
                                    .map_err(|_| OutboundError::BadRegex(param.value.clone()))?,
                            )
                        }
                        (CompiledFilterInput::Name, "keyword") => {
                            CompiledFilterParam::Keyword(param.value.clone())
                        }
                        (CompiledFilterInput::Name, "")
                        | (CompiledFilterInput::SubscriptionTag, "") => {
                            CompiledFilterParam::Exact(param.value.clone())
                        }
                        (input, key) => {
                            return Err(OutboundError::UnsupportedFilterKey {
                                input: input.as_str().to_owned(),
                                key: key.to_owned(),
                            });
                        }
                    };
                    params.push(compiled);
                }
                compiled_group.push(CompiledFilter {
                    input,
                    not: filter.not,
                    params,
                });
            }
            groups.push(compiled_group);
        }
        Ok(Self { groups })
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

impl CompiledFilterInput {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::SubscriptionTag => "subtag",
        }
    }
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

        let compiled_groups = CompiledFilterGroups::compile(filter_groups)?;
        self.filter_and_annotate_compiled(&compiled_groups, annotations)
            .map(|matched| {
                matched
                    .into_iter()
                    .map(|matched| MatchedDialer {
                        index: matched.index,
                        name: matched.name.to_owned(),
                        subscription_tag: matched.subscription_tag.to_owned(),
                        annotation: matched.annotation,
                    })
                    .collect()
            })
    }

    pub fn filter_and_annotate_compiled<'a>(
        &'a self,
        compiled_groups: &CompiledFilterGroups,
        annotations: &[Annotation],
    ) -> Result<Vec<MatchedDialerRef<'a>>, OutboundError> {
        let mut matched = Vec::with_capacity(self.dialers.len());
        self.filter_and_annotate_compiled_into(compiled_groups, annotations, &mut matched)?;
        Ok(matched)
    }

    pub fn filter_and_annotate_compiled_into<'a>(
        &'a self,
        compiled_groups: &CompiledFilterGroups,
        annotations: &[Annotation],
        matched: &mut Vec<MatchedDialerRef<'a>>,
    ) -> Result<(), OutboundError> {
        if compiled_groups.groups.len() != annotations.len() {
            return Err(OutboundError::UnsupportedPolicy(
                "unmatched annotations length".to_owned(),
            ));
        }
        matched.clear();
        if compiled_groups.is_empty() {
            matched.reserve(self.dialers.len());
            matched.extend(self.dialers.iter().enumerate().map(|(index, dialer)| {
                MatchedDialerRef {
                    index,
                    name: &dialer.name,
                    subscription_tag: &dialer.subscription_tag,
                    annotation: Annotation::default(),
                }
            }));
            return Ok(());
        }
        if self.dialers.is_empty() {
            return Ok(());
        }

        matched.reserve(self.dialers.len());
        'next_dialer: for (index, dialer) in self.dialers.iter().enumerate() {
            for (group_index, group) in compiled_groups.groups.iter().enumerate() {
                if self.filter_group_hit(dialer, group)? {
                    matched.push(MatchedDialerRef {
                        index,
                        name: &dialer.name,
                        subscription_tag: &dialer.subscription_tag,
                        annotation: annotations[group_index],
                    });
                    continue 'next_dialer;
                }
            }
        }
        Ok(())
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
            let input = match filter.input {
                CompiledFilterInput::Name => &dialer.name,
                CompiledFilterInput::SubscriptionTag => &dialer.subscription_tag,
            };
            let sub_hit = filter_params_match(input, &filter.params);
            if sub_hit == filter.not {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn filter_params_match(input: &str, params: &[CompiledFilterParam]) -> bool {
    for param in params {
        match param {
            CompiledFilterParam::Regex(regex) => {
                if regex.is_match(input) {
                    return true;
                }
            }
            CompiledFilterParam::Keyword(value) => {
                if input.contains(value) {
                    return true;
                }
            }
            CompiledFilterParam::Exact(value) => {
                if input == value {
                    return true;
                }
            }
        }
    }
    false
}
