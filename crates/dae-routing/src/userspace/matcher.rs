use super::*;
impl RoutingMatcher {
    pub fn from_typed_sets(
        domain_sets: Vec<RoutingDomainSet>,
        lpm_sets: Vec<RoutingLpmSet>,
        matches: Vec<RoutingMatchSet>,
    ) -> Result<Self, RoutingError> {
        let domain_sets = domain_sets
            .into_iter()
            .map(|set| {
                SharedDomainSet::new(set.patterns, set.key).map(|patterns| RoutingSharedDomainSet {
                    bit: set.bit,
                    patterns,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lpm_sets = lpm_sets
            .into_iter()
            .map(|set| RoutingSharedLpmSet {
                index: set.index,
                prefixes: SharedIpPrefixSet::new(set.prefixes),
            })
            .collect::<Vec<_>>();
        Self::from_shared_typed_sets(domain_sets, lpm_sets, matches)
    }

    pub fn from_shared_typed_sets(
        domain_sets: Vec<RoutingSharedDomainSet>,
        lpm_sets: Vec<RoutingSharedLpmSet>,
        matches: Vec<RoutingMatchSet>,
    ) -> Result<Self, RoutingError> {
        let max_domain_bit = domain_sets.iter().map(|set| set.bit + 1).max().unwrap_or(0);
        let mut domain_matcher = DomainMatcher::new(max_domain_bit.max(matches.len()).max(1));
        for set in domain_sets {
            domain_matcher.add_shared_set(set.bit, set.patterns);
        }
        let lpm_sets = lpm_sets
            .into_iter()
            .map(|set| (set.index, set.prefixes))
            .collect::<BTreeMap<_, _>>();
        let matches = matches
            .into_iter()
            .map(MatchSet::from_typed_set)
            .collect::<Vec<_>>();
        Ok(Self {
            lpm_sets,
            domain_matcher,
            matches,
        })
    }

    pub fn from_fixture_value(value: &Value) -> Result<Self, RoutingError> {
        let mut domain_sets = Vec::new();
        for set in value
            .get("domain_sets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let bit = required_u64(set, "bit")? as usize;
            let key = DomainKey::try_from(required_str(set, "key")?)?;
            let patterns = required_array(set, "patterns")?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        RoutingError::InvalidFixture("domain pattern must be string".to_owned())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            domain_sets.push(RoutingDomainSet { bit, key, patterns });
        }

        let matches_json = required_array(value, "matches")?;
        let mut matches = Vec::with_capacity(matches_json.len());
        for item in matches_json {
            matches.push(RoutingMatchSet::from_fixture_value(item)?);
        }

        let mut lpm_sets = Vec::new();
        for set in value
            .get("lpm_sets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = required_u64(set, "index")? as u32;
            let prefixes = required_array(set, "prefixes")?
                .iter()
                .map(|value| {
                    let prefix = value.as_str().ok_or_else(|| {
                        RoutingError::InvalidFixture("prefix must be string".to_owned())
                    })?;
                    IpPrefix::parse(prefix)
                })
                .collect::<Result<Vec<_>, _>>()?;
            lpm_sets.push(RoutingLpmSet { index, prefixes });
        }

        Self::from_typed_sets(domain_sets, lpm_sets, matches)
    }

    pub fn match_query(&self, query: &Query) -> Result<OutboundIndex, RoutingError> {
        self.match_query_detail(query)
            .map(|outcome| outcome.outbound)
    }

    pub fn match_query_detail(&self, query: &Query) -> Result<MatchOutcome, RoutingError> {
        let mut domain_bitmap = Vec::new();
        self.match_query_detail_into(query, &mut domain_bitmap)
    }

    pub fn match_query_detail_into(
        &self,
        query: &Query,
        domain_bitmap: &mut Vec<u32>,
    ) -> Result<MatchOutcome, RoutingError> {
        domain_bitmap.resize(self.domain_bitmap_words(), 0);
        self.match_query_detail_with_bitmap(query, domain_bitmap)
    }

    pub fn match_query_detail_with_bitmap(
        &self,
        query: &Query,
        domain_bitmap: &mut [u32],
    ) -> Result<MatchOutcome, RoutingError> {
        let domain_bitmap = self.prepare_domain_bitmap(query, domain_bitmap)?;
        self.match_query_detail_with_prepared_domain_bitmap(query, domain_bitmap)
    }

    pub fn domain_bitmap_words(&self) -> usize {
        self.domain_matcher.bitmap_words()
    }

    pub fn domain_bitmap_for_domain_into<'a>(
        &'a self,
        domain: &str,
        domain_bitmap: &'a mut Vec<u32>,
    ) -> Result<&'a [u32], RoutingError> {
        domain_bitmap.resize(self.domain_bitmap_words(), 0);
        let words = self
            .domain_matcher
            .fill_domain_bitmap(domain, domain_bitmap)?;
        Ok(&domain_bitmap[..words])
    }

    pub fn domain_bitmap_for_domain(&self, domain: &str) -> Result<Vec<u32>, RoutingError> {
        let mut domain_bitmap = Vec::new();
        self.domain_bitmap_for_domain_into(domain, &mut domain_bitmap)?;
        Ok(domain_bitmap)
    }

    pub(super) fn prepare_domain_bitmap<'a>(
        &'a self,
        query: &Query,
        domain_bitmap: &'a mut [u32],
    ) -> Result<&'a [u32], RoutingError> {
        let domain_bitmap = if query.domain.is_empty() {
            let words = self.domain_bitmap_words();
            if domain_bitmap.len() < words {
                return Err(RoutingError::InvalidFixture(format!(
                    "domain bitmap buffer too short: got {}, want {words}",
                    domain_bitmap.len()
                )));
            }
            let domain_bitmap = &mut domain_bitmap[..words];
            domain_bitmap.fill(0);
            domain_bitmap
        } else {
            let words = self
                .domain_matcher
                .fill_domain_bitmap(&query.domain, domain_bitmap)?;
            &mut domain_bitmap[..words]
        };
        Ok(domain_bitmap)
    }

    pub(super) fn match_query_detail_with_prepared_domain_bitmap(
        &self,
        query: &Query,
        domain_bitmap: &[u32],
    ) -> Result<MatchOutcome, RoutingError> {
        let mut good_subrule = false;
        let mut bad_rule = false;
        let mut must_rules_hit = false;
        for (index, match_set) in self.matches.iter().enumerate() {
            if !bad_rule
                && !good_subrule
                && match_set.matches(index, query, domain_bitmap, &self.lpm_sets)
            {
                good_subrule = true;
            }

            let outbound = match_set.outbound;
            if outbound != OutboundIndex::LOGICAL_OR {
                if good_subrule == match_set.not {
                    bad_rule = true;
                }
                good_subrule = false;
            }

            if outbound.value() & OutboundIndex::LOGICAL_MASK.value()
                != OutboundIndex::LOGICAL_MASK.value()
            {
                if !bad_rule {
                    if outbound == OutboundIndex::MUST_RULES {
                        must_rules_hit = true;
                        continue;
                    }
                    return Ok(MatchOutcome {
                        outbound,
                        mark: match_set.mark,
                        must: match_set.must || must_rules_hit,
                    });
                }
                bad_rule = false;
            }
        }

        Err(RoutingError::InvalidFixture("no match set hit".to_owned()))
    }
}
