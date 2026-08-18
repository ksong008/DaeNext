use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OutboundIndex(pub u8);

impl OutboundIndex {
    pub const DIRECT: Self = Self(0);
    pub const BLOCK: Self = Self(1);
    pub const USER_DEFINED_MIN: Self = Self(2);
    pub const MUST_RULES: Self = Self(0xFC);
    pub const CONTROL_PLANE_ROUTING: Self = Self(0xFD);
    pub const LOGICAL_OR: Self = Self(0xFE);
    pub const LOGICAL_AND: Self = Self(0xFF);
    pub const LOGICAL_MASK: Self = Self(0xFE);
    pub const USER_DEFINED_MAX: Self = Self(Self::MUST_RULES.0 - 1);

    pub const fn value(self) -> u8 {
        self.0
    }

    pub fn is_reserved(self) -> bool {
        self.0 <= Self::BLOCK.0 || self.0 >= Self::MUST_RULES.0
    }
}

impl OutboundIndex {
    pub const fn try_from_user_offset(offset: usize) -> Result<Self, &'static str> {
        let value = Self::USER_DEFINED_MIN.0 as usize + offset;
        if value > Self::USER_DEFINED_MAX.0 as usize {
            return Err("user outbound index exceeds reserved control range");
        }
        Ok(Self(value as u8))
    }
}

impl fmt::Display for OutboundIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MUST_RULES => f.write_str("must_rules"),
            Self::DIRECT => f.write_str("direct"),
            Self::BLOCK => f.write_str("block"),
            Self::CONTROL_PLANE_ROUTING => f.write_str("<Control Plane Routing>"),
            Self::LOGICAL_OR => f.write_str("<OR>"),
            Self::LOGICAL_AND => f.write_str("<AND>"),
            _ => write!(f, "<index: {}>", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn outbound_indices_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/reserved_indices.json").unwrap();
        let outbound = &fixture["outbound"];

        assert_index(OutboundIndex::DIRECT, &outbound["direct"]);
        assert_index(OutboundIndex::BLOCK, &outbound["block"]);
        assert_index(OutboundIndex::MUST_RULES, &outbound["must_rules"]);
        assert_index(
            OutboundIndex::CONTROL_PLANE_ROUTING,
            &outbound["control_plane_routing"],
        );
        assert_index(OutboundIndex::LOGICAL_OR, &outbound["logical_or"]);
        assert_index(OutboundIndex::LOGICAL_AND, &outbound["logical_and"]);
        assert_eq!(
            OutboundIndex::USER_DEFINED_MIN.value(),
            outbound["user_defined_min"].as_u64().unwrap() as u8
        );
        assert_eq!(
            OutboundIndex::USER_DEFINED_MAX.value(),
            outbound["user_defined_max"].as_u64().unwrap() as u8
        );
        assert_eq!(
            OutboundIndex::LOGICAL_MASK.value(),
            outbound["logical_mask"]["value"].as_u64().unwrap() as u8
        );

        let user_defined = OutboundIndex(2);
        assert_eq!(
            user_defined.to_string(),
            outbound["example_user_defined"]["string"].as_str().unwrap()
        );
        assert_eq!(
            user_defined.is_reserved(),
            outbound["example_user_defined"]["reserved"]
                .as_bool()
                .unwrap()
        );
    }

    fn assert_index(index: OutboundIndex, fixture: &Value) {
        assert_eq!(index.value(), fixture["value"].as_u64().unwrap() as u8);
        assert_eq!(index.to_string(), fixture["string"].as_str().unwrap());
        assert_eq!(index.is_reserved(), fixture["reserved"].as_bool().unwrap());
    }
}

#[cfg(test)]
mod outbound_index_tests {
    use super::OutboundIndex;

    #[test]
    fn user_offset_within_range_succeeds() {
        assert_eq!(
            OutboundIndex::try_from_user_offset(0).unwrap(),
            OutboundIndex::USER_DEFINED_MIN
        );
        assert_eq!(
            OutboundIndex::try_from_user_offset(100).unwrap().value(),
            102
        );
    }

    #[test]
    fn user_offset_beyond_range_fails_without_wraparound() {
        let max_offset = OutboundIndex::USER_DEFINED_MAX.value() as usize
            - OutboundIndex::USER_DEFINED_MIN.value() as usize;
        assert!(OutboundIndex::try_from_user_offset(max_offset).is_ok());
        assert!(OutboundIndex::try_from_user_offset(max_offset + 1).is_err());
    }

    #[test]
    fn is_reserved_uses_numeric_criteria() {
        assert!(OutboundIndex::DIRECT.is_reserved());
        assert!(OutboundIndex::BLOCK.is_reserved());
        assert!(OutboundIndex::MUST_RULES.is_reserved());
        assert!(OutboundIndex::CONTROL_PLANE_ROUTING.is_reserved());
        assert!(OutboundIndex::LOGICAL_OR.is_reserved());
        assert!(!OutboundIndex::USER_DEFINED_MIN.is_reserved());
        assert!(!OutboundIndex::USER_DEFINED_MAX.is_reserved());
    }
}
