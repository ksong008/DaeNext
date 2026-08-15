use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRequestOutboundIndex(pub u8);

impl DnsRequestOutboundIndex {
    pub const REJECT: Self = Self(0xFC);
    pub const ASIS: Self = Self(0xFD);
    pub const LOGICAL_OR: Self = Self(0xFE);
    pub const LOGICAL_AND: Self = Self(0xFF);
    pub const LOGICAL_MASK: Self = Self(0xFE);
    pub const USER_DEFINED_MIN: Self = Self(0);
    pub const USER_DEFINED_MAX: Self = Self(Self::REJECT.0 - 1);

    pub const fn value(self) -> u8 {
        self.0
    }

    pub const fn is_reserved(self) -> bool {
        self.0 > Self::USER_DEFINED_MAX.0
    }
}

impl TryFrom<usize> for DnsRequestOutboundIndex {
    type Error = DnsUserDefinedOutboundIndexError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value <= Self::USER_DEFINED_MAX.0 as usize {
            Ok(Self(value as u8))
        } else {
            Err(DnsUserDefinedOutboundIndexError { value })
        }
    }
}

impl fmt::Display for DnsRequestOutboundIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::REJECT => f.write_str("reject"),
            Self::ASIS => f.write_str("asis"),
            Self::LOGICAL_OR => f.write_str("<OR>"),
            Self::LOGICAL_AND => f.write_str("<AND>"),
            _ => write!(f, "<index: {}>", self.0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsResponseOutboundIndex(pub u8);

impl DnsResponseOutboundIndex {
    pub const ACCEPT: Self = Self(0xFC);
    pub const REJECT: Self = Self(0xFD);
    pub const LOGICAL_OR: Self = Self(0xFE);
    pub const LOGICAL_AND: Self = Self(0xFF);
    pub const LOGICAL_MASK: Self = Self(0xFE);
    pub const USER_DEFINED_MIN: Self = Self(0);
    pub const USER_DEFINED_MAX: Self = Self(Self::ACCEPT.0 - 1);

    pub const fn value(self) -> u8 {
        self.0
    }

    pub const fn is_reserved(self) -> bool {
        self.0 > Self::USER_DEFINED_MAX.0
    }
}

impl TryFrom<usize> for DnsResponseOutboundIndex {
    type Error = DnsUserDefinedOutboundIndexError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value <= Self::USER_DEFINED_MAX.0 as usize {
            Ok(Self(value as u8))
        } else {
            Err(DnsUserDefinedOutboundIndexError { value })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsUserDefinedOutboundIndexError {
    value: usize,
}

impl fmt::Display for DnsUserDefinedOutboundIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS user-defined outbound index {} exceeds {}",
            self.value,
            DnsRequestOutboundIndex::USER_DEFINED_MAX.value()
        )
    }
}

impl std::error::Error for DnsUserDefinedOutboundIndexError {}

impl fmt::Display for DnsResponseOutboundIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ACCEPT => f.write_str("accept"),
            Self::REJECT => f.write_str("reject"),
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
    fn dns_request_indices_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/reserved_indices.json").unwrap();
        let request = &fixture["dns_request"];

        assert_request_index(DnsRequestOutboundIndex::REJECT, &request["reject"]);
        assert_request_index(DnsRequestOutboundIndex::ASIS, &request["asis"]);
        assert_request_index(DnsRequestOutboundIndex::LOGICAL_OR, &request["logical_or"]);
        assert_request_index(
            DnsRequestOutboundIndex::LOGICAL_AND,
            &request["logical_and"],
        );
        assert_eq!(
            DnsRequestOutboundIndex::LOGICAL_MASK.value(),
            request["logical_mask"]["value"].as_u64().unwrap() as u8
        );
        assert_eq!(
            DnsRequestOutboundIndex::USER_DEFINED_MAX.value(),
            request["user_defined_max"].as_u64().unwrap() as u8
        );
        assert_eq!(
            DnsRequestOutboundIndex(2).to_string(),
            request["example_user_defined"]["string"].as_str().unwrap()
        );
        assert!(!DnsRequestOutboundIndex(2).is_reserved());
    }

    #[test]
    fn dns_response_indices_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/reserved_indices.json").unwrap();
        let response = &fixture["dns_response"];

        assert_response_index(DnsResponseOutboundIndex::ACCEPT, &response["accept"]);
        assert_response_index(DnsResponseOutboundIndex::REJECT, &response["reject"]);
        assert_response_index(
            DnsResponseOutboundIndex::LOGICAL_OR,
            &response["logical_or"],
        );
        assert_response_index(
            DnsResponseOutboundIndex::LOGICAL_AND,
            &response["logical_and"],
        );
        assert_eq!(
            DnsResponseOutboundIndex::LOGICAL_MASK.value(),
            response["logical_mask"]["value"].as_u64().unwrap() as u8
        );
        assert_eq!(
            DnsResponseOutboundIndex::USER_DEFINED_MAX.value(),
            response["user_defined_max"].as_u64().unwrap() as u8
        );
        let user_defined = DnsResponseOutboundIndex(2);
        assert_eq!(
            user_defined.to_string(),
            response["example_user_defined"]["string"].as_str().unwrap()
        );
        assert_eq!(
            user_defined.is_reserved(),
            response["example_user_defined"]["reserved"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn dns_user_defined_indices_enforce_the_byte_range() {
        assert_eq!(
            DnsRequestOutboundIndex::try_from(0_usize).unwrap(),
            DnsRequestOutboundIndex::USER_DEFINED_MIN
        );
        assert_eq!(
            DnsRequestOutboundIndex::try_from(251_usize).unwrap(),
            DnsRequestOutboundIndex::USER_DEFINED_MAX
        );
        assert!(DnsRequestOutboundIndex::try_from(252_usize).is_err());
        assert_eq!(
            DnsResponseOutboundIndex::try_from(251_usize).unwrap(),
            DnsResponseOutboundIndex::USER_DEFINED_MAX
        );
        assert!(DnsResponseOutboundIndex::try_from(252_usize).is_err());
        assert!(DnsResponseOutboundIndex::try_from(usize::MAX).is_err());
    }

    fn assert_request_index(index: DnsRequestOutboundIndex, fixture: &Value) {
        assert_eq!(index.value(), fixture["value"].as_u64().unwrap() as u8);
        assert_eq!(index.to_string(), fixture["string"].as_str().unwrap());
    }

    fn assert_response_index(index: DnsResponseOutboundIndex, fixture: &Value) {
        assert_eq!(index.value(), fixture["value"].as_u64().unwrap() as u8);
        assert_eq!(index.to_string(), fixture["string"].as_str().unwrap());
        assert_eq!(index.is_reserved(), fixture["reserved"].as_bool().unwrap());
    }
}
