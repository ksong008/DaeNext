use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRequestOutboundIndex(pub i16);

impl DnsRequestOutboundIndex {
    pub const REJECT: Self = Self(0xFC);
    pub const ASIS: Self = Self(0xFD);
    pub const LOGICAL_OR: Self = Self(0xFE);
    pub const LOGICAL_AND: Self = Self(0xFF);
    pub const LOGICAL_MASK: Self = Self(0xFE);
    pub const USER_DEFINED_MAX: Self = Self(Self::REJECT.0 - 1);

    pub const fn value(self) -> i16 {
        self.0
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
    pub const USER_DEFINED_MAX: Self = Self(Self::ACCEPT.0 - 1);

    pub const fn value(self) -> u8 {
        self.0
    }

    pub fn is_reserved(self) -> bool {
        !self.to_string().starts_with("<index: ")
    }
}

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
            request["logical_mask"]["value"].as_i64().unwrap() as i16
        );
        assert_eq!(
            DnsRequestOutboundIndex::USER_DEFINED_MAX.value(),
            request["user_defined_max"].as_i64().unwrap() as i16
        );
        assert_eq!(
            DnsRequestOutboundIndex(2).to_string(),
            request["example_user_defined"]["string"].as_str().unwrap()
        );
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

    fn assert_request_index(index: DnsRequestOutboundIndex, fixture: &Value) {
        assert_eq!(index.value(), fixture["value"].as_i64().unwrap() as i16);
        assert_eq!(index.to_string(), fixture["string"].as_str().unwrap());
    }

    fn assert_response_index(index: DnsResponseOutboundIndex, fixture: &Value) {
        assert_eq!(index.value(), fixture["value"].as_u64().unwrap() as u8);
        assert_eq!(index.to_string(), fixture["string"].as_str().unwrap());
        assert_eq!(index.is_reserved(), fixture["reserved"].as_bool().unwrap());
    }
}
