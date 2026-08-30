#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirectOption {
    pub resolver_dialer: bool,
    pub resolver_fullcone_dialer: bool,
    pub global_symmetric_direct: bool,
    pub global_fullcone_direct: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverChoice {
    pub selected: String,
    pub property_name: String,
    pub fallback_constructed: bool,
}

pub fn select_direct_resolver(option: &DirectOption, fullcone: bool) -> ResolverChoice {
    let selected = if fullcone {
        if option.resolver_fullcone_dialer {
            "ResolverFullconeDialer"
        } else if option.global_fullcone_direct {
            "GlobalFullconeDirect"
        } else {
            "FallbackFullconeResolver"
        }
    } else if option.resolver_dialer {
        "ResolverDialer"
    } else if option.global_symmetric_direct {
        "GlobalSymmetricDirect"
    } else {
        "FallbackSymmetricResolver"
    };

    ResolverChoice {
        selected: selected.to_owned(),
        property_name: "direct".to_owned(),
        fallback_constructed: selected.starts_with("Fallback"),
    }
}
