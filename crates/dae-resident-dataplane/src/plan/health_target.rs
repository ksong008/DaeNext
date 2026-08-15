use super::*;
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResidentHealthTargetFamily {
    Present(Vec<SocketAddr>),
    Absent,
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentHealthTargetFamilies {
    pub(crate) ipv4: ResidentHealthTargetFamily,
    pub(crate) ipv6: ResidentHealthTargetFamily,
}

#[derive(Clone, Debug)]
struct CachedResidentHealthTargetFamilies {
    value: ResidentHealthTargetFamilies,
    valid_until: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct ResidentHealthTargetResolver {
    host: String,
    port: u16,
    literal_addrs: Vec<SocketAddr>,
    fallback_resolver: SocketAddr,
    resolver_mark: u32,
    refresh_interval: Duration,
    cache: Arc<Mutex<Option<CachedResidentHealthTargetFamilies>>>,
    #[cfg(test)]
    test_result: Option<ResidentHealthTargetFamilies>,
}

impl ResidentHealthTargetResolver {
    pub(crate) fn new(
        host: String,
        port: u16,
        literal_addrs: Vec<SocketAddr>,
        fallback_resolver: SocketAddr,
        resolver_mark: u32,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            host,
            port,
            literal_addrs,
            fallback_resolver,
            resolver_mark,
            refresh_interval,
            cache: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_result: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_result(mut self, result: ResidentHealthTargetFamilies) -> Self {
        self.test_result = Some(result);
        self
    }

    pub(crate) async fn resolve(&self) -> ResidentHealthTargetFamilies {
        #[cfg(test)]
        if let Some(result) = self.test_result.as_ref() {
            return result.clone();
        }
        if !self.literal_addrs.is_empty() {
            return classify_resident_health_target_addrs(self.literal_addrs.clone());
        }
        let now = Instant::now();
        if let Ok(cache) = self.cache.lock()
            && let Some(cached) = cache.as_ref()
            && cached.valid_until > now
        {
            return cached.value.clone();
        }
        let resolved = resolve_host_addrs_with_configured_fallback_dns_ttl(
            &self.host,
            self.port,
            self.fallback_resolver,
            self.resolver_mark,
            "resolve health check target",
            self.refresh_interval,
        )
        .await;
        match resolved {
            Ok(resolved) => {
                let value = classify_resident_health_target_addrs(resolved.addrs);
                if !resolved.valid_for.is_zero()
                    && let Some(valid_until) = Instant::now().checked_add(resolved.valid_for)
                    && let Ok(mut cache) = self.cache.lock()
                {
                    *cache = Some(CachedResidentHealthTargetFamilies {
                        value: value.clone(),
                        valid_until,
                    });
                }
                value
            }
            Err(err) => ResidentHealthTargetFamilies {
                ipv4: ResidentHealthTargetFamily::Unknown(err.clone()),
                ipv6: ResidentHealthTargetFamily::Unknown(err),
            },
        }
    }

    pub(crate) fn identity(&self) -> String {
        let literal_addrs = self
            .literal_addrs
            .iter()
            .map(SocketAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");
        link_hash(&format!(
            "health-target|{}|{}|{}|{}|{}",
            self.host, self.port, literal_addrs, self.fallback_resolver, self.resolver_mark
        ))
    }
}

impl PartialEq for ResidentHealthTargetResolver {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.literal_addrs == other.literal_addrs
            && self.fallback_resolver == other.fallback_resolver
            && self.resolver_mark == other.resolver_mark
            && self.refresh_interval == other.refresh_interval
            && {
                #[cfg(test)]
                {
                    self.test_result == other.test_result
                }
                #[cfg(not(test))]
                {
                    true
                }
            }
    }
}

impl Eq for ResidentHealthTargetResolver {}

fn classify_resident_health_target_addrs(addrs: Vec<SocketAddr>) -> ResidentHealthTargetFamilies {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for addr in addrs {
        let targets = if addr.is_ipv6() { &mut ipv6 } else { &mut ipv4 };
        if !targets.contains(&addr) {
            targets.push(addr);
        }
    }
    ResidentHealthTargetFamilies {
        ipv4: if ipv4.is_empty() {
            ResidentHealthTargetFamily::Absent
        } else {
            ResidentHealthTargetFamily::Present(ipv4)
        },
        ipv6: if ipv6.is_empty() {
            ResidentHealthTargetFamily::Absent
        } else {
            ResidentHealthTargetFamily::Present(ipv6)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_resolution_classifies_each_family_without_inventing_the_other() {
        let dual = classify_resident_health_target_addrs(vec![
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
        ]);
        assert!(
            matches!(dual.ipv4, ResidentHealthTargetFamily::Present(ref addrs) if addrs.len() == 1)
        );
        assert!(
            matches!(dual.ipv6, ResidentHealthTargetFamily::Present(ref addrs) if addrs.len() == 1)
        );

        let only_v4 = classify_resident_health_target_addrs(vec!["192.0.2.2:53".parse().unwrap()]);
        assert_eq!(only_v4.ipv6, ResidentHealthTargetFamily::Absent);
    }

    #[test]
    fn domain_resolution_outcomes_preserve_v4_only_v6_only_and_dual_stack_shapes() {
        let fallback = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        for (addrs, expect_v4, expect_v6) in [
            (
                vec![SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    80,
                )],
                true,
                false,
            ),
            (
                vec![SocketAddr::new(
                    IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    80,
                )],
                false,
                true,
            ),
            (
                vec![
                    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 80),
                    SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 80),
                ],
                true,
                true,
            ),
        ] {
            let expected = classify_resident_health_target_addrs(addrs);
            let resolver = ResidentHealthTargetResolver::new(
                "health-target.invalid".to_owned(),
                80,
                Vec::new(),
                fallback,
                0,
                Duration::from_secs(30),
            )
            .with_test_result(expected);
            let resolved = runtime.block_on(resolver.resolve());
            assert_eq!(
                matches!(resolved.ipv4, ResidentHealthTargetFamily::Present(_)),
                expect_v4
            );
            assert_eq!(
                matches!(resolved.ipv6, ResidentHealthTargetFamily::Present(_)),
                expect_v6
            );
        }
    }

    #[test]
    fn resolver_error_remains_distinct_from_absent_family() {
        let unknown = ResidentHealthTargetFamilies {
            ipv4: ResidentHealthTargetFamily::Unknown("temporary resolver failure".to_owned()),
            ipv6: ResidentHealthTargetFamily::Unknown("temporary resolver failure".to_owned()),
        };
        assert!(matches!(
            unknown.ipv4,
            ResidentHealthTargetFamily::Unknown(_)
        ));
    }
}
