use super::*;
use crate::{ResidentDnsFlightPermit, ResidentDnsFlightWaitError};

pub(super) enum Acquired<'a> {
    Leader {
        permit: ResidentDnsFlightPermit<'a>,
        recovered: bool,
    },
    Response {
        response: Vec<u8>,
        recovered: bool,
    },
}

pub(super) async fn acquire<'a>(
    plan: &'a ResidentDnsPlan,
    key: &ResidentDnsResponseCacheKey,
    request: &DnsPacketView<'_>,
    context: ProxyDnsRequestContext,
) -> Result<Acquired<'a>, String> {
    let mut recovered = false;
    loop {
        context
            .ensure(ProxyDnsRequestStage::Queued)
            .map_err(|error| error.to_string())?;
        if recovered {
            let mut response = Vec::new();
            if plan
                .cache
                .lookup_response_into(key, request, false, &mut response)?
            {
                return Ok(Acquired::Response {
                    response,
                    recovered,
                });
            }
        }
        let permit = plan.cache.begin_flight(key.clone())?;
        if permit.is_leader() {
            return Ok(Acquired::Leader { permit, recovered });
        }
        match permit.wait_recoverable(context, request.id()).await {
            Ok(mut response) => {
                dae_dns::restore_dns_response_for_request(request, &mut response)
                    .map_err(|error| format!("restore shared DNS response: {error}"))?;
                return Ok(Acquired::Response {
                    response,
                    recovered,
                });
            }
            Err(ResidentDnsFlightWaitError::LeaderTerminated) if !recovered => {
                drop(permit);
                recovered = true;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

#[cfg(all(test, feature = "dns-runtime-tests"))]
#[path = "flight_tests.rs"]
mod tests;
