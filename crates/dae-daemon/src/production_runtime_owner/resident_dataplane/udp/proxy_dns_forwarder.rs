use super::*;

const RESIDENT_PROXY_DNS_UDP_FORWARDER_MAX_SHARDS: usize = 4;

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxyDnsUdpForwarder {
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    next_shard: std::sync::atomic::AtomicUsize,
    shards: Vec<ResidentProxyDnsUdpForwarderShard>,
}

struct ResidentProxyDnsUdpForwarderShard {
    executor: tokio::sync::Mutex<Option<UdpSessionExecutor>>,
}

impl ResidentProxyDnsUdpForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        proxy: Arc<ResidentProxyPlan>,
        original_dst: SocketAddr,
    ) -> Self {
        let shard_count = resident_proxy_dns_udp_forwarder_shard_count();
        Self {
            proxy,
            original_dst,
            next_shard: std::sync::atomic::AtomicUsize::new(0),
            shards: (0..shard_count)
                .map(|_| ResidentProxyDnsUdpForwarderShard {
                    executor: tokio::sync::Mutex::new(None),
                })
                .collect(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn exchange(
        &self,
        payload: &[u8],
        attempts: usize,
    ) -> Result<Vec<u8>, String> {
        let attempts = attempts.max(1);
        let mut failures = Vec::new();
        for _ in 0..attempts {
            let shard = self.select_shard();
            match shard
                .exchange(&self.proxy, self.original_dst, payload)
                .await
            {
                Ok(response) => return Ok(response),
                Err(err) => failures.push(err),
            }
        }
        Err(format!(
            "proxied DNS UDP response failed after {attempts} attempts: {}",
            failures.join("; ")
        ))
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn shard_count(&self) -> usize {
        self.shards.len()
    }

    fn select_shard(&self) -> &ResidentProxyDnsUdpForwarderShard {
        let shard_count = self.shards.len().max(1);
        let index = self
            .next_shard
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % shard_count;
        &self.shards[index]
    }
}

impl ResidentProxyDnsUdpForwarderShard {
    async fn exchange(
        &self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut executor = self.executor.lock().await;
        if executor.is_none() {
            *executor = Some(UdpSessionExecutor::new_proxy_packet(proxy));
        }
        let Some(executor_ref) = executor.as_mut() else {
            return Err("proxied DNS UDP executor was not initialized".to_owned());
        };
        let result = execute_forced_dns_proxy_payload(executor_ref, proxy, original_dst, payload)
            .await
            .map(|(_, response)| response.payload);
        if result.is_err() {
            executor_ref.shutdown().await;
            *executor = None;
        }
        result
    }
}

fn resident_proxy_dns_udp_forwarder_shard_count() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(parallelism)
}

#[cfg(test)]
pub(in crate::production_runtime_owner::resident_dataplane) fn resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(
    parallelism: usize,
) -> usize {
    proxy_dns_udp_forwarder_shard_count_for_parallelism(parallelism)
}

#[cfg(not(test))]
fn resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(parallelism: usize) -> usize {
    proxy_dns_udp_forwarder_shard_count_for_parallelism(parallelism)
}

fn proxy_dns_udp_forwarder_shard_count_for_parallelism(parallelism: usize) -> usize {
    if parallelism <= 1 {
        1
    } else {
        parallelism.min(RESIDENT_PROXY_DNS_UDP_FORWARDER_MAX_SHARDS)
    }
}

async fn execute_forced_dns_proxy_payload(
    executor: &mut UdpSessionExecutor,
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<(&'static str, UdpExchangeResult), String> {
    let (event, response) = executor
        .execute_proxy_packet(proxy, original_dst, payload)
        .await?;
    if response.reply_forwarded {
        return Ok((event, response.into_independent_datagram()));
    }
    executor
        .wait_response_with_timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            "receive proxied DNS UDP response",
        )
        .await
        .map(|(event, response)| (event, response.into_independent_datagram()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_dns_udp_forwarder_shard_count_follows_cpu_parallelism() {
        assert_eq!(
            resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(0),
            1
        );
        assert_eq!(
            resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(1),
            1
        );
        assert_eq!(
            resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(2),
            2
        );
        assert_eq!(
            resident_proxy_dns_udp_forwarder_shard_count_for_parallelism(
                RESIDENT_PROXY_DNS_UDP_FORWARDER_MAX_SHARDS + 1
            ),
            RESIDENT_PROXY_DNS_UDP_FORWARDER_MAX_SHARDS
        );
    }
}
