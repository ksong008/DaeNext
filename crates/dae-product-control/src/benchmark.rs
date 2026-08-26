use super::*;

pub struct ProductControlBenchmarkFixture {
    handoff_runtime: Arc<ProductControlRuntime>,
    saturated_runtime: Arc<ProductControlRuntime>,
}

pub fn product_control_benchmark_fixture() -> Result<ProductControlBenchmarkFixture, String> {
    let handoff_runtime =
        ProductControlRuntime::start(ProductControlRuntimeConfig::for_benchmark())
            .map_err(|error| format!("start control handoff benchmark runtime: {error}"))?;
    let mut saturated_config = ProductControlRuntimeConfig::for_benchmark();
    saturated_config.proxy_http_limit = 0;
    let saturated_runtime = ProductControlRuntime::start(saturated_config)
        .map_err(|error| format!("start saturated control benchmark runtime: {error}"))?;
    Ok(ProductControlBenchmarkFixture {
        handoff_runtime,
        saturated_runtime,
    })
}

impl ProductControlBenchmarkFixture {
    pub fn handoff_once(&self) -> u64 {
        self.handoff_runtime
            .execute(
                ProductControlTaskKind::DirectHttp,
                Duration::from_secs(1),
                |_| async { 1_u64 },
            )
            .expect("control benchmark handoff must complete")
    }

    pub fn rejected_saturated_submission_once(&self) -> u64 {
        match self.saturated_runtime.execute(
            ProductControlTaskKind::ProxyHttp,
            Duration::from_secs(1),
            |_| async { 0_u64 },
        ) {
            Err(ProductControlExecutionError::Busy) => 1,
            result => panic!("saturated control benchmark expected busy, got {result:?}"),
        }
    }
}

impl Drop for ProductControlBenchmarkFixture {
    fn drop(&mut self) {
        let _ = self.handoff_runtime.shutdown();
        let _ = self.saturated_runtime.shutdown();
    }
}
