use super::*;

#[cfg(test)]
mod tests;

pub(in crate::daed_product) type ProductGeodataUpdateRuntime =
    dae_product_geodata::ProductGeodataUpdateRuntime<
        ProductGeodataUpdateContext,
        DaemonGeodataUpdateJob,
    >;

pub(crate) struct DaemonGeodataUpdateJob {
    stream: TcpStream,
    request: HttpRequest,
    kind: GeodataKind,
    http_metrics: Arc<ProductHttpMetrics>,
}

impl dae_product_geodata::ProductGeodataUpdateJob for DaemonGeodataUpdateJob {
    fn complete(self, result: io::Result<Value>) {
        let Self {
            mut stream,
            request,
            kind,
            http_metrics,
        } = self;
        let response = super::super::geodata_update_http_response(kind, result);
        let _ = write_http_response_for_request(&mut stream, &request, &response, false);
        http_metrics.closed();
    }
}

struct DaemonGeodataUpdateWorkerHooks;

impl dae_product_geodata::ProductGeodataUpdateWorkerHooks for DaemonGeodataUpdateWorkerHooks {
    fn worker_started(&self) -> Box<dyn dae_product_geodata::ProductGeodataUpdateWorker> {
        Box::new(DaemonGeodataUpdateWorker {
            inner: allocator_register_reclaim_worker(AllocatorWorkerKind::ControlAux),
        })
    }

    fn job_started(&self) -> Option<Box<dyn Send>> {
        Some(Box::new(allocator_reclaim_busy(
            AllocatorReclaimBusyKind::Geodata,
        )))
    }
}

struct DaemonGeodataUpdateWorker {
    inner: AllocatorReclaimWorker,
}

impl dae_product_geodata::ProductGeodataUpdateWorker for DaemonGeodataUpdateWorker {
    fn poll(&mut self) {
        self.inner.poll();
    }
}

pub(in crate::daed_product) fn start_for_app(
    http_config: ProductHttpWorkerConfig,
    app: &AppState,
) -> io::Result<Arc<ProductGeodataUpdateRuntime>> {
    let context = ProductGeodataUpdateContext::from_app(app);
    let config =
        dae_product_geodata::ProductGeodataUpdateRuntimeConfig::from_http_config(http_config);
    dae_product_geodata::ProductGeodataUpdateRuntime::start(
        config,
        context,
        Arc::clone(&app.geodata_updates),
        Arc::new(DaemonGeodataUpdateWorkerHooks),
    )
}

#[cfg(test)]
fn start_with_config(
    config: dae_product_geodata::ProductGeodataUpdateRuntimeConfig,
    context: ProductGeodataUpdateContext,
) -> io::Result<Arc<ProductGeodataUpdateRuntime>> {
    let updates = Arc::clone(&context.updates);
    dae_product_geodata::ProductGeodataUpdateRuntime::start(
        config,
        context,
        updates,
        Arc::new(DaemonGeodataUpdateWorkerHooks),
    )
}

pub(in crate::daed_product) fn submit_update_job(
    runtime: &ProductGeodataUpdateRuntime,
    kind: GeodataKind,
    stream: TcpStream,
    request: HttpRequest,
    http_metrics: Arc<ProductHttpMetrics>,
) -> Result<(), Box<dae_product_geodata::ProductGeodataUpdateSubmissionError<DaemonGeodataUpdateJob>>>
{
    runtime.submit(
        kind,
        DaemonGeodataUpdateJob {
            stream,
            request,
            kind,
            http_metrics,
        },
    )
}

pub(in crate::daed_product) fn geodata_submission_rejection(
    rejection: dae_product_geodata::ProductGeodataUpdateSubmissionError<DaemonGeodataUpdateJob>,
) -> (TcpStream, HttpRequest, HttpResponse) {
    let DaemonGeodataUpdateJob {
        stream,
        request,
        kind,
        http_metrics,
    } = rejection.job;
    http_metrics.closed();
    let (status, message) = match rejection.reason {
        dae_product_geodata::ProductGeodataUpdateSubmissionReason::Unavailable => {
            (503, "geodata update runtime is unavailable")
        }
        dae_product_geodata::ProductGeodataUpdateSubmissionReason::SameKind => {
            (409, "geodata update is already in progress")
        }
        dae_product_geodata::ProductGeodataUpdateSubmissionReason::Capacity => {
            (503, "geodata update queue is full; retry later")
        }
    };
    (
        stream,
        request,
        if status == 409 {
            super::super::geodata_update_http_response(
                kind,
                Err(io::Error::new(io::ErrorKind::WouldBlock, message)),
            )
        } else {
            HttpResponse::json(status, json!({"error": message}))
        },
    )
}
