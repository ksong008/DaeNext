use super::client_io::{
    begin_xhttp_packet_up_request, replace_xhttp_packet_up_client, reserve_xhttp_packet_up_post,
};
use super::*;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};

pub struct XhttpPacketUpPipeline {
    completions: FuturesUnordered<XhttpPacketUpCompletion>,
    max_in_flight: usize,
    max_post_bytes: usize,
    min_post_interval_ms: (i32, i32),
    last_post_started: Option<time::Instant>,
}

impl XhttpPacketUpPipeline {
    pub fn for_upload(upload: &XhttpUploadClient) -> Self {
        let settings = match upload {
            XhttpUploadClient::H1 { endpoint, .. }
            | XhttpUploadClient::H2 { endpoint, .. }
            | XhttpUploadClient::H3 { endpoint, .. } => &endpoint.settings,
        };
        let max_in_flight = usize::try_from(settings.normalized_sc_max_buffered_posts())
            .unwrap_or(usize::MAX)
            .max(1);
        let max_post_bytes = usize::try_from(ResidentXhttpSettingsPlan::sample_range(
            settings.normalized_sc_max_each_post_bytes(),
        ))
        .unwrap_or(usize::MAX)
        .max(1);
        Self {
            completions: FuturesUnordered::new(),
            max_in_flight,
            max_post_bytes,
            min_post_interval_ms: settings.normalized_sc_min_posts_interval_ms(),
            last_post_started: None,
        }
    }

    pub async fn send(
        &mut self,
        upload: &mut XhttpUploadClient,
        session_id: &str,
        seq: &mut u64,
        mut payload: Bytes,
    ) -> Result<(), String> {
        if payload.is_empty() {
            return self.send_one(upload, session_id, seq, Bytes::new()).await;
        }
        while !payload.is_empty() {
            let chunk = self.take_post_chunk(&mut payload);
            self.send_one(upload, session_id, seq, chunk).await?;
        }
        Ok(())
    }

    fn take_post_chunk(&self, payload: &mut Bytes) -> Bytes {
        let take = payload.len().min(self.max_post_bytes);
        payload.split_to(take)
    }

    async fn send_one(
        &mut self,
        upload: &mut XhttpUploadClient,
        session_id: &str,
        seq: &mut u64,
        payload: Bytes,
    ) -> Result<(), String> {
        self.poll_ready()?;
        if reserve_xhttp_packet_up_post(upload) {
            self.finish().await?;
            replace_xhttp_packet_up_client(upload).await?;
        }
        self.wait_for_capacity().await?;
        self.wait_post_interval().await;
        let completion = begin_xhttp_packet_up_request(upload, session_id, *seq, payload).await?;
        *seq = seq.saturating_add(1);
        self.last_post_started = Some(time::Instant::now());
        self.completions.push(completion);
        self.poll_ready()
    }

    async fn wait_for_capacity(&mut self) -> Result<(), String> {
        while self.completions.len() >= self.max_in_flight {
            self.wait_one().await?;
        }
        Ok(())
    }

    async fn wait_post_interval(&mut self) {
        let Some(last_started) = self.last_post_started else {
            return;
        };
        let interval_ms = ResidentXhttpSettingsPlan::sample_range(self.min_post_interval_ms).max(0);
        if interval_ms == 0 {
            return;
        }
        let deadline = last_started + Duration::from_millis(interval_ms as u64);
        if deadline > time::Instant::now() {
            time::sleep_until(deadline).await;
        }
    }

    pub fn poll_ready(&mut self) -> Result<(), String> {
        loop {
            let Some(completion) = self.completions.next().now_or_never() else {
                return Ok(());
            };
            let Some(result) = completion else {
                return Ok(());
            };
            result?;
        }
    }

    pub async fn wait_one(&mut self) -> Result<bool, String> {
        match self.completions.next().await {
            Some(result) => {
                result?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub async fn finish(&mut self) -> Result<(), String> {
        while self.wait_one().await? {}
        Ok(())
    }

    pub fn has_in_flight(&self) -> bool {
        !self.completions.is_empty()
    }

    pub fn max_post_bytes(&self) -> usize {
        self.max_post_bytes
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(max_in_flight: usize) -> Self {
        Self {
            completions: FuturesUnordered::new(),
            max_in_flight,
            max_post_bytes: usize::MAX,
            min_post_interval_ms: (0, 0),
            last_post_started: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn push_test_completion(&self, completion: XhttpPacketUpCompletion) {
        self.completions.push(completion);
    }
}

#[cfg(test)]
#[path = "packet_up_pipeline/tests.rs"]
mod tests;
