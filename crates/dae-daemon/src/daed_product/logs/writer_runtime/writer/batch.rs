use super::*;

impl ProductLogWriter {
    pub(in super::super) fn append_batch(
        &mut self,
        requests: Vec<ProductLogAppendRequest>,
    ) -> Vec<io::Result<ProductLogAppendOutcome>> {
        if requests.len() == 1 {
            return vec![self.append(requests.into_iter().next().unwrap())];
        }
        let count = requests.len();
        let mut results = Vec::with_capacity(count);
        let mut positions = Vec::new();
        let mut wire = Vec::new();
        let store = Arc::clone(&self.store);
        let result = (|| -> io::Result<()> {
            let _guard = store.lock()?;
            store.publish_count(None, 0, 0)?;
            self.ensure_current_file_locked()?;
            for request in requests {
                if request.respect_runtime_log_level
                    && !log_level_enabled(&request.level, &self.policy.runtime_level)
                {
                    results.push(Some(Ok(ProductLogAppendOutcome::Filtered)));
                    continue;
                }
                if self.size_bytes.saturating_add(wire.len() as u64)
                    >= PRODUCT_LOG_SEGMENT_MAX_BYTES
                    || self.segments.back().is_some_and(|segment| {
                        segment.visible_entries + positions.len() >= PRODUCT_LOG_SEGMENT_MAX_ENTRIES
                    })
                {
                    self.flush_batch(&mut wire, &mut positions, &mut results)?;
                    self.rotate_active_locked()?;
                }
                let id = self
                    .last_id
                    .saturating_add(positions.len() as u64)
                    .saturating_add(1);
                match encode_log_entry_line(id, &request.level, &request.message, request.fields) {
                    Ok(line) => {
                        positions.push(results.len());
                        wire.extend_from_slice(&line);
                        results.push(None);
                    }
                    Err(error) => results.push(Some(Err(error))),
                }
            }
            self.flush_batch(&mut wire, &mut positions, &mut results)
        })();
        if let Err(error) = result {
            let kind = error.kind();
            let message = error.to_string();
            results.resize_with(count, || None);
            for result in &mut results {
                if result.is_none() {
                    *result = Some(Err(io::Error::new(kind, message.clone())));
                }
            }
        }
        results
            .into_iter()
            .map(|result| result.unwrap_or_else(|| Err(io::Error::other("incomplete log batch"))))
            .collect()
    }

    fn flush_batch(
        &mut self,
        wire: &mut Vec<u8>,
        positions: &mut Vec<usize>,
        results: &mut [Option<io::Result<ProductLogAppendOutcome>>],
    ) -> io::Result<()> {
        if positions.is_empty() {
            return Ok(());
        }
        let pruned = self.commit_append(wire, positions.len())?;
        let last = positions.last().copied();
        for index in positions.drain(..) {
            results[index] = Some(Ok(ProductLogAppendOutcome::Appended {
                pruned: pruned && Some(index) == last,
            }));
        }
        wire.clear();
        Ok(())
    }
    // Both single writes and batches share rollback and publication semantics.
    pub(super) fn commit_append(&mut self, wire: &[u8], count: usize) -> io::Result<bool> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("product log file is unavailable"))?;
        if let Err(error) = write_product_log_line(file, wire) {
            #[cfg(test)]
            let truncate = !LOG_APPEND_TRUNCATE_FAILURE.replace(false);
            #[cfg(not(test))]
            let truncate = true;
            if truncate {
                let _ = file.set_len(self.size_bytes);
            }
            self.file.take();
            return Err(error);
        }
        let first = self.last_id.saturating_add(1);
        let was_empty = self.entry_count == 0;
        self.last_id = self.last_id.saturating_add(count as u64);
        self.size_bytes = self.size_bytes.saturating_add(wire.len() as u64);
        self.entry_count = self.entry_count.saturating_add(count);
        self.visible_bytes = self.visible_bytes.saturating_add(wire.len() as u64);
        if let Some(active) = self.segments.back_mut() {
            if active.visible_entries == 0 {
                active.first_id = first;
                if was_empty {
                    self.first_visible_id = first;
                }
            }
            active.visible_entries += count;
            active.size_bytes = self.size_bytes;
            active.visible_bytes = active.visible_bytes.saturating_add(wire.len() as u64);
            active.last_id = self.last_id;
        }
        set_log_id_cache(&self.path, self.last_id)?;
        self.prune_if_over_limit_locked()
    }
}
