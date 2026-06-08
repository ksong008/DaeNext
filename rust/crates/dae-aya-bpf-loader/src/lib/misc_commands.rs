fn run_load_pin_command(args: &[String]) -> LoaderOutput {
    match parse_load_pin_options(args) {
        Ok(options) => run_load_pin(options),
        Err(err) => LoaderOutput::usage(err),
    }
}

fn run_map_stats_count(requests: Vec<MapStatsCountRequest>) -> LoaderOutput {
    if requests.is_empty() {
        return LoaderOutput::usage("map-stats count requires at least one --map name:id");
    }
    let mut counts = Vec::with_capacity(requests.len());
    for request in requests {
        match dae_ebpf_support::count_map_entries_by_id(request.id) {
            Ok(entries) => counts.push(json!({
                "name": request.name,
                "id": request.id,
                "entries": entries,
            })),
            Err(err) => {
                return LoaderOutput::error(format!(
                    "count map {}:{} failed: {err}",
                    request.name, request.id
                ));
            }
        }
    }
    LoaderOutput::ok(format!(
        "{}\n",
        json!({
            "status": "pass",
            "loader": "rust",
            "scope": "read-only-bpf-map-stats",
            "counts": counts,
        })
    ))
}
