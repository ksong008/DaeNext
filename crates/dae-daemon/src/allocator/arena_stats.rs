use super::*;

#[cfg(feature = "allocator-jemalloc")]
pub(super) fn allocator_arena_stats_json() -> Value {
    let narenas = match mallctl::read_u32(b"arenas.narenas\0") {
        Ok(narenas) => narenas,
        Err(error) => {
            return json!({
                "available": false,
                "error": error,
            });
        }
    };
    let mut arenas = Vec::new();
    let mut failures = Vec::new();
    for arena in 0..narenas {
        let initialized_key = format!("arena.{arena}.initialized\0");
        match mallctl::read_bool(initialized_key.as_bytes()) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                failures.push(json!({
                    "arena": arena,
                    "field": "initialized",
                    "error": error,
                }));
                continue;
            }
        }
        let read_u32 = |field: &'static str| {
            let key = format!("stats.arenas.{arena}.{field}\0");
            mallctl::read_u32(key.as_bytes()).map(u64::from)
        };
        let read_usize = |field: &'static str| {
            let key = format!("stats.arenas.{arena}.{field}\0");
            mallctl::read_usize(key.as_bytes()).map(|value| value as u64)
        };
        match (
            read_u32("nthreads"),
            read_usize("pactive"),
            read_usize("pdirty"),
            read_usize("pmuzzy"),
            read_usize("tcache_bytes"),
        ) {
            (Ok(threads), Ok(active), Ok(dirty), Ok(muzzy), Ok(tcache)) => {
                arenas.push(json!({
                    "arena": arena,
                    "threads": threads,
                    "pages": {
                        "active": active,
                        "dirty": dirty,
                        "muzzy": muzzy,
                    },
                    "tcacheBytes": tcache.to_string(),
                }));
            }
            values => {
                let errors = [
                    ("nthreads", values.0.err()),
                    ("pactive", values.1.err()),
                    ("pdirty", values.2.err()),
                    ("pmuzzy", values.3.err()),
                    ("tcache_bytes", values.4.err()),
                ]
                .into_iter()
                .filter_map(|(field, error)| {
                    error.map(|error| {
                        json!({
                            "field": field,
                            "error": error,
                        })
                    })
                })
                .collect::<Vec<_>>();
                failures.push(json!({
                    "arena": arena,
                    "errors": errors,
                }));
            }
        }
    }
    json!({
        "available": true,
        "observedArenas": narenas,
        "initializedArenas": arenas,
        "failures": failures,
    })
}

#[cfg(not(feature = "allocator-jemalloc"))]
pub(super) fn allocator_arena_stats_json() -> Value {
    json!({
        "available": false,
        "reason": "arena statistics require allocator-jemalloc",
    })
}
