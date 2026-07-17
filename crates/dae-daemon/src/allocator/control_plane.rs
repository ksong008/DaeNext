use super::*;

#[cfg(feature = "allocator-jemalloc")]
static CONTROL_PLANE_ARENA: OnceLock<Result<u32, String>> = OnceLock::new();

pub(crate) fn allocator_bind_control_plane_thread() -> Result<Option<u32>, String> {
    #[cfg(feature = "allocator-jemalloc")]
    {
        let arena = control_plane_arena()?;
        mallctl::write_u32(b"thread.arena\0", arena)?;
        Ok(Some(arena))
    }
    #[cfg(not(feature = "allocator-jemalloc"))]
    Ok(None)
}

pub(crate) fn allocator_flush_current_thread_cache() -> Result<(), String> {
    #[cfg(feature = "allocator-jemalloc")]
    {
        mallctl::command(b"thread.tcache.flush\0")
    }
    #[cfg(not(feature = "allocator-jemalloc"))]
    Ok(())
}

pub(crate) fn allocator_purge_control_plane_arena() -> (&'static str, Value) {
    #[cfg(feature = "allocator-jemalloc")]
    {
        use tikv_jemalloc_ctl::epoch;

        let arena = match control_plane_arena() {
            Ok(arena) => arena,
            Err(error) => {
                return (
                    "fail",
                    json!({
                        "operation": "jemalloc_control_plane_arena_purge",
                        "error": error,
                    }),
                );
            }
        };
        let epoch_before = epoch::advance().ok();
        let command = format!("arena.{arena}.purge\0");
        let result = mallctl::command(command.as_bytes());
        let epoch_after = epoch::advance().ok();
        match result {
            Ok(()) => (
                "pass",
                json!({
                    "operation": "jemalloc_control_plane_arena_purge",
                    "arena": arena,
                    "arenaPurgeScope": "control-plane-only",
                    "epochBefore": epoch_before,
                    "epochAfter": epoch_after,
                }),
            ),
            Err(error) => (
                "fail",
                json!({
                    "operation": "jemalloc_control_plane_arena_purge",
                    "arena": arena,
                    "arenaPurgeScope": "control-plane-only",
                    "epochBefore": epoch_before,
                    "epochAfter": epoch_after,
                    "error": error,
                }),
            ),
        }
    }
    #[cfg(not(feature = "allocator-jemalloc"))]
    (
        "unsupported",
        json!({
            "operation": "control_plane_arena_purge",
            "reason": "dedicated arenas require allocator-jemalloc",
        }),
    )
}

#[cfg(feature = "allocator-jemalloc")]
fn control_plane_arena() -> Result<u32, String> {
    CONTROL_PLANE_ARENA
        .get_or_init(|| mallctl::read_command_u32(b"arenas.create\0"))
        .clone()
}

#[cfg(all(test, feature = "allocator-jemalloc"))]
mod tests {
    use super::*;

    #[test]
    fn control_plane_thread_binds_flushes_and_purges_only_its_arena() {
        let arena = allocator_bind_control_plane_thread().unwrap().unwrap();
        assert_eq!(mallctl::read_u32(b"thread.arena\0").unwrap(), arena);
        allocator_flush_current_thread_cache().unwrap();
        let (status, report) = allocator_purge_control_plane_arena();
        assert_eq!(status, "pass");
        assert_eq!(report["arena"], json!(arena));
        assert_eq!(report["arenaPurgeScope"], json!("control-plane-only"));
    }
}
