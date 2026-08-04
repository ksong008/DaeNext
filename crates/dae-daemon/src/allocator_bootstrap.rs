use std::io;

#[cfg(any(feature = "allocator-jemalloc", test))]
use std::ffi::OsString;

pub(crate) const JEMALLOC_RUNTIME_CONF_ENV: &str = "_RJEM_MALLOC_CONF";
pub(crate) const JEMALLOC_BUILD_CONF_ENV: &str = "JEMALLOC_SYS_WITH_MALLOC_CONF";
pub(crate) const JEMALLOC_BUILD_CONF_SOURCE: &str = ".cargo/config.toml";
pub(crate) const JEMALLOC_RUNTIME_DEFAULT_SOURCE: &str = "startup-bootstrap";
pub(crate) const JEMALLOC_BUILD_FALLBACK: &str = "background_thread:true,max_background_threads:1,dirty_decay_ms:5000,muzzy_decay_ms:5000,percpu_arena:disabled,narenas:2";
pub(crate) const JEMALLOC_AUTOMATIC_ARENA_MAX: usize = 2;

#[cfg(any(feature = "allocator-jemalloc", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JemallocConfigurationSource {
    EffectiveEnvironment,
    AdaptiveDefault,
}

#[cfg(any(feature = "allocator-jemalloc", test))]
#[derive(Debug, Eq, PartialEq)]
struct JemallocBootstrapDecision {
    source: JemallocConfigurationSource,
    restart_configuration: Option<OsString>,
}

pub(crate) fn jemalloc_automatic_arena_count(available_parallelism: usize) -> usize {
    available_parallelism.clamp(1, JEMALLOC_AUTOMATIC_ARENA_MAX)
}

pub(crate) fn jemalloc_adaptive_configuration(available_parallelism: usize) -> String {
    format!(
        "background_thread:true,max_background_threads:1,dirty_decay_ms:5000,muzzy_decay_ms:5000,percpu_arena:disabled,narenas:{}",
        jemalloc_automatic_arena_count(available_parallelism)
    )
}

pub(crate) fn jemalloc_process_default_configuration() -> String {
    let available_parallelism = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    jemalloc_adaptive_configuration(available_parallelism)
}

#[cfg(any(feature = "allocator-jemalloc", test))]
fn jemalloc_bootstrap_decision(
    effective_configuration: Option<OsString>,
    available_parallelism: usize,
) -> JemallocBootstrapDecision {
    if effective_configuration
        .as_ref()
        .is_some_and(jemalloc_configuration_is_valid)
    {
        return JemallocBootstrapDecision {
            source: JemallocConfigurationSource::EffectiveEnvironment,
            restart_configuration: None,
        };
    }
    JemallocBootstrapDecision {
        source: JemallocConfigurationSource::AdaptiveDefault,
        restart_configuration: Some(jemalloc_adaptive_configuration(available_parallelism).into()),
    }
}

#[cfg(any(feature = "allocator-jemalloc", test))]
fn jemalloc_configuration_is_valid(configuration: &OsString) -> bool {
    let Some(configuration) = configuration.to_str() else {
        return false;
    };
    if configuration.is_empty() {
        return false;
    }
    configuration.split(',').all(|entry| {
        let Some((name, value)) = entry.split_once(':') else {
            return false;
        };
        if name.is_empty()
            || value.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == 0)
        {
            return false;
        }
        match name {
            "background_thread" => matches!(value, "true" | "false"),
            "max_background_threads" | "narenas" => {
                value.parse::<usize>().is_ok_and(|value| value > 0)
            }
            "dirty_decay_ms" | "muzzy_decay_ms" => {
                value.parse::<i64>().is_ok_and(|value| value >= -1)
            }
            "percpu_arena" => matches!(value, "disabled" | "percpu" | "phycpu"),
            "lg_tcache_max" => value.parse::<u32>().is_ok_and(|value| value < usize::BITS),
            // Preserve syntactically valid operator options that jemalloc itself owns;
            // the runtime contract reports the effective product-critical opt.* values.
            _ => true,
        }
    })
}

/// Ensures that immutable jemalloc options are present before the product
/// process performs normal startup work.
///
/// The first image starts with the bounded build fallback, derives an
/// affinity/cgroup-aware default, and replaces itself once. The replacement
/// image inherits the same PID and starts jemalloc with the effective prefixed
/// configuration variable already present.
#[doc(hidden)]
pub fn ensure_allocator_startup_configuration() -> io::Result<()> {
    ensure_allocator_startup_configuration_impl()
}

#[cfg(all(feature = "allocator-jemalloc", unix))]
fn ensure_allocator_startup_configuration_impl() -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let available_parallelism = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let decision = jemalloc_bootstrap_decision(
        std::env::var_os(JEMALLOC_RUNTIME_CONF_ENV),
        available_parallelism,
    );
    let Some(configuration) = decision.restart_configuration else {
        return Ok(());
    };

    let executable = std::env::current_exe()?;
    let mut arguments = std::env::args_os();
    let argument_zero = arguments.next();
    let mut command = Command::new(executable);
    if let Some(argument_zero) = argument_zero {
        command.arg0(argument_zero);
    }
    command
        .args(arguments)
        .env(JEMALLOC_RUNTIME_CONF_ENV, configuration);
    Err(command.exec())
}

#[cfg(all(feature = "allocator-jemalloc", not(unix)))]
fn ensure_allocator_startup_configuration_impl() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "adaptive jemalloc startup configuration requires process replacement support",
    ))
}

#[cfg(not(feature = "allocator-jemalloc"))]
fn ensure_allocator_startup_configuration_impl() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_arena_count_tracks_effective_parallelism_with_a_small_cap() {
        assert_eq!(jemalloc_automatic_arena_count(0), 1);
        assert_eq!(jemalloc_automatic_arena_count(1), 1);
        assert_eq!(jemalloc_automatic_arena_count(2), 2);
        assert_eq!(jemalloc_automatic_arena_count(64), 2);
    }

    #[test]
    fn adaptive_configuration_keeps_the_validated_background_policy() {
        let single_cpu = jemalloc_adaptive_configuration(1);
        assert!(single_cpu.contains("narenas:1"));
        assert!(single_cpu.contains("max_background_threads:1"));
        assert!(single_cpu.contains("dirty_decay_ms:5000"));
        assert!(single_cpu.contains("muzzy_decay_ms:5000"));
        assert!(single_cpu.contains("percpu_arena:disabled"));

        let multi_cpu = jemalloc_adaptive_configuration(4);
        assert!(multi_cpu.contains("narenas:2"));
        assert!(!multi_cpu.contains("percpu_arena:percpu"));
    }

    #[test]
    fn effective_prefixed_configuration_has_precedence() {
        let decision = jemalloc_bootstrap_decision(Some("narenas:7".into()), 1);
        assert_eq!(
            decision.source,
            JemallocConfigurationSource::EffectiveEnvironment
        );
        assert_eq!(decision.restart_configuration, None);
    }

    #[test]
    fn empty_effective_configuration_does_not_disable_the_default() {
        let decision = jemalloc_bootstrap_decision(Some(OsString::new()), 1);
        assert_eq!(
            decision.source,
            JemallocConfigurationSource::AdaptiveDefault
        );
        assert_eq!(
            decision.restart_configuration,
            Some(OsString::from(jemalloc_adaptive_configuration(1)))
        );
    }

    #[test]
    fn invalid_effective_configuration_is_replaced_by_the_adaptive_default() {
        for invalid in [
            "not-a-malloc-conf",
            "narenas:0",
            "background_thread:maybe",
            "dirty_decay_ms:-2",
            "percpu_arena:unknown",
        ] {
            let decision = jemalloc_bootstrap_decision(Some(invalid.into()), 4);
            assert_eq!(
                decision.source,
                JemallocConfigurationSource::AdaptiveDefault,
                "{invalid}"
            );
            assert_eq!(
                decision.restart_configuration,
                Some(OsString::from(jemalloc_adaptive_configuration(4))),
                "{invalid}"
            );
        }
    }

    #[test]
    fn absent_override_selects_the_affinity_aware_default() {
        let single_cpu = jemalloc_bootstrap_decision(None, 1);
        assert_eq!(
            single_cpu.source,
            JemallocConfigurationSource::AdaptiveDefault
        );
        assert_eq!(
            single_cpu.restart_configuration,
            Some(OsString::from(jemalloc_adaptive_configuration(1)))
        );

        let multi_cpu = jemalloc_bootstrap_decision(None, 8);
        assert_eq!(
            multi_cpu.source,
            JemallocConfigurationSource::AdaptiveDefault
        );
        assert_eq!(
            multi_cpu.restart_configuration,
            Some(OsString::from(jemalloc_adaptive_configuration(8)))
        );
    }
}
