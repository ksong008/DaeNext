use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

const STRIP_TOOL_ENV: &str = "DAE_RUST_NATIVE_BPF_STRIP";
const REQUIRED_SECTIONS: [&str; 5] = [".BTF", ".BTF.ext", ".symtab", ".strtab", ".text"];
const REQUIRED_BTF_IDENTIFIERS: [&[u8]; 2] = [b"bpf_timer\0", b"__opaque\0"];

#[derive(Debug, Eq, PartialEq)]
struct NativeObjectShape {
    programs: BTreeSet<String>,
    maps: BTreeSet<String>,
    relocations: BTreeMap<String, usize>,
}

pub(crate) fn strip_debug_and_validate(path: &Path) -> Result<(), String> {
    let before = parse_shape(path, false);
    run_strip_tool(path)?;
    let after = parse_shape(path, true);
    if before != after {
        return Err(format!(
            "native eBPF object functional shape changed while stripping debug data: {}\nbefore: {before:?}\nafter: {after:?}",
            path.display()
        ));
    }
    Ok(())
}

fn parse_shape(path: &Path, require_stripped: bool) -> NativeObjectShape {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "failed to read native eBPF object for validation {}: {error}",
            path.display()
        )
    });
    let file = object::File::parse(bytes.as_slice()).unwrap_or_else(|error| {
        panic!(
            "failed to parse native eBPF ELF object {}: {error}",
            path.display()
        )
    });
    let sections = file
        .sections()
        .filter_map(|section| section.name().ok().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let missing = REQUIRED_SECTIONS
        .iter()
        .filter(|required| !sections.contains(**required))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        panic!(
            "native eBPF object is missing loader-required sections {}: {}",
            missing.join(", "),
            path.display()
        );
    }
    if !sections.contains("maps") && !sections.contains(".maps") {
        panic!(
            "native eBPF object has neither maps nor .maps section: {}",
            path.display()
        );
    }
    let btf = file
        .section_by_name(".BTF")
        .expect("required .BTF section was checked above")
        .data()
        .unwrap_or_else(|error| {
            panic!(
                "failed to read native eBPF BTF section {}: {error}",
                path.display()
            )
        });
    let missing_btf_identifiers = REQUIRED_BTF_IDENTIFIERS
        .iter()
        .filter(|identifier| !contains_bytes(btf, identifier))
        .map(|identifier| {
            String::from_utf8_lossy(identifier)
                .trim_end_matches('\0')
                .to_owned()
        })
        .collect::<Vec<_>>();
    if !missing_btf_identifiers.is_empty() {
        panic!(
            "native eBPF object is missing kernel-required BTF identifiers {}: {}",
            missing_btf_identifiers.join(", "),
            path.display()
        );
    }
    if require_stripped {
        let debug_sections = sections
            .iter()
            .filter(|name| is_debug_section(name))
            .cloned()
            .collect::<Vec<_>>();
        if !debug_sections.is_empty() {
            panic!(
                "native eBPF object retains debug sections after strip {}: {}",
                path.display(),
                debug_sections.join(", ")
            );
        }
    }

    let programs = sections
        .iter()
        .filter(|name| is_program_section(name))
        .cloned()
        .collect::<BTreeSet<_>>();
    if programs.is_empty() {
        panic!(
            "native eBPF object has no classifier/cgroup program sections: {}",
            path.display()
        );
    }
    let maps = file
        .symbols()
        .filter_map(|symbol| {
            let section = symbol.section_index()?;
            let section_name = file.section_by_index(section).ok()?.name().ok()?;
            matches!(section_name, "maps" | ".maps")
                .then(|| symbol.name().ok().map(str::to_owned))
                .flatten()
        })
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();
    if maps.is_empty() {
        panic!(
            "native eBPF object has no map symbols in maps/.maps: {}",
            path.display()
        );
    }
    let relocations = file
        .sections()
        .filter_map(|section| {
            let name = section.name().ok()?;
            is_program_section(name).then(|| (name.to_owned(), section.relocations().count()))
        })
        .collect::<BTreeMap<_, _>>();
    if relocations.values().any(|count| *count == 0) {
        panic!(
            "native eBPF object lost a loader-required program relocation set: {} {relocations:?}",
            path.display()
        );
    }
    NativeObjectShape {
        programs,
        maps,
        relocations,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Run every configured strip candidate and fail only after all of them have
/// been tried. Previously a candidate that exists but failed (non-zero exit,
/// corrupt input, version mismatch) panicked immediately without falling back
/// to the remaining candidates; now each failure is collected with its stderr
/// and reported together in the returned error.
fn run_strip_tool(path: &Path) -> Result<(), String> {
    let candidates = std::env::var_os(STRIP_TOOL_ENV)
        .map(|tool| vec![tool])
        .unwrap_or_else(|| {
            vec![
                OsString::from("llvm-strip"),
                OsString::from("rust-llvm-strip"),
            ]
        });
    let mut failures = Vec::new();
    for tool in candidates {
        match Command::new(&tool).arg("--strip-debug").arg(path).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => failures.push(format!(
                "{tool:?}: status={} stdout={} stderr={}",
                output.status,
                bounded_output(&output.stdout),
                bounded_output(&output.stderr),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                failures.push(format!("{tool:?}: not found"));
            }
            Err(error) => failures.push(format!("{tool:?}: {error}")),
        }
    }
    Err(format!(
        "native eBPF debug stripping failed for {}; every candidate failed:\n{}\nset {STRIP_TOOL_ENV} to point at a working strip tool",
        path.display(),
        failures.join("\n"),
    ))
}

fn bounded_output(bytes: &[u8]) -> String {
    const LIMIT: usize = 4 * 1024;
    String::from_utf8_lossy(&bytes[..bytes.len().min(LIMIT)]).into_owned()
}

fn is_program_section(name: &str) -> bool {
    name.starts_with("classifier/") || name.starts_with("cgroup/")
}

fn is_debug_section(name: &str) -> bool {
    name.starts_with(".debug_") || name.starts_with(".rel.debug_") || name.starts_with(".zdebug_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_classification_keeps_btf_and_programs_out_of_debug_removal() {
        assert!(is_program_section("classifier/dae0_ingress"));
        assert!(is_program_section("cgroup/connect4"));
        assert!(!is_program_section(".text"));
        assert!(is_debug_section(".debug_info"));
        assert!(is_debug_section(".rel.debug_line"));
        assert!(is_debug_section(".zdebug_info"));
        assert!(is_debug_section(".zdebug_line"));
        assert!(!is_debug_section(".BTF"));
        assert!(!is_debug_section(".BTF.ext"));
    }

    #[test]
    fn btf_identifier_match_requires_a_nul_terminated_name() {
        let btf_strings = b"\0BpfUdpConnState\0bpf_timer\0__opaque\0";
        assert!(contains_bytes(btf_strings, b"bpf_timer\0"));
        assert!(contains_bytes(btf_strings, b"__opaque\0"));
        assert!(!contains_bytes(btf_strings, b"timer_missing\0"));
    }
}
