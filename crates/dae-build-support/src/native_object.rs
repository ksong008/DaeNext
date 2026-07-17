use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

const STRIP_TOOL_ENV: &str = "DAE_RUST_NATIVE_BPF_STRIP";
const REQUIRED_SECTIONS: [&str; 6] = [".BTF", ".BTF.ext", "maps", ".maps", ".symtab", ".strtab"];

#[derive(Debug, Eq, PartialEq)]
struct NativeObjectShape {
    programs: BTreeSet<String>,
    maps: BTreeSet<String>,
    relocations: BTreeMap<String, usize>,
}

pub(crate) fn strip_debug_and_validate(path: &Path) {
    let before = parse_shape(path, false);
    run_strip_tool(path);
    let after = parse_shape(path, true);
    if before != after {
        panic!(
            "native eBPF object functional shape changed while stripping debug data: {}\nbefore: {before:?}\nafter: {after:?}",
            path.display()
        );
    }
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

fn run_strip_tool(path: &Path) {
    let candidates = std::env::var_os(STRIP_TOOL_ENV)
        .map(|tool| vec![tool])
        .unwrap_or_else(|| {
            vec![
                OsString::from("llvm-strip"),
                OsString::from("rust-llvm-strip"),
            ]
        });
    let mut missing = Vec::new();
    for tool in candidates {
        match Command::new(&tool).arg("--strip-debug").arg(path).output() {
            Ok(output) if output.status.success() => return,
            Ok(output) => {
                panic!(
                    "native eBPF debug stripping failed for {} with {:?}: status={} stdout={} stderr={}",
                    path.display(),
                    tool,
                    output.status,
                    bounded_output(&output.stdout),
                    bounded_output(&output.stderr),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing.push(tool),
            Err(error) => {
                panic!(
                    "failed to execute native eBPF strip tool {:?} for {}: {error}",
                    tool,
                    path.display()
                );
            }
        }
    }
    panic!(
        "no native eBPF strip tool is available for {} (tried {missing:?}); set {STRIP_TOOL_ENV}",
        path.display()
    );
}

fn bounded_output(bytes: &[u8]) -> String {
    const LIMIT: usize = 4 * 1024;
    String::from_utf8_lossy(&bytes[..bytes.len().min(LIMIT)]).into_owned()
}

fn is_program_section(name: &str) -> bool {
    name.starts_with("classifier/") || name.starts_with("cgroup/")
}

fn is_debug_section(name: &str) -> bool {
    name.starts_with(".debug_") || name.starts_with(".rel.debug_")
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
        assert!(!is_debug_section(".BTF"));
        assert!(!is_debug_section(".BTF.ext"));
    }
}
