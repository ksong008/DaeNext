use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use serde_json::json;

mod cases;
#[cfg(test)]
mod coverage;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

static ALLOC_ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

// The counters are updated with Relaxed ordering: the benchmark is
// single-threaded and the numbers are best-effort instrumentation, not a
// synchronization mechanism, so SeqCst would only add fence overhead to every
// allocation without any correctness benefit.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if ALLOC_ENABLED.load(Ordering::Relaxed) && !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if ALLOC_ENABLED.load(Ordering::Relaxed) && !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if ALLOC_ENABLED.load(Ordering::Relaxed) && !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        }
        ptr
    }
}

#[derive(Clone, Debug)]
struct Options {
    case_filter: String,
    iters: u64,
    warmup: u64,
    repeat: u64,
    output: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            case_filter: "all".to_owned(),
            iters: 100_000,
            warmup: 100,
            repeat: 5,
            output: None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BenchCase {
    id: &'static str,
    default_iters: u64,
    run: fn(u64, u64) -> Result<Measurement, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Measurement {
    checksum: u64,
    elapsed_ns: u128,
    allocs: u64,
    bytes: u64,
}

#[derive(Clone, Debug)]
struct BenchmarkMeasurementRow {
    engine: &'static str,
    case: &'static str,
    repeat: u64,
    iters: u64,
    elapsed_ns: u128,
    ns_per_op: f64,
    checksum: u64,
    allocs: u64,
    bytes: u64,
}

impl BenchmarkMeasurementRow {
    fn from_measurement(
        case: &'static str,
        repeat: u64,
        iters: u64,
        measurement: Measurement,
    ) -> Self {
        let ns_per_op = measurement.elapsed_ns as f64 / iters as f64;
        Self {
            engine: "rust",
            case,
            repeat,
            iters,
            elapsed_ns: measurement.elapsed_ns,
            ns_per_op,
            checksum: measurement.checksum,
            allocs: measurement.allocs,
            bytes: measurement.bytes,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "engine": self.engine,
            "case": self.case,
            "repeat": self.repeat,
            "iters": self.iters,
            "elapsed_ns": self.elapsed_ns,
            "ns_per_op": self.ns_per_op,
            "us_per_op": self.ns_per_op / 1000.0,
            "bytes_per_op": self.bytes as f64 / self.iters as f64,
            "allocs_per_op": self.allocs as f64 / self.iters as f64,
            "allocated_bytes": self.bytes,
            "alloc_count": self.allocs,
            "checksum": self.checksum,
        })
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_args()?;
    if let Some(path) = options.output.as_ref()
        && let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create output dir {} failed: {err}", parent.display()))?;
    }
    let matched = if let Some(path) = options.output.as_ref() {
        let file = File::create(path)
            .map_err(|err| format!("write rust bench output {} failed: {err}", path.display()))?;
        let mut writer = BufWriter::new(file);
        let matched = write_benchmark_rows(&options, &mut writer)?;
        writer
            .flush()
            .map_err(|err| format!("flush rust bench output {} failed: {err}", path.display()))?;
        matched
    } else {
        let stdout = io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        let matched = write_benchmark_rows(&options, &mut writer)?;
        writer
            .flush()
            .map_err(|err| format!("flush rust bench stdout failed: {err}"))?;
        matched
    };
    if matched == 0 {
        return Err(format!("no benchmark case matched {}", options.case_filter));
    }
    Ok(())
}

fn write_benchmark_rows<W: Write>(options: &Options, writer: &mut W) -> Result<usize, String> {
    let mut matched = 0_usize;
    for case in bench_cases() {
        if options.case_filter != "all" && options.case_filter != case.id {
            continue;
        }
        matched += 1;
        let iters = if options.iters == 0 {
            case.default_iters
        } else {
            options.iters
        };
        for repeat_index in 0..options.repeat {
            let measurement = (case.run)(iters, options.warmup)?;
            let row = BenchmarkMeasurementRow::from_measurement(
                case.id,
                repeat_index + 1,
                iters,
                measurement,
            );
            serde_json::to_writer(&mut *writer, &row.to_json())
                .map_err(|err| format!("serialize benchmark row {} failed: {err}", case.id))?;
            writer
                .write_all(b"\n")
                .map_err(|err| format!("write benchmark row {} failed: {err}", case.id))?;
        }
    }
    Ok(matched)
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--case" => {
                options.case_filter = args
                    .next()
                    .ok_or_else(|| "--case requires a value".to_owned())?;
            }
            "--iters" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "--iters requires a value".to_owned())?;
                options.iters = if raw == "auto" {
                    0
                } else {
                    raw.parse()
                        .map_err(|_| format!("invalid --iters value: {raw}"))?
                };
            }
            "--warmup" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "--warmup requires a value".to_owned())?;
                options.warmup = raw
                    .parse()
                    .map_err(|_| format!("invalid --warmup value: {raw}"))?;
            }
            "--repeat" => {
                let raw = args
                    .next()
                    .ok_or_else(|| "--repeat requires a value".to_owned())?;
                options.repeat = raw
                    .parse()
                    .map_err(|_| format!("invalid --repeat value: {raw}"))?;
            }
            "--output" => {
                options.output = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--output requires a value".to_owned())?,
                ));
            }
            "--help" | "-h" => {
                println!(
                    "usage: dae-functional-bench [--case all|CASE] [--iters auto|N] [--warmup N] [--repeat N] [--output PATH]"
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unsupported argument: {arg}")),
        }
    }
    if options.repeat == 0 {
        return Err("--repeat must be greater than zero".to_owned());
    }
    Ok(options)
}

fn bench_cases() -> Vec<BenchCase> {
    let mut cases = cases::config::cases();
    cases.extend(cases::dns::cases());
    cases.extend(cases::routing::cases());
    cases.extend(cases::geodata::cases());
    cases.extend(cases::sniffing::cases());
    cases.extend(cases::outbound::cases());
    cases.extend(cases::protocol::cases());
    cases.extend(cases::control::cases());
    cases.extend(cases::daemon::cases());
    cases.extend(cases::engine::cases());
    cases.extend(cases::trace::cases());
    cases.extend(cases::sysdump::cases());
    cases.extend(cases::cli::cases());
    cases
}

pub(crate) fn measure(mut f: impl FnMut() -> u64, iters: u64, warmup: u64) -> Measurement {
    let mut checksum = 0_u64;
    for _ in 0..warmup {
        checksum ^= f();
    }
    // Time the workload with allocator instrumentation disabled. Counting
    // requires atomic operations in every allocation hook and would otherwise
    // inflate ns/op for allocation-heavy cases.
    let started = Instant::now();
    for _ in 0..iters {
        checksum ^= f();
    }
    let elapsed_ns = started.elapsed().as_nanos();

    // Collect allocations in a separate untimed steady-state pass.
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    ALLOC_ENABLED.store(true, Ordering::Relaxed);
    let mut allocation_checksum = 0_u64;
    for _ in 0..iters {
        allocation_checksum ^= f();
    }
    ALLOC_ENABLED.store(false, Ordering::Relaxed);
    checksum ^= std::hint::black_box(allocation_checksum);
    Measurement {
        checksum,
        elapsed_ns,
        allocs: ALLOC_COUNT.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::{BenchmarkMeasurementRow, Measurement};

    #[test]
    fn benchmark_measurement_row_preserves_functional_summary_fields() {
        let row = BenchmarkMeasurementRow::from_measurement(
            "routing/domain-match",
            2,
            10,
            Measurement {
                checksum: 7,
                elapsed_ns: 20_000,
                allocs: 5,
                bytes: 80,
            },
        )
        .to_json();

        assert_eq!(row["engine"].as_str().unwrap(), "rust");
        assert_eq!(row["case"].as_str().unwrap(), "routing/domain-match");
        assert_eq!(row["repeat"].as_u64().unwrap(), 2);
        assert_eq!(row["iters"].as_u64().unwrap(), 10);
        assert_eq!(row["us_per_op"].as_f64().unwrap(), 2.0);
        assert_eq!(row["bytes_per_op"].as_f64().unwrap(), 8.0);
        assert_eq!(row["allocs_per_op"].as_f64().unwrap(), 0.5);
        assert_eq!(row["checksum"].as_u64().unwrap(), 7);
    }
}
