#!/usr/bin/env python3
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


GO_BENCH_RE = re.compile(
    r"^(Benchmark\S+)\s+\d+\s+([\d.]+)\s+ns/op(?:\s+([\d.]+)\s+B/op)?(?:\s+([\d.]+)\s+allocs/op)?"
)
GO_BENCH_RESULT_RE = re.compile(
    r"^\d+\s+([\d.]+)\s+ns/op(?:\s+([\d.]+)\s+B/op)?(?:\s+([\d.]+)\s+allocs/op)?"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", default="tools/bench/functional_matrix.toml")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--go-count", type=int, default=3)
    parser.add_argument("--go-benchtime", default="100ms")
    parser.add_argument("--rust-repeat", type=int, default=3)
    parser.add_argument("--rust-iters", default="auto")
    parser.add_argument("--rust-warmup", type=int, default=100)
    parser.add_argument("--skip-go", action="store_true")
    parser.add_argument("--skip-rust", action="store_true")
    args = parser.parse_args()

    repo = Path.cwd()
    matrix = load_matrix(repo / args.matrix)
    out_dir = Path(args.out_dir) if args.out_dir else Path(
        f"/tmp/dae-daex-functional-bench-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    env = collect_env(repo)
    (out_dir / "env.json").write_text(json.dumps(env, indent=2, ensure_ascii=False) + "\n")
    (out_dir / "manifest.json").write_text(
        json.dumps({"matrix": matrix, "env": env}, indent=2, ensure_ascii=False) + "\n"
    )

    go_rows = []
    if not args.skip_go:
        go_raw = run_go_bench(repo, out_dir, matrix, args.go_count, args.go_benchtime)
        (out_dir / "go.raw.txt").write_text(go_raw)
        go_rows = parse_go(go_raw, matrix)
        (out_dir / "go.parsed.json").write_text(
            json.dumps(go_rows, indent=2, ensure_ascii=False) + "\n"
        )

    rust_rows = []
    if not args.skip_rust:
        rust_raw = run_rust_bench(repo, out_dir, args.rust_repeat, args.rust_iters, args.rust_warmup)
        (out_dir / "rust.raw.jsonl").write_text(rust_raw)
        rust_rows = [json.loads(line) for line in rust_raw.splitlines() if line.strip()]
        (out_dir / "rust.parsed.json").write_text(
            json.dumps(rust_rows, indent=2, ensure_ascii=False) + "\n"
        )

    compare = compare_rows(matrix, go_rows, rust_rows)
    (out_dir / "compare.json").write_text(json.dumps(compare, indent=2, ensure_ascii=False) + "\n")
    (out_dir / "compare.md").write_text(render_markdown(compare, out_dir))
    print(out_dir)
    return 0


def load_matrix(path: Path) -> list[dict]:
    with path.open("rb") as f:
        data = tomllib.load(f)
    return data["case"]


def collect_env(repo: Path) -> dict:
    def capture(cmd):
        try:
            return subprocess.check_output(cmd, cwd=repo, text=True, stderr=subprocess.STDOUT).strip()
        except Exception as exc:
            return f"unavailable: {exc}"

    return {
        "repo": str(repo),
        "timestamp_unix": int(time.time()),
        "git_head": capture(["git", "rev-parse", "HEAD"]),
        "git_branch": capture(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "go_version": capture(["bash", "-lc", "PATH=/root/.local/go1.25.9/bin:$PATH go version"]),
        "rustc_version": capture(["rustc", "--version"]),
        "cargo_version": capture(["cargo", "--version"]),
        "kernel": capture(["uname", "-a"]),
    }


def run_go_bench(repo: Path, out_dir: Path, matrix: list[dict], count: int, benchtime: str) -> str:
    by_pkg: dict[str, list[str]] = {}
    for row in matrix:
        bench = row["go_benchmark"].split("/")[0]
        by_pkg.setdefault(row["go_package"], []).append(bench)
    output = []
    for pkg, benches in sorted(by_pkg.items()):
        regex = "(" + "|".join(sorted(set(re.escape(name) for name in benches))) + ")"
        cmd = [
            "bash",
            "-lc",
            "PATH=/root/.local/go1.25.9/bin:$PATH GOWORK=off "
            f"go test -run '^$' -bench '{regex}' -benchmem -count={count} -benchtime={benchtime} {pkg}",
        ]
        output.append(f"$ {' '.join(cmd)}\n")
        proc = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output.append(proc.stdout)
        if proc.returncode != 0:
            (out_dir / "go.failed.txt").write_text("".join(output))
            raise SystemExit(f"go benchmark failed for {pkg}, see {out_dir / 'go.failed.txt'}")
    return "".join(output)


def run_rust_bench(repo: Path, out_dir: Path, repeat: int, iters: str, warmup: int) -> str:
    output_file = out_dir / "rust.raw.jsonl"
    cmd = [
        "cargo",
        "run",
        "--manifest-path",
        "rust/Cargo.toml",
        "-p",
        "dae-bench",
        "--release",
        "--quiet",
        "--",
        "--case",
        "all",
        "--iters",
        str(iters),
        "--warmup",
        str(warmup),
        "--repeat",
        str(repeat),
        "--output",
        str(output_file),
    ]
    proc = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        (out_dir / "rust.failed.txt").write_text(proc.stdout)
        raise SystemExit(f"rust benchmark failed, see {out_dir / 'rust.failed.txt'}")
    return output_file.read_text()


def parse_go(raw: str, matrix: list[dict]) -> list[dict]:
    bench_to_case = {row["go_benchmark"]: row["id"] for row in matrix}
    rows = []
    pending_benchmark = None
    for line in raw.splitlines():
        stripped = line.strip()
        match = GO_BENCH_RE.match(stripped)
        if match:
            raw_name = re.sub(r"-\d+$", "", match.group(1))
            pending_benchmark = None
            parsed = parse_go_measurement(raw_name, match, bench_to_case, line, value_offset=2)
            if parsed:
                rows.append(parsed)
            continue
        if stripped.startswith("Benchmark"):
            raw_name = re.sub(r"-\d+$", "", stripped.split()[0])
            if raw_name in bench_to_case:
                pending_benchmark = raw_name
            continue
        match = GO_BENCH_RESULT_RE.match(stripped)
        if match and pending_benchmark:
            parsed = parse_go_measurement(pending_benchmark, match, bench_to_case, line, value_offset=1)
            pending_benchmark = None
            if parsed:
                rows.append(parsed)
            continue
    return rows


def parse_go_measurement(
    raw_name: str,
    match: re.Match[str],
    bench_to_case: dict[str, str],
    line: str,
    value_offset: int,
) -> dict | None:
    if not match:
        return None
    case_id = bench_to_case.get(raw_name)
    if not case_id:
        return None
    ns = float(match.group(value_offset))
    bytes_per_op = float(match.group(value_offset + 1) or 0.0)
    allocs_per_op = float(match.group(value_offset + 2) or 0.0)
    return {
        "engine": "go",
        "case": case_id,
        "benchmark": raw_name,
        "ns_per_op": ns,
        "us_per_op": ns / 1000.0,
        "bytes_per_op": bytes_per_op,
        "allocs_per_op": allocs_per_op,
        "raw": line,
    }


def summarize(rows: list[dict], case_id: str) -> dict | None:
    selected = [row for row in rows if row["case"] == case_id]
    if not selected:
        return None
    out = {"count": len(selected)}
    for key in ["ns_per_op", "us_per_op", "bytes_per_op", "allocs_per_op"]:
        values = [float(row[key]) for row in selected]
        out[key + "_avg"] = statistics.fmean(values)
        out[key + "_min"] = min(values)
        out[key + "_max"] = max(values)
    return out


def compare_rows(matrix: list[dict], go_rows: list[dict], rust_rows: list[dict]) -> list[dict]:
    result = []
    for row in matrix:
        case_id = row["id"]
        go = summarize(go_rows, case_id)
        rust = summarize(rust_rows, case_id)
        ratios = {}
        if go and rust:
            for key in ["us_per_op", "bytes_per_op", "allocs_per_op"]:
                g = go[key + "_avg"]
                r = rust[key + "_avg"]
                ratios[key + "_rust_vs_go"] = None if g == 0 else r / g
        result.append({"case": case_id, "go": go, "rust": rust, "ratio": ratios})
    return result


def render_markdown(compare: list[dict], out_dir: Path) -> str:
    lines = [
        "# DAEX Functional Benchmark Compare",
        "",
        f"Output: `{out_dir}`",
        "",
        "| case | Go us/op | Rust us/op | Rust/Go time | Go B/op | Rust B/op | Rust/Go B | Go allocs/op | Rust allocs/op | Rust/Go allocs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in compare:
        go = row["go"] or {}
        rust = row["rust"] or {}
        ratio = row["ratio"] or {}
        lines.append(
            "| {case} | {go_us} | {rust_us} | {time_ratio} | {go_b} | {rust_b} | {b_ratio} | {go_a} | {rust_a} | {a_ratio} |".format(
                case=row["case"],
                go_us=fmt(go.get("us_per_op_avg")),
                rust_us=fmt(rust.get("us_per_op_avg")),
                time_ratio=fmt(ratio.get("us_per_op_rust_vs_go")),
                go_b=fmt(go.get("bytes_per_op_avg")),
                rust_b=fmt(rust.get("bytes_per_op_avg")),
                b_ratio=fmt(ratio.get("bytes_per_op_rust_vs_go")),
                go_a=fmt(go.get("allocs_per_op_avg")),
                rust_a=fmt(rust.get("allocs_per_op_avg")),
                a_ratio=fmt(ratio.get("allocs_per_op_rust_vs_go")),
            )
        )
    lines.append("")
    return "\n".join(lines)


def fmt(value):
    if value is None:
        return "n/a"
    return f"{value:.3f}"


if __name__ == "__main__":
    sys.exit(main())
