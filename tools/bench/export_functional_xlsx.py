#!/usr/bin/env python3
import argparse
import json
import math
import time
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from xml.sax.saxutils import escape


SHEET_NAMES = [
    "Summary",
    "By_Category",
    "Latest_73_Compare",
    "Slower_Cases",
    "Threshold_Failures",
    "Allocation_Higher",
    "Delta_vs_Baseline",
    "Matrix_Manifest",
    "Env",
    "Files",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--old-compare", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--kind", default="latest 73-case functional Go/Rust benchmark")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    compare = load_json(run_dir / "compare.json")
    manifest = load_json(run_dir / "manifest.json")
    env = load_json(run_dir / "env.json")
    old_compare_path = Path(args.old_compare).resolve() if args.old_compare else None
    old_compare = load_json(old_compare_path) if old_compare_path else []
    out = Path(args.out).resolve() if args.out else run_dir / default_name(run_dir)

    sheets = build_sheets(
        run_dir, compare, manifest, env, old_compare, old_compare_path, out, args.kind
    )
    write_xlsx(out, sheets)
    print(out)
    return 0


def load_json(path: Path):
    return json.loads(path.read_text())


def default_name(run_dir: Path) -> str:
    suffix = run_dir.name.replace("functional_73_", "").upper()
    return f"DAEX_FUNCTIONAL_73_{suffix}_COMPARE.xlsx"


def build_sheets(
    run_dir: Path, compare, manifest, env, old_compare, old_compare_path: Path | None,
    out: Path, kind: str
):
    summary = summarize(compare)
    old_by_case = {row["case"]: row for row in old_compare}
    matrix = manifest.get("matrix", [])
    category_rows = build_category_rows(compare)
    latest_rows = [["category", "case", "go_count", "go_us_avg", "rust_count", "rust_us_avg",
                    "rust_go_time_ratio", "go_b_op_avg", "rust_b_op_avg", "rust_go_b_ratio",
                    "go_allocs_op_avg", "rust_allocs_op_avg", "rust_go_allocs_ratio",
                    "go_us_min", "go_us_max", "rust_us_min", "rust_us_max"]]
    for row in compare:
        latest_rows.append(compare_row(row))

    slower_rows = [["category", "case", "go_us_avg", "rust_us_avg", "rust_go_time_ratio",
                    "go_b_op_avg", "rust_b_op_avg", "rust_go_b_ratio", "go_allocs_op_avg",
                    "rust_allocs_op_avg", "rust_go_allocs_ratio", "go_count", "go_us_min",
                    "go_us_max", "rust_count", "rust_us_min", "rust_us_max"]]
    for row in sorted(compare, key=lambda item: ratio(item, "us_per_op") or -1.0, reverse=True):
        if ratio_gt(row, "us_per_op", 1.0):
            values = compare_row(row)
            slower_rows.append([values[0], values[1], values[3], values[5], values[6],
                                values[7], values[8], values[9], values[10], values[11],
                                values[12], values[2], values[13], values[14], values[4],
                                values[15], values[16]])

    threshold_rows = [["threshold_reasons", "category", "case", "go_us_avg", "rust_us_avg",
                       "rust_go_time_ratio", "go_b_op_avg", "rust_b_op_avg", "rust_go_b_ratio",
                       "go_allocs_op_avg", "rust_allocs_op_avg", "rust_go_allocs_ratio",
                       "go_count", "go_us_min", "go_us_max", "rust_count", "rust_us_min",
                       "rust_us_max"]]
    for row in compare:
        reasons = threshold_reasons(row)
        if reasons:
            values = compare_row(row)
            threshold_rows.append(["; ".join(reasons), values[0], values[1], values[3],
                                   values[5], values[6], values[7], values[8], values[9],
                                   values[10], values[11], values[12], values[2],
                                   values[13], values[14], values[4], values[15], values[16]])

    allocation_rows = [["category", "case", "go_b_op_avg", "rust_b_op_avg", "rust_go_b_ratio",
                        "go_allocs_op_avg", "rust_allocs_op_avg", "rust_go_allocs_ratio",
                        "go_us_avg", "rust_us_avg", "rust_go_time_ratio", "go_count",
                        "go_us_min", "go_us_max", "rust_count", "rust_us_min", "rust_us_max"]]
    for row in compare:
        if ratio_gt(row, "bytes_per_op", 1.1) or ratio_gt(row, "allocs_per_op", 1.1):
            values = compare_row(row)
            allocation_rows.append([values[0], values[1], values[7], values[8], values[9],
                                    values[10], values[11], values[12], values[3], values[5],
                                    values[6], values[2], values[13], values[14], values[4],
                                    values[15], values[16]])

    delta_rows = [["category", "case", "old_go_us_avg", "new_go_us_avg", "go_us_delta_pct",
                   "old_rust_us_avg", "new_rust_us_avg", "rust_us_delta_pct",
                   "old_time_ratio", "new_time_ratio", "time_ratio_delta",
                   "old_rust_b_op", "new_rust_b_op", "old_rust_allocs", "new_rust_allocs"]]
    for row in compare:
        old = old_by_case.get(row["case"], {})
        delta_rows.append([
            category(row["case"]),
            row["case"],
            metric(old, "go", "us_per_op"),
            metric(row, "go", "us_per_op"),
            pct_delta(metric(old, "go", "us_per_op"), metric(row, "go", "us_per_op")),
            metric(old, "rust", "us_per_op"),
            metric(row, "rust", "us_per_op"),
            pct_delta(metric(old, "rust", "us_per_op"), metric(row, "rust", "us_per_op")),
            ratio(old, "us_per_op"),
            ratio(row, "us_per_op"),
            diff(ratio(old, "us_per_op"), ratio(row, "us_per_op")),
            metric(old, "rust", "bytes_per_op"),
            metric(row, "rust", "bytes_per_op"),
            metric(old, "rust", "allocs_per_op"),
            metric(row, "rust", "allocs_per_op"),
        ])

    manifest_rows = [["id", "go_package", "go_benchmark", "rust_case"]]
    for row in matrix:
        manifest_rows.append([
            row.get("id", ""),
            row.get("go_package", ""),
            row.get("go_benchmark", ""),
            row.get("rust_case", ""),
        ])

    env_rows = [["Field", "Value"]]
    for key, value in env.items():
        env_rows.append([key, value])

    summary_rows = [
        ["Field", "Value"],
        ["benchmark_kind", kind],
        ["run_dir", str(run_dir)],
        ["xlsx", str(out)],
        ["compare_json", str(run_dir / "compare.json")],
        ["compare_md", str(run_dir / "compare.md")],
        ["old_compare_json", str(old_compare_path) if old_compare_path else ""],
        ["go_count", summary["go_count"]],
        ["go_benchtime", "1s"],
        ["rust_repeat", summary["rust_count"]],
        ["rust_iters", "auto"],
        ["rust_warmup", 100],
        ["repo", env.get("repo", "")],
        ["git_head", env.get("git_head", "")],
        ["git_branch", env.get("git_branch", "")],
        ["go_version", env.get("go_version", "")],
        ["rustc_version", env.get("rustc_version", "")],
        ["cargo_version", env.get("cargo_version", "")],
        ["kernel", env.get("kernel", "")],
        ["timestamp_unix", env.get("timestamp_unix", "")],
        ["total_cases", summary["total_cases"]],
        ["with_go_and_rust", summary["with_both"]],
        ["missing_go", summary["missing_go"]],
        ["missing_rust", summary["missing_rust"]],
        ["rust_time_faster", summary["rust_time_faster"]],
        ["rust_time_slower", summary["rust_time_slower"]],
        ["rust_time_le_0_8x_go", summary["rust_time_le_0_8x_go"]],
        ["rust_time_gt_1_2x_go", summary["rust_time_gt_1_2x_go"]],
        ["rust_b_gt_1_1x_go", summary["rust_b_gt_1_1x_go"]],
        ["rust_allocs_gt_1_1x_go", summary["rust_allocs_gt_1_1x_go"]],
    ]

    files_rows = [["file", "bytes", "path"]]
    for path in sorted(run_dir.iterdir()):
        if path.is_file():
            files_rows.append([path.name, path.stat().st_size, str(path)])

    return [
        ("Summary", summary_rows),
        ("By_Category", category_rows),
        ("Latest_73_Compare", latest_rows),
        ("Slower_Cases", slower_rows),
        ("Threshold_Failures", threshold_rows),
        ("Allocation_Higher", allocation_rows),
        ("Delta_vs_Baseline", delta_rows),
        ("Matrix_Manifest", manifest_rows),
        ("Env", env_rows),
        ("Files", files_rows),
    ]


def summarize(compare):
    with_both = [row for row in compare if row.get("go") and row.get("rust")]
    return {
        "total_cases": len(compare),
        "with_both": len(with_both),
        "missing_go": sum(1 for row in compare if not row.get("go")),
        "missing_rust": sum(1 for row in compare if not row.get("rust")),
        "rust_time_faster": sum(1 for row in with_both if ratio_lt(row, "us_per_op", 1.0)),
        "rust_time_slower": sum(1 for row in with_both if ratio_gt(row, "us_per_op", 1.0)),
        "rust_time_le_0_8x_go": sum(1 for row in with_both if ratio_lte(row, "us_per_op", 0.8)),
        "rust_time_gt_1_2x_go": sum(1 for row in with_both if ratio_gt(row, "us_per_op", 1.2)),
        "rust_b_gt_1_1x_go": sum(1 for row in with_both if ratio_gt(row, "bytes_per_op", 1.1)),
        "rust_allocs_gt_1_1x_go": sum(1 for row in with_both if ratio_gt(row, "allocs_per_op", 1.1)),
        "go_count": max((metric(row, "go", "count") or 0 for row in with_both), default=0),
        "rust_count": max((metric(row, "rust", "count") or 0 for row in with_both), default=0),
    }


def build_category_rows(compare):
    buckets = {}
    for row in compare:
        cat = category(row["case"])
        bucket = buckets.setdefault(cat, [])
        bucket.append(row)
    rows = [["category", "cases", "with_both", "rust_time_faster", "rust_time_slower",
             "time_gt_1_2", "bytes_gt_1_1", "allocs_gt_1_1"]]
    for cat in sorted(buckets):
        rows_for_cat = buckets[cat]
        with_both = [row for row in rows_for_cat if row.get("go") and row.get("rust")]
        rows.append([
            cat,
            len(rows_for_cat),
            len(with_both),
            sum(1 for row in with_both if ratio_lt(row, "us_per_op", 1.0)),
            sum(1 for row in with_both if ratio_gt(row, "us_per_op", 1.0)),
            sum(1 for row in with_both if ratio_gt(row, "us_per_op", 1.2)),
            sum(1 for row in with_both if ratio_gt(row, "bytes_per_op", 1.1)),
            sum(1 for row in with_both if ratio_gt(row, "allocs_per_op", 1.1)),
        ])
    return rows


def compare_row(row):
    return [
        category(row["case"]),
        row["case"],
        metric(row, "go", "count"),
        metric(row, "go", "us_per_op"),
        metric(row, "rust", "count"),
        metric(row, "rust", "us_per_op"),
        ratio(row, "us_per_op"),
        metric(row, "go", "bytes_per_op"),
        metric(row, "rust", "bytes_per_op"),
        ratio(row, "bytes_per_op"),
        metric(row, "go", "allocs_per_op"),
        metric(row, "rust", "allocs_per_op"),
        ratio(row, "allocs_per_op"),
        metric(row, "go", "us_per_op", "min"),
        metric(row, "go", "us_per_op", "max"),
        metric(row, "rust", "us_per_op", "min"),
        metric(row, "rust", "us_per_op", "max"),
    ]


def threshold_reasons(row):
    reasons = []
    if ratio_gt(row, "us_per_op", 1.2):
        reasons.append("rust_time_gt_1_2x_go")
    if ratio_gt(row, "bytes_per_op", 1.1):
        reasons.append("rust_b_gt_1_1x_go")
    if ratio_gt(row, "allocs_per_op", 1.1):
        reasons.append("rust_allocs_gt_1_1x_go")
    return reasons


def category(case_id: str) -> str:
    return case_id.split("/", 1)[0]


def metric(row, engine, key, suffix="avg"):
    values = row.get(engine) or {}
    if key == "count":
        return values.get("count")
    return values.get(f"{key}_{suffix}")


def ratio(row, key):
    if not row:
        return None
    return (row.get("ratio") or {}).get(f"{key}_rust_vs_go")


def ratio_gt(row, key, threshold):
    value = ratio(row, key)
    return value is not None and value > threshold


def ratio_lt(row, key, threshold):
    value = ratio(row, key)
    return value is not None and value < threshold


def ratio_lte(row, key, threshold):
    value = ratio(row, key)
    return value is not None and value <= threshold


def pct_delta(old, new):
    if old in (None, 0) or new is None:
        return None
    return (new - old) / old * 100.0


def diff(old, new):
    if old is None or new is None:
        return None
    return new - old


def write_xlsx(path: Path, sheets):
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w", ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types(len(sheets)))
        zf.writestr("_rels/.rels", root_rels())
        zf.writestr("xl/workbook.xml", workbook_xml(sheets))
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels(len(sheets)))
        zf.writestr("xl/styles.xml", styles_xml())
        zf.writestr("docProps/core.xml", core_xml())
        zf.writestr("docProps/app.xml", app_xml(sheets))
        for idx, (_, rows) in enumerate(sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", worksheet_xml(rows))


def content_types(sheet_count: int) -> str:
    sheet_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        f"{sheet_overrides}</Types>"
    )


def root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '</Relationships>'
    )


def workbook_xml(sheets) -> str:
    entries = "".join(
        f'<sheet name="{xml(name)}" sheetId="{idx}" r:id="rId{idx}"/>'
        for idx, (name, _) in enumerate(sheets, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{entries}</sheets></workbook>"
    )


def workbook_rels(sheet_count: int) -> str:
    entries = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, sheet_count + 1)
    )
    entries += (
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{entries}</Relationships>'
    )


def worksheet_xml(rows) -> str:
    max_cols = max((len(row) for row in rows), default=1)
    cols = "".join(
        f'<col min="{i}" max="{i}" width="{52 if i in (2, 4, 7) else 18 if i > 2 else 24}" customWidth="1"/>'
        for i in range(1, max_cols + 1)
    )
    row_xml = []
    for r, row in enumerate(rows, start=1):
        cells = []
        for c, value in enumerate(row, start=1):
            ref = f"{col_name(c)}{r}"
            style = ' s="1"' if r == 1 else ""
            cells.append(cell_xml(ref, value, style))
        row_xml.append(f'<row r="{r}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        f"<cols>{cols}</cols><sheetData>{''.join(row_xml)}</sheetData>"
        f'<autoFilter ref="A1:{col_name(max_cols)}{max(1, len(rows))}"/>'
        '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>'
        '</worksheet>'
    )


def cell_xml(ref: str, value, style: str) -> str:
    if value is None:
        return f'<c r="{ref}"{style}/>'
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"{style}><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return f'<c r="{ref}"{style}/>'
        return f'<c r="{ref}"{style}><v>{value}</v></c>'
    return f'<c r="{ref}" t="inlineStr"{style}><is><t>{xml(str(value))}</t></is></c>'


def col_name(index: int) -> str:
    out = ""
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )


def core_xml() -> str:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<dc:creator>dae bench</dc:creator><cp:lastModifiedBy>dae bench</cp:lastModifiedBy>'
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>'
        '</cp:coreProperties>'
    )


def app_xml(sheets) -> str:
    titles = "".join(f"<vt:lpstr>{xml(name)}</vt:lpstr>" for name, _ in sheets)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        '<Application>dae bench</Application>'
        f'<TitlesOfParts><vt:vector size="{len(sheets)}" baseType="lpstr">{titles}</vt:vector></TitlesOfParts>'
        '</Properties>'
    )


def xml(value: str) -> str:
    return escape(value, {'"': "&quot;"})


if __name__ == "__main__":
    raise SystemExit(main())
