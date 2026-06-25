"""Read ScanCode input and generate JSON, CSV, and HTML reports."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

try:
    from .scancode_core import merge_policy, normalize_scan
except ImportError:
    from scancode_core import merge_policy, normalize_scan


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read JSON from {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def load_policy(path: Path | None) -> dict[str, Any]:
    return merge_policy(read_json(path) if path else None)


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def write_findings_csv(path: Path, report: dict[str, Any]) -> None:
    fields = [
        "status",
        "component",
        "path",
        "license_expressions",
        "copyrights",
        "holders",
        "package_refs",
        "scan_errors",
        "reasons",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for finding in report["findings"]:
            writer.writerow(
                {
                    field: "; ".join(finding[field])
                    if isinstance(finding[field], list)
                    else finding[field]
                    for field in fields
                }
            )


def write_components_csv(path: Path, report: dict[str, Any]) -> None:
    fields = [
        "component",
        "files_with_evidence",
        "licenses",
        "pass",
        "review",
        "fail",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for component, item in report["components"].items():
            writer.writerow(
                {
                    "component": component,
                    "files_with_evidence": item["files_with_evidence"],
                    "licenses": "; ".join(item["licenses"]),
                    "pass": item["pass"],
                    "review": item["review"],
                    "fail": item["fail"],
                }
            )


def badge(status: str) -> str:
    return f'<span class="badge {html.escape(status)}">{html.escape(status.upper())}</span>'


def write_html(path: Path, report: dict[str, Any]) -> None:
    count = report["counts"]
    component_rows = "".join(
        "<tr>"
        f"<td>{html.escape(name)}</td>"
        f"<td>{item['files_with_evidence']}</td>"
        f"<td>{html.escape(', '.join(item['licenses']) or 'No expression')}</td>"
        f"<td>{item['pass']}</td><td>{item['review']}</td><td>{item['fail']}</td>"
        "</tr>"
        for name, item in report["components"].items()
    )
    finding_rows = "".join(
        "<tr>"
        f"<td>{badge(item['status'])}</td>"
        f"<td>{html.escape(item['component'])}</td>"
        f"<td><code>{html.escape(item['path'])}</code></td>"
        f"<td>{html.escape(', '.join(item['license_expressions']) or 'None')}</td>"
        f"<td>{html.escape('; '.join(item['reasons']) or 'Evidence only')}</td>"
        "</tr>"
        for item in report["findings"]
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanCode License Evidence Report</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#667085; --line:#d0d5dd;
  --panel:#f8fafc; --accent:#175cd3; --pass:#067647; --review:#b54708; --fail:#b42318; }}
body {{ font: 14px/1.5 Arial, sans-serif; color:var(--ink); margin:0; background:#eef2f6; }}
main {{ max-width:1180px; margin:32px auto; background:white; padding:32px; border-radius:12px; }}
h1 {{ margin:0 0 6px; font-size:28px; }} h2 {{ margin-top:32px; }}
.subtitle {{ color:var(--muted); }} .notice {{ border-left:4px solid var(--review);
  background:#fffaeb; padding:12px 16px; margin:22px 0; }}
.cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:24px 0; }}
.card {{ background:var(--panel); border:1px solid var(--line); padding:14px; border-radius:8px; }}
.value {{ font-size:24px; font-weight:700; }} .label {{ color:var(--muted); }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
th,td {{ border-bottom:1px solid var(--line); padding:10px; text-align:left; vertical-align:top; }}
th {{ background:var(--panel); }} code {{ overflow-wrap:anywhere; }}
.badge {{ display:inline-block; color:white; font-weight:700; padding:2px 8px; border-radius:999px; }}
.badge.pass {{ background:var(--pass); }} .badge.review {{ background:var(--review); }}
.badge.fail {{ background:var(--fail); }}
@media (max-width:800px) {{ main {{ margin:0; padding:18px; }} .cards {{ grid-template-columns:1fr 1fr; }}
  table {{ display:block; overflow-x:auto; }} }}
</style>
</head>
<body><main>
<h1>ScanCode License Evidence Report</h1>
<div class="subtitle">Generated {html.escape(report['generated_at'])} | Gate {badge(report['gate'])}</div>
<div class="notice"><strong>Scope:</strong> {html.escape(report['notice'])}</div>
<section class="cards">
<div class="card"><div class="value">{count['scanned_files']}</div><div class="label">Scanned files</div></div>
<div class="card"><div class="value">{count['files_with_evidence']}</div><div class="label">Evidence files</div></div>
<div class="card"><div class="value">{count['components']}</div><div class="label">Components/areas</div></div>
<div class="card"><div class="value">{count['review']}</div><div class="label">Review</div></div>
<div class="card"><div class="value">{count['fail']}</div><div class="label">Failed</div></div>
</section>
<h2>Component Summary</h2>
<table><thead><tr><th>Component/area</th><th>Files</th><th>Licenses</th>
<th>Pass</th><th>Review</th><th>Fail</th></tr></thead><tbody>{component_rows}</tbody></table>
<h2>File Findings</h2>
<table><thead><tr><th>Status</th><th>Component/area</th><th>Path</th>
<th>License expressions</th><th>Reason</th></tr></thead><tbody>{finding_rows}</tbody></table>
</main></body></html>"""
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(document)


def generate_reports(
    input_path: Path,
    output_dir: Path,
    policy_path: Path | None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report = normalize_scan(read_json(input_path), load_policy(policy_path))
    write_json(output_dir / "summary.json", report)
    write_findings_csv(output_dir / "findings.csv", report)
    write_components_csv(output_dir / "components.csv", report)
    write_html(output_dir / "report.html", report)
    return report
