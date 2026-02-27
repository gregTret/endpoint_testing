"""
Upload Test Report Generator — Produces structured reports from test results.

Supports three output formats:
  - console: Rich table printed to stdout
  - json: Structured JSON file
  - html: Self-contained HTML report

Usage:
    from report import generate_report
    generate_report(results, fmt="console", output_path="report.json")
"""

from __future__ import annotations

import html as html_mod
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# High-risk categories — accepted files from these are dangerous
HIGH_RISK_CATEGORIES = {
    "Webshell", "Python Execution", "Out-of-Band", "Path Traversal",
}

MEDIUM_RISK_CATEGORIES = {
    "Polyglot", "SVG", "SVG (React/Flask)", "MIME Mismatch",
    "Filename Injection", "Extension Bypass",
}


# ── Analysis helpers ──────────────────────────────────────────────────────────


def _summarize(results: list[dict]) -> dict:
    """Build a summary from the test results."""
    total = len(results)
    by_result = Counter(r["result"] for r in results)
    by_category = defaultdict(lambda: Counter())
    by_endpoint = defaultdict(list)
    dangerous_accepted = []

    for r in results:
        by_category[r["preset_category"]][r["result"]] += 1
        by_endpoint[r["endpoint_url"]].append(r)

        if r["result"] == "accepted":
            cat = r["preset_category"]
            if cat in HIGH_RISK_CATEGORIES:
                dangerous_accepted.append({**r, "risk": "HIGH"})
            elif cat in MEDIUM_RISK_CATEGORIES:
                dangerous_accepted.append({**r, "risk": "MEDIUM"})

    # Sort dangerous findings by risk (HIGH first)
    dangerous_accepted.sort(key=lambda x: (0 if x["risk"] == "HIGH" else 1, x["preset_category"]))

    return {
        "total": total,
        "accepted": by_result.get("accepted", 0),
        "rejected": by_result.get("rejected", 0),
        "error": by_result.get("error", 0),
        "uncertain": by_result.get("uncertain", 0),
        "by_category": {cat: dict(counts) for cat, counts in sorted(by_category.items())},
        "by_endpoint": {url: rs for url, rs in sorted(by_endpoint.items())},
        "dangerous_accepted": dangerous_accepted,
    }


# ── Console (Rich) output ────────────────────────────────────────────────────


def _report_console(results: list[dict]):
    """Print a rich table report to stdout."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    console = Console()
    summary = _summarize(results)

    # Header
    console.print()
    console.print(Panel.fit(
        "[bold]Upload Security Test Report[/bold]",
        subtitle=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    ))

    # Summary
    summary_table = Table(title="Summary", show_header=False, box=None, padding=(0, 2))
    summary_table.add_column(style="bold")
    summary_table.add_column(justify="right")
    summary_table.add_row("Total Tests", str(summary["total"]))
    summary_table.add_row("Accepted", f"[green]{summary['accepted']}[/green]" if summary["accepted"] == 0 else f"[red bold]{summary['accepted']}[/red bold]")
    summary_table.add_row("Rejected", f"[green]{summary['rejected']}[/green]")
    summary_table.add_row("Errors", f"[yellow]{summary['error']}[/yellow]")
    summary_table.add_row("Uncertain", f"[dim]{summary['uncertain']}[/dim]")
    console.print(summary_table)
    console.print()

    # Dangerous findings
    if summary["dangerous_accepted"]:
        console.print("[red bold]⚠ DANGEROUS FILES ACCEPTED[/red bold]")
        danger_table = Table(show_lines=True)
        danger_table.add_column("Risk", width=6)
        danger_table.add_column("Category", width=20)
        danger_table.add_column("Preset", width=30)
        danger_table.add_column("Filename", width=25)
        danger_table.add_column("Status", width=6, justify="center")
        danger_table.add_column("Details", width=40)

        for d in summary["dangerous_accepted"]:
            risk_style = "red bold" if d["risk"] == "HIGH" else "yellow"
            danger_table.add_row(
                Text(d["risk"], style=risk_style),
                d["preset_category"],
                d["preset_name"],
                d["filename"][:25],
                str(d["status_code"]),
                d["details"][:40],
            )
        console.print(danger_table)
        console.print()
    else:
        console.print("[green]No dangerous files were accepted.[/green]")
        console.print()

    # Per-category breakdown
    cat_table = Table(title="Results by Category")
    cat_table.add_column("Category", width=25)
    cat_table.add_column("Accepted", justify="right", width=10)
    cat_table.add_column("Rejected", justify="right", width=10)
    cat_table.add_column("Error", justify="right", width=10)
    cat_table.add_column("Uncertain", justify="right", width=10)

    for cat, counts in summary["by_category"].items():
        accepted = counts.get("accepted", 0)
        cat_table.add_row(
            cat,
            f"[red]{accepted}[/red]" if accepted > 0 else "0",
            str(counts.get("rejected", 0)),
            str(counts.get("error", 0)),
            str(counts.get("uncertain", 0)),
        )
    console.print(cat_table)
    console.print()

    # Full results table
    full_table = Table(title="All Test Results", show_lines=False)
    full_table.add_column("#", width=4, justify="right")
    full_table.add_column("Result", width=10)
    full_table.add_column("Status", width=6, justify="center")
    full_table.add_column("Category", width=20)
    full_table.add_column("Preset", width=28)
    full_table.add_column("Filename", width=22)
    full_table.add_column("Details", width=35)

    result_styles = {
        "accepted": "red",
        "rejected": "green",
        "error": "yellow",
        "uncertain": "dim",
    }

    for i, r in enumerate(results, 1):
        style = result_styles.get(r["result"], "")
        full_table.add_row(
            str(i),
            Text(r["result"].upper(), style=style),
            str(r["status_code"]),
            r["preset_category"],
            r["preset_name"][:28],
            r["filename"][:22] if r["filename"] else "(empty)",
            r["details"][:35],
        )
    console.print(full_table)
    console.print()


# ── JSON output ───────────────────────────────────────────────────────────────


def _report_json(results: list[dict], output_path: str):
    """Write a JSON report to a file."""
    summary = _summarize(results)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": summary["total"],
            "accepted": summary["accepted"],
            "rejected": summary["rejected"],
            "error": summary["error"],
            "uncertain": summary["uncertain"],
        },
        "risk_assessment": {
            "dangerous_accepted_count": len(summary["dangerous_accepted"]),
            "findings": summary["dangerous_accepted"],
        },
        "by_category": summary["by_category"],
        "results": results,
    }

    Path(output_path).write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )


# ── HTML output ───────────────────────────────────────────────────────────────


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html_mod.escape(str(text)) if text else ""


def _report_html(results: list[dict], output_path: str):
    """Write a self-contained HTML report."""
    summary = _summarize(results)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    result_colors = {
        "accepted": "#f85149",
        "rejected": "#3fb950",
        "error": "#d29922",
        "uncertain": "#8b949e",
    }

    # Build dangerous findings rows
    danger_rows = ""
    for d in summary["dangerous_accepted"]:
        risk_color = "#f85149" if d["risk"] == "HIGH" else "#d29922"
        danger_rows += f"""<tr>
            <td style="color:{risk_color};font-weight:bold">{_esc(d['risk'])}</td>
            <td>{_esc(d['preset_category'])}</td>
            <td>{_esc(d['preset_name'])}</td>
            <td><code>{_esc(d['filename'][:40])}</code></td>
            <td>{d['status_code']}</td>
            <td>{_esc(d['details'][:60])}</td>
        </tr>\n"""

    # Build category rows
    cat_rows = ""
    for cat, counts in summary["by_category"].items():
        accepted = counts.get("accepted", 0)
        acc_style = "color:#f85149;font-weight:bold" if accepted > 0 else ""
        cat_rows += f"""<tr>
            <td>{_esc(cat)}</td>
            <td style="{acc_style}">{accepted}</td>
            <td>{counts.get('rejected', 0)}</td>
            <td>{counts.get('error', 0)}</td>
            <td>{counts.get('uncertain', 0)}</td>
        </tr>\n"""

    # Build all results rows
    all_rows = ""
    for i, r in enumerate(results, 1):
        color = result_colors.get(r["result"], "#8b949e")
        all_rows += f"""<tr>
            <td>{i}</td>
            <td style="color:{color};font-weight:bold">{_esc(r['result'].upper())}</td>
            <td>{r['status_code']}</td>
            <td>{_esc(r['preset_category'])}</td>
            <td>{_esc(r['preset_name'])}</td>
            <td><code>{_esc(r['filename'][:30]) if r['filename'] else '(empty)'}</code></td>
            <td>{_esc(r['details'][:60])}</td>
        </tr>\n"""

    danger_section = ""
    if summary["dangerous_accepted"]:
        danger_section = f"""
        <h2 style="color:#f85149">Dangerous Files Accepted</h2>
        <table>
            <thead><tr>
                <th>Risk</th><th>Category</th><th>Preset</th>
                <th>Filename</th><th>Status</th><th>Details</th>
            </tr></thead>
            <tbody>{danger_rows}</tbody>
        </table>
        """
    else:
        danger_section = '<p style="color:#3fb950;font-weight:bold">No dangerous files were accepted.</p>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Upload Security Test Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
           background: #0d1117; color: #c9d1d9; padding: 24px; line-height: 1.5; }}
    h1 {{ color: #58a6ff; margin-bottom: 4px; }}
    h2 {{ color: #c9d1d9; margin: 24px 0 12px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
    .subtitle {{ color: #8b949e; margin-bottom: 24px; }}
    .summary {{ display: flex; gap: 24px; margin-bottom: 24px; flex-wrap: wrap; }}
    .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                     padding: 16px 24px; min-width: 120px; }}
    .summary-card .label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; }}
    .summary-card .value {{ font-size: 28px; font-weight: bold; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
    th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }}
    th {{ background: #161b22; color: #8b949e; font-size: 12px; text-transform: uppercase;
         position: sticky; top: 0; }}
    tr:hover {{ background: #161b22; }}
    code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
</style>
</head>
<body>
    <h1>Upload Security Test Report</h1>
    <p class="subtitle">Generated {ts}</p>

    <div class="summary">
        <div class="summary-card">
            <div class="label">Total Tests</div>
            <div class="value">{summary['total']}</div>
        </div>
        <div class="summary-card">
            <div class="label">Accepted</div>
            <div class="value" style="color:{'#f85149' if summary['accepted'] > 0 else '#3fb950'}">{summary['accepted']}</div>
        </div>
        <div class="summary-card">
            <div class="label">Rejected</div>
            <div class="value" style="color:#3fb950">{summary['rejected']}</div>
        </div>
        <div class="summary-card">
            <div class="label">Errors</div>
            <div class="value" style="color:#d29922">{summary['error']}</div>
        </div>
        <div class="summary-card">
            <div class="label">Uncertain</div>
            <div class="value" style="color:#8b949e">{summary['uncertain']}</div>
        </div>
    </div>

    {danger_section}

    <h2>Results by Category</h2>
    <table>
        <thead><tr>
            <th>Category</th><th>Accepted</th><th>Rejected</th><th>Error</th><th>Uncertain</th>
        </tr></thead>
        <tbody>{cat_rows}</tbody>
    </table>

    <h2>All Test Results</h2>
    <table>
        <thead><tr>
            <th>#</th><th>Result</th><th>Status</th><th>Category</th>
            <th>Preset</th><th>Filename</th><th>Details</th>
        </tr></thead>
        <tbody>{all_rows}</tbody>
    </table>
</body>
</html>"""

    Path(output_path).write_text(html_content, encoding="utf-8")


# ── Public API ────────────────────────────────────────────────────────────────


def generate_report(
    results: list[dict],
    fmt: str = "console",
    output_path: Optional[str] = None,
):
    """Generate a test report in the specified format.

    Args:
        results: List of test result dicts from tester.run_tests().
        fmt: Output format — "console", "json", or "html".
        output_path: File path for json/html output. Ignored for console.
    """
    if not results:
        print("[info] No test results to report.")
        return

    if fmt == "console":
        _report_console(results)
    elif fmt == "json":
        path = output_path or "upload_report.json"
        _report_json(results, path)
        print(f"[report] JSON report saved to: {path}")
    elif fmt == "html":
        path = output_path or "upload_report.html"
        _report_html(results, path)
        print(f"[report] HTML report saved to: {path}")
    else:
        print(f"[error] Unknown format: {fmt}")
