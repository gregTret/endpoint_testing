"""
Upload Tester — CLI entry point for the file upload security testing toolkit.

Workflow:
    1. Record traffic:   python main.py record --port 8888 --output capture.json
       Point your browser's proxy to 127.0.0.1:8888 and perform a normal file
       upload on the target application. Press Ctrl+C when done.

    2. Analyze capture:  python main.py analyze --input capture.json --output profile.json
       Identifies upload endpoints, extracts auth/CSRF prerequisites, and
       produces a structured profile for the tester.

    3. Run tests:        python main.py test --profile profile.json --format console
       Replays the upload with all malicious presets (webshells, polyglots,
       SVG XSS, path traversal filenames, etc.) and classifies each response.

    4. Auto (2+3):       python main.py auto --input capture.json --format console
       Runs analyze then test in sequence.

Each step is independent — you can re-run test with different options without
re-recording. Profiles are plain JSON and can be hand-edited.

Requirements: pip install -r requirements.txt  (httpx, mitmproxy, rich)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path


def _setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(name)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


# ── Subcommands ───────────────────────────────────────────────────────────────


def cmd_record(args):
    """Start the mitmproxy recorder."""
    _setup_logging(args.verbose)

    # Import here to avoid requiring mitmproxy for other subcommands
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    from recorder import UploadRecorder

    async def run():
        opts = Options(listen_host="127.0.0.1", listen_port=args.port)
        master = DumpMaster(opts)

        recorder = UploadRecorder()
        master.addons.add(recorder)
        # Set _output_path AFTER addons.add() — the mitmproxy lifecycle calls
        # configure() during add(), which resets _output_path to the default.
        recorder._output_path = args.output

        print(f"[record] Proxy listening on 127.0.0.1:{args.port}")
        print(f"[record] Saving traffic to {args.output}")
        print("[record] Perform your file upload, then press Ctrl+C to stop.")

        try:
            await master.run()
        except KeyboardInterrupt:
            pass
        finally:
            master.shutdown()

    asyncio.run(run())


def cmd_analyze(args):
    """Run the upload analyzer."""
    _setup_logging(args.verbose)

    if not Path(args.input).exists():
        print(f"[error] Capture file not found: {args.input}")
        sys.exit(1)

    from analyzer import analyze, _print_summary

    result = analyze(args.input)

    Path(args.output).write_text(
        json.dumps(result, indent=2, default=str),
        encoding="utf-8",
    )

    _print_summary(result)
    print(f"  Profile saved to: {args.output}")
    print()


def cmd_test(args):
    """Run the upload tester."""
    _setup_logging(args.verbose)

    if not Path(args.profile).exists():
        print(f"[error] Profile file not found: {args.profile}")
        sys.exit(1)

    from tester import run_tests
    from report import generate_report

    # Parse categories
    categories = None
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",") if c.strip()]

    # Progress callback
    completed = [0]
    def on_result(result):
        completed[0] += 1
        status = result["result"].upper()
        preset = result["preset_name"][:30]
        code = result["status_code"]
        print(f"  [{completed[0]:>3}] {status:<10} HTTP {code:<3}  {preset}")

    print(f"[test] Loading profile: {args.profile}")
    print(f"[test] Concurrency: {args.concurrency}, Delay: {args.delay}s")
    if categories:
        print(f"[test] Categories: {', '.join(categories)}")
    if args.callback_url:
        print(f"[test] OOB callback: {args.callback_url}")
    print()

    results = asyncio.run(run_tests(
        profile_path=args.profile,
        concurrency=args.concurrency,
        delay=args.delay,
        categories=categories,
        callback_url=args.callback_url,
        on_result=on_result,
    ))

    print()

    # Generate report
    generate_report(
        results,
        fmt=args.format,
        output_path=args.output,
    )

    # Always save raw results JSON alongside any report
    if args.output and args.format != "json":
        raw_path = str(Path(args.output).with_suffix(".results.json"))
        Path(raw_path).write_text(
            json.dumps(results, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"[test] Raw results saved to: {raw_path}")


def cmd_auto(args):
    """Run analyze + test in sequence."""
    _setup_logging(args.verbose)

    if not Path(args.input).exists():
        print(f"[error] Capture file not found: {args.input}")
        sys.exit(1)

    # Step 1: Analyze
    from analyzer import analyze, _print_summary

    print("[auto] Step 1/2: Analyzing capture...")
    result = analyze(args.input)

    profile_path = str(Path(args.input).with_suffix(".profile.json"))
    Path(profile_path).write_text(
        json.dumps(result, indent=2, default=str),
        encoding="utf-8",
    )
    _print_summary(result)

    profiles = result.get("profiles", [])
    if not profiles:
        print("[auto] No upload endpoints found. Nothing to test.")
        return

    # Step 2: Test
    from tester import run_tests
    from report import generate_report

    categories = None
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",") if c.strip()]

    completed = [0]
    def on_result(r):
        completed[0] += 1
        status = r["result"].upper()
        preset = r["preset_name"][:30]
        code = r["status_code"]
        print(f"  [{completed[0]:>3}] {status:<10} HTTP {code:<3}  {preset}")

    print(f"[auto] Step 2/2: Testing {len(profiles)} endpoint(s)...")
    print()

    results = asyncio.run(run_tests(
        profile_path=profile_path,
        concurrency=args.concurrency,
        delay=args.delay,
        categories=categories,
        callback_url=args.callback_url,
        on_result=on_result,
    ))

    print()

    fmt = args.format
    output = args.output

    generate_report(results, fmt=fmt, output_path=output)

    if output and fmt != "json":
        raw_path = str(Path(output).with_suffix(".results.json"))
        Path(raw_path).write_text(
            json.dumps(results, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"[auto] Raw results saved to: {raw_path}")


# ── Argument parser ───────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="upload-tester",
        description="File upload security testing toolkit. "
                    "Record > Analyze > Test > Report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
workflow:
  1. record  -- Start a proxy, browse the target, perform a file upload.
  2. analyze -- Parse the capture to find upload endpoints and prerequisites.
  3. test    -- Replay the upload with malicious presets and generate a report.
  4. auto    -- Run analyze + test in one step.

examples:
  python main.py record --port 8888 --output capture.json
  python main.py analyze --input capture.json --output profile.json
  python main.py test --profile profile.json --format html --output report.html
  python main.py auto --input capture.json --concurrency 5 --format console
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- record ----------------------------------------------------------------
    p_record = subparsers.add_parser(
        "record",
        help="Start the mitmproxy recorder to capture upload traffic",
    )
    p_record.add_argument(
        "--port", type=int, default=8888,
        help="Proxy listen port (default: 8888)",
    )
    p_record.add_argument(
        "--output", "-o", type=str, default="capture.json",
        help="Output file for captured flows (default: capture.json)",
    )
    p_record.add_argument("--verbose", "-v", action="store_true")
    p_record.set_defaults(func=cmd_record)

    # -- analyze ---------------------------------------------------------------
    p_analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a capture file to produce upload test profiles",
    )
    p_analyze.add_argument(
        "--input", "-i", type=str, default="capture.json",
        help="Path to the recorder capture file (default: capture.json)",
    )
    p_analyze.add_argument(
        "--output", "-o", type=str, default="upload_profile.json",
        help="Output path for the upload profile (default: upload_profile.json)",
    )
    p_analyze.add_argument("--verbose", "-v", action="store_true")
    p_analyze.set_defaults(func=cmd_analyze)

    # -- test ------------------------------------------------------------------
    p_test = subparsers.add_parser(
        "test",
        help="Run upload tests using a profile and malicious presets",
    )
    p_test.add_argument(
        "--profile", "-p", type=str, required=True,
        help="Path to the upload profile JSON (from analyze)",
    )
    p_test.add_argument(
        "--concurrency", "-c", type=int, default=3,
        help="Max concurrent requests (default: 3)",
    )
    p_test.add_argument(
        "--delay", "-d", type=float, default=0.5,
        help="Delay in seconds between requests (default: 0.5)",
    )
    p_test.add_argument(
        "--categories", type=str, default=None,
        help="Comma-separated preset categories to test (default: all)",
    )
    p_test.add_argument(
        "--callback-url", type=str, default=None,
        help="OOB callback URL for {{CALLBACK}} replacement in presets",
    )
    p_test.add_argument(
        "--format", "-f", type=str, default="console",
        choices=["console", "json", "html"],
        help="Report format (default: console)",
    )
    p_test.add_argument(
        "--output", "-o", type=str, default=None,
        help="Output file for json/html report",
    )
    p_test.add_argument("--verbose", "-v", action="store_true")
    p_test.set_defaults(func=cmd_test)

    # -- auto ------------------------------------------------------------------
    p_auto = subparsers.add_parser(
        "auto",
        help="Analyze capture + run tests in one step",
    )
    p_auto.add_argument(
        "--input", "-i", type=str, default="capture.json",
        help="Path to the recorder capture file (default: capture.json)",
    )
    p_auto.add_argument(
        "--concurrency", "-c", type=int, default=3,
        help="Max concurrent requests (default: 3)",
    )
    p_auto.add_argument(
        "--delay", "-d", type=float, default=0.5,
        help="Delay in seconds between requests (default: 0.5)",
    )
    p_auto.add_argument(
        "--categories", type=str, default=None,
        help="Comma-separated preset categories to test (default: all)",
    )
    p_auto.add_argument(
        "--callback-url", type=str, default=None,
        help="OOB callback URL for {{CALLBACK}} replacement in presets",
    )
    p_auto.add_argument(
        "--format", "-f", type=str, default="console",
        choices=["console", "json", "html"],
        help="Report format (default: console)",
    )
    p_auto.add_argument(
        "--output", "-o", type=str, default=None,
        help="Output file for json/html report",
    )
    p_auto.add_argument("--verbose", "-v", action="store_true")
    p_auto.set_defaults(func=cmd_auto)

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
