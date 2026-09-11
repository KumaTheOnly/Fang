#!/usr/bin/env python3
"""
Fang — recon/orchestration tool combining nmap, httpx, feroxbuster (and more
to come) into one pipeline.

Usage:
    python3 fang.py scan <target>
    python3 fang.py scan <target> --ports 1-65535 --threads 100
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from core.pipeline import Pipeline
from modules.nmap_module import NmapModule
from modules.httpx_module import HttpxModule
from modules.feroxbuster_module import FeroxbusterModule
from modules.subfinder_module import SubfinderModule
from modules.nuclei_module import NucleiModule
from modules.whatweb_module import WhatwebModule
from modules.ffuf_module import FfufModule
from modules.sqlmap_module import SqlmapModule

BANNER = r"""
  ____
 / __/____ _____  ____ _
/ /_ / __ `/ __ \/ __ `/
/ __// /_/ / / / / /_/ /
/_/   \__,_/_/ /_/\__, /
                 /____/
"""

# Default pipeline. nmap and subfinder have no dependencies and run first,
# concurrently. httpx runs once nmap finishes. feroxbuster, nuclei, whatweb,
# and ffuf all depend only on httpx, so they run concurrently with each
# other once httpx finishes.
DEFAULT_PIPELINE = [
    NmapModule,
    SubfinderModule,
    HttpxModule,
    FeroxbusterModule,
    NucleiModule,
    WhatwebModule,
    FfufModule,
]

# sqlmap is opt-in only (--sqlmap flag) since it's invasive — never runs
# as part of the default pipeline.


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fang", description="Fang recon orchestrator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run the default pipeline against a target")
    scan.add_argument("target", help="Target host or IP (e.g. example.com)")
    scan.add_argument("--ports", default="1-1000", help="nmap port range (default: 1-1000)")
    scan.add_argument("--wordlist", default=None,
                       help="Override feroxbuster wordlist path (default: raft-medium-directories.txt)")
    scan.add_argument("--threads", type=int, default=50, help="feroxbuster/ffuf thread count (default: 50)")
    scan.add_argument("--output", default=None, help="Path to write the JSON report (default: output/<target>_report.json)")
    scan.add_argument("--severity", default="low,medium,high,critical",
                       help="nuclei severity filter (default: low,medium,high,critical)")
    scan.add_argument("--sqlmap", action="store_true",
                       help="Also run sqlmap against the first live URL (opt-in, invasive)")
    scan.add_argument("--sqlmap-url", default=None,
                       help="Specific URL for sqlmap to test (implies --sqlmap)")

    return parser


async def run_scan(args: argparse.Namespace) -> None:
    pipeline_modules = list(DEFAULT_PIPELINE)
    run_sqlmap = args.sqlmap or bool(args.sqlmap_url)
    if run_sqlmap:
        pipeline_modules.append(SqlmapModule)

    print(BANNER)
    print("Made by yahyatahakazzi")
    print(f"[*] Target: {args.target}")
    print(f"[*] Pipeline: {', '.join(cls.name for cls in pipeline_modules)}")
    if run_sqlmap:
        print("[!] sqlmap enabled — this is invasive. Only use against authorized targets.")
    print()

    options = {
        "nmap": {"ports": args.ports},
        "subfinder": {},
        "httpx": {},
        "feroxbuster": {
            "threads": args.threads,
            **({"wordlist": args.wordlist} if args.wordlist else {}),
        },
        "nuclei": {"severity": args.severity},
        "whatweb": {},
        "ffuf": {"threads": args.threads},
        "sqlmap": {**({"url": args.sqlmap_url} if args.sqlmap_url else {})},
    }

    pipeline = Pipeline(args.target, pipeline_modules, options)
    results = await pipeline.run()

    for name, result in results.items():
        status_marker = {"success": "[+]", "failed": "[-]", "skipped": "[~]"}.get(result.status.value, "[?]")
        print(f"{status_marker} {name}: {result.status.value} "
              f"({len(result.findings)} findings, {result.duration_seconds:.1f}s)")
        if result.error:
            print(f"    -> {result.error}")

    output_path = Path(args.output) if args.output else Path("output") / f"{args.target}_report.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(pipeline.summary(), indent=2))
    print(f"\n[*] Full report written to {output_path}")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()
