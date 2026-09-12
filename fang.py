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
from core.orchestrator import MultiTargetOrchestrator
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
    scan.add_argument("target", nargs="?", default=None,
                       help="Target host or IP (e.g. example.com). Optional if --scope-file is used.")
    scan.add_argument("--scope-file", default=None,
                       help="Path to a file with one target per line — scans all of them")
    scan.add_argument("--expand-scope", action="store_true",
                       help="Automatically scan subdomains discovered by subfinder too (multiplies scan time)")
    scan.add_argument("--max-concurrent", type=int, default=3,
                       help="Max number of targets scanned simultaneously (default: 3)")
    scan.add_argument("--dry-run", action="store_true",
                       help="Show what would be scanned (including scope expansion) without actually scanning")
    scan.add_argument("--confirm-above", type=int, default=10,
                       help="Ask for confirmation if --expand-scope finds more than this many new subdomains (default: 10)")
    scan.add_argument("--yes", action="store_true",
                       help="Skip the confirmation prompt (for scripts/automation)")
    scan.add_argument("--exclude", action="append", default=[],
                       help="Host to exclude from scope expansion. Repeatable: --exclude a.com --exclude b.com")
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

    # Build the base target list: the positional target (if given) plus
    # anything in --scope-file, deduplicated while preserving order.
    base_targets: list[str] = []
    if args.target:
        base_targets.append(args.target)
    if args.scope_file:
        try:
            with open(args.scope_file) as f:
                file_targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[-] Scope file not found: {args.scope_file}")
            return
        for t in file_targets:
            if t not in base_targets:
                base_targets.append(t)

    if not base_targets:
        print("[-] No targets provided. Pass a target or use --scope-file.")
        return

    excluded = set(args.exclude)

    print(BANNER)
    print("Made by yahyatahakazzi")
    print(f"[*] Targets ({len(base_targets)}): {', '.join(base_targets)}")
    print(f"[*] Pipeline: {', '.join(cls.name for cls in pipeline_modules)}")
    if args.expand_scope:
        print("[*] Scope expansion enabled — discovered subdomains will be scanned too")
    if excluded:
        print(f"[*] Excluded from expansion: {', '.join(sorted(excluded))}")
    if run_sqlmap:
        print("[!] sqlmap enabled — this is invasive. Only use against authorized targets.")

    # --dry-run without --expand-scope: nothing to discover, just show the
    # base list and stop. Cheap and immediate.
    if args.dry_run and not args.expand_scope:
        print("\n[*] DRY RUN — the following would be scanned:")
        for t in base_targets:
            print(f"    {t}")
        print(f"\n[*] Total: {len(base_targets)} target(s). Re-run without --dry-run to scan.")
        return

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

    if args.dry_run:
        # --dry-run WITH --expand-scope: we still need subfinder's actual
        # output to know what expansion would scan, so run just that one
        # module (cheap and fast) rather than the full pipeline.
        print("[*] DRY RUN — running subfinder only to preview scope expansion...")
        discovery = MultiTargetOrchestrator(base_targets, [SubfinderModule], {"subfinder": {}},
                                             max_concurrent=args.max_concurrent)
        discovery_results = await discovery.run()

        discovered: set[str] = set()
        for target, module_results in discovery_results.items():
            sf = module_results.get("subfinder")
            if sf and sf.status.value == "success":
                for finding in sf.findings:
                    sub = finding.get("subdomain")
                    if sub and sub not in base_targets and sub not in excluded:
                        discovered.add(sub)

        print(f"\n[*] DRY RUN — base targets ({len(base_targets)}):")
        for t in base_targets:
            print(f"    {t}")
        print(f"\n[*] DRY RUN — would additionally discover & scan ({len(discovered)}):")
        for t in sorted(discovered):
            print(f"    {t}")
        total = len(base_targets) + len(discovered)
        print(f"\n[*] Total if run for real: {total} target(s). Re-run without --dry-run to scan.")
        return

    orchestrator = MultiTargetOrchestrator(base_targets, pipeline_modules, options,
                                            max_concurrent=args.max_concurrent)
    results = await orchestrator.run()

    # Scope expansion: pull subdomains subfinder found for each base target,
    # and scan those too — as a second orchestrator pass so we don't block
    # the first pass waiting on discoveries that might not even happen.
    if args.expand_scope:
        discovered: set[str] = set()
        for target, module_results in results.items():
            subfinder_result = module_results.get("subfinder")
            if subfinder_result and subfinder_result.status.value == "success":
                for finding in subfinder_result.findings:
                    sub = finding.get("subdomain")
                    if sub and sub not in base_targets and sub not in excluded:
                        discovered.add(sub)

        if discovered:
            if len(discovered) > args.confirm_above and not args.yes:
                # Estimate time from what the base scan just took.
                base_durations = [
                    r.duration_seconds
                    for module_results in results.values()
                    for r in module_results.values()
                ]
                avg_per_target = (sum(base_durations) / max(len(base_targets), 1))
                # Account for the max_concurrent bound — targets run in batches.
                batches = (len(discovered) + args.max_concurrent - 1) // args.max_concurrent
                est_seconds = batches * (avg_per_target / max(args.max_concurrent, 1)) * args.max_concurrent
                est_minutes = est_seconds / 60

                print(f"[!] Scope expansion found {len(discovered)} new subdomain(s) — "
                      f"more than your --confirm-above threshold of {args.confirm_above}.")
                print(f"[!] Estimated additional time: ~{est_minutes:.0f} minute(s) "
                      f"(at --max-concurrent {args.max_concurrent})")
                answer = input("[?] Continue scanning all of them? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    print("[-] Scope expansion cancelled. Base target results are still in the report.")
                    discovered = set()

        if discovered:
            print(f"[*] Scope expansion: scanning {len(discovered)} new subdomain(s)...")
            expansion = MultiTargetOrchestrator(sorted(discovered), pipeline_modules, options,
                                                 max_concurrent=args.max_concurrent)
            expansion_results = await expansion.run()
            results.update(expansion_results)
            orchestrator.targets = orchestrator.targets + expansion.targets
        else:
            print("[*] Scope expansion: no new subdomains to scan")

    orchestrator.results = results

    print()
    for target, module_results in results.items():
        print(f"== {target} ==")
        for name, result in module_results.items():
            status_marker = {"success": "[+]", "failed": "[-]", "skipped": "[~]"}.get(result.status.value, "[?]")
            print(f"{status_marker} {name}: {result.status.value} "
                  f"({len(result.findings)} findings, {result.duration_seconds:.1f}s)")
            if result.error:
                print(f"    -> {result.error}")
        print()

    duplicates = {ip: hosts for ip, hosts in orchestrator.group_by_ip().items()
                  if ip != "unresolved" and len(hosts) > 1}
    if duplicates:
        print("[*] Duplicate infrastructure detected (same IP, likely the same server):")
        for ip, hosts in duplicates.items():
            print(f"    {ip}: {', '.join(hosts)}")
        print()

    report_name = args.target if args.target else "scope"
    output_path = Path(args.output) if args.output else Path("output") / f"{report_name}_report.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(orchestrator.summary(), indent=2))
    print(f"[*] Full report written to {output_path}")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(run_scan(args))


if __name__ == "__main__":
    main()
