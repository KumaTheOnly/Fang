"""
feroxbuster module — content discovery against every URL httpx confirmed
is live. Runs one feroxbuster pass per live URL (a target can have several,
e.g. both port 80 and 8080 alive) and merges the findings.
"""

from __future__ import annotations

import json
import asyncio
from pathlib import Path
from typing import Any

from core.module_base import FangModule, ModuleResult, ModuleStatus


class FeroxbusterModule(FangModule):
    name = "feroxbuster"
    depends_on = ["httpx"]

    def _should_skip(self, context: dict[str, ModuleResult]) -> str | None:
        httpx_result = context.get("httpx")
        if not httpx_result or httpx_result.status != ModuleStatus.SUCCESS:
            return "httpx did not complete successfully"
        if not httpx_result.findings:
            return "no live HTTP/S hosts confirmed by httpx"
        return None

    def _build_command(self, context: dict[str, ModuleResult]) -> list[str]:
        # feroxbuster only really supports one --url per invocation for clean
        # per-URL output, so `run()` below overrides the single-command flow
        # to loop over URLs. _build_command is kept for interface compliance
        # but isn't used directly — see run().
        raise NotImplementedError("FeroxbusterModule overrides run() directly")

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get("type") != "response":
                continue
            findings.append({
                "url": data.get("url"),
                "status_code": data.get("status"),
                "content_length": data.get("content_length"),
                "line_count": data.get("line_count"),
            })
        return findings

    async def run(self, context: dict[str, ModuleResult]) -> ModuleResult:
        import time

        skip_reason = self._should_skip(context)
        if skip_reason:
            return ModuleResult(tool=self.name, target=self.target,
                                 status=ModuleStatus.SKIPPED, error=skip_reason)

        from modules.httpx_module import HttpxModule
        httpx_result = context["httpx"]
        live_urls = HttpxModule(self.target).live_urls(httpx_result.findings)

        wordlist = self.options.get(
            "wordlist",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        )
        threads = str(self.options.get("threads", 50))

        all_findings: list[dict[str, Any]] = []
        raw_paths: list[str] = []
        start = time.monotonic()
        errors: list[str] = []

        for url in live_urls:
            safe_url = "".join(c if c.isalnum() else "_" for c in url)
            raw_path = self.output_dir / f"feroxbuster_{safe_url}.json"

            command = [
                "feroxbuster",
                "--url", url,
                "--wordlist", wordlist,
                "--threads", threads,
                "--json",
                "--silent",
                "--output", str(raw_path),
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate()

                if raw_path.exists():
                    raw_text = raw_path.read_text()
                    all_findings.extend(self._parse_output(raw_text, raw_path))
                    raw_paths.append(str(raw_path))
                elif proc.returncode != 0:
                    errors.append(f"{url}: {stderr.decode(errors='replace')[:200]}")

            except FileNotFoundError:
                return ModuleResult(
                    tool=self.name, target=self.target, status=ModuleStatus.FAILED,
                    error="'feroxbuster' not found. Is it installed and on your PATH?",
                )

        duration = time.monotonic() - start

        if not raw_paths and errors:
            return ModuleResult(
                tool=self.name, target=self.target, status=ModuleStatus.FAILED,
                duration_seconds=duration, error="; ".join(errors)[:500],
            )

        return ModuleResult(
            tool=self.name,
            target=self.target,
            status=ModuleStatus.SUCCESS,
            findings=all_findings,
            raw_output_path=", ".join(raw_paths) if raw_paths else None,
            duration_seconds=duration,
            error="; ".join(errors)[:500] if errors else None,
        )
