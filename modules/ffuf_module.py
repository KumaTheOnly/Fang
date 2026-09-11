"""
ffuf module — parameter fuzzing against every URL httpx confirmed is
live. Complements feroxbuster: feroxbuster finds hidden paths, ffuf finds
hidden GET parameters on the paths that already exist (huge for bug
bounty since unexpected params are often where the interesting bugs hide).
"""

from __future__ import annotations

import json
import asyncio
import time
from pathlib import Path
from typing import Any

from core.module_base import FangModule, ModuleResult, ModuleStatus


class FfufModule(FangModule):
    name = "ffuf"
    depends_on = ["httpx"]

    def _should_skip(self, context: dict[str, ModuleResult]) -> str | None:
        httpx_result = context.get("httpx")
        if not httpx_result or httpx_result.status != ModuleStatus.SUCCESS:
            return "httpx did not complete successfully"
        if not httpx_result.findings:
            return "no live HTTP/S hosts confirmed by httpx"
        return None

    def _build_command(self, context: dict[str, Any]) -> list[str]:
        # ffuf, like feroxbuster, runs once per live URL — see run() override below.
        raise NotImplementedError("FfufModule overrides run() directly")

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            findings.append({
                "url": result.get("url"),
                "input": result.get("input", {}),
                "status_code": result.get("status"),
                "length": result.get("length"),
            })
        return findings

    async def run(self, context: dict[str, ModuleResult]) -> ModuleResult:
        skip_reason = self._should_skip(context)
        if skip_reason:
            return ModuleResult(tool=self.name, target=self.target,
                                 status=ModuleStatus.SKIPPED, error=skip_reason)

        from modules.httpx_module import HttpxModule
        httpx_result = context["httpx"]
        live_urls = HttpxModule(self.target).live_urls(httpx_result.findings)

        wordlist = self.options.get(
            "wordlist",
            "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        )
        threads = str(self.options.get("threads", 40))

        all_findings: list[dict[str, Any]] = []
        raw_paths: list[str] = []
        start = time.monotonic()
        errors: list[str] = []

        for url in live_urls:
            safe_url = "".join(c if c.isalnum() else "_" for c in url)
            raw_path = self.output_dir / f"ffuf_{safe_url}.json"
            fuzz_url = f"{url.rstrip('/')}/?FUZZ=test"

            command = [
                "ffuf",
                "-u", fuzz_url,
                "-w", wordlist,
                "-t", threads,
                "-of", "json",
                "-o", str(raw_path),
                "-s",  # silent
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
                    error="'ffuf' not found. Is it installed and on your PATH?",
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
