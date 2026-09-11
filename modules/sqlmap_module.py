"""
sqlmap module — SQL injection testing.

Deliberately NOT part of the default pipeline. sqlmap is invasive (sends
attack payloads, can be slow/loud) and shouldn't fire automatically against
every URL just because it was reachable. This module only runs when
explicitly requested via `fang scan <target> --sqlmap`, and only against
URLs you point it at directly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.module_base import FangModule, ModuleResult


class SqlmapModule(FangModule):
    name = "sqlmap"
    depends_on = ["httpx"]

    def _should_skip(self, context: dict[str, ModuleResult]) -> str | None:
        httpx_result = context.get("httpx")
        if not httpx_result or httpx_result.status.value != "success":
            return "httpx did not complete successfully"
        if not httpx_result.findings:
            return "no live HTTP/S hosts confirmed by httpx"
        return None

    def _build_command(self, context: dict[str, ModuleResult]) -> list[str]:
        from modules.httpx_module import HttpxModule

        httpx_result = context["httpx"]
        live_urls = HttpxModule(self.target).live_urls(httpx_result.findings)
        # sqlmap tests one URL at a time and is slow — default to the first
        # live URL unless the user specifies one explicitly via options.
        url = self.options.get("url", live_urls[0] if live_urls else self.target)

        level = str(self.options.get("level", 1))
        risk = str(self.options.get("risk", 1))

        return [
            "sqlmap",
            "-u", url,
            "--batch",              # non-interactive, use defaults for prompts
            f"--level={level}",
            f"--risk={risk}",
            "--output-dir", str(self.output_dir / "sqlmap"),
        ]

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []
        if re.search(r"is vulnerable", raw_output, re.IGNORECASE):
            findings.append({
                "vulnerable": True,
                "summary": "sqlmap reported at least one injectable parameter — see raw output for details",
            })
        else:
            findings.append({
                "vulnerable": False,
                "summary": "No SQL injection found at the tested level/risk",
            })
        return findings
