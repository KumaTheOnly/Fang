"""
whatweb module — identifies CMS, frameworks, and server tech for every
live URL httpx confirmed. Useful for deciding which nuclei templates or
manual attacks are worth trying (e.g. WordPress-specific checks).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.module_base import FangModule, ModuleResult


class WhatwebModule(FangModule):
    name = "whatweb"
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

        return [
            "whatweb",
            "--log-json=-",   # JSON to stdout
            *live_urls,
        ]

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []
        # whatweb's --log-json=- emits one JSON array per line/run in older
        # versions, or a single JSON array total in newer ones. Handle both.
        text = raw_output.strip()
        if not text:
            return findings

        try:
            data = json.loads(text)
            entries = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Fall back to line-by-line JSON objects
            entries = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for entry in entries:
            plugins = entry.get("plugins", {})
            findings.append({
                "url": entry.get("target"),
                "technologies": list(plugins.keys()),
                "details": {k: v.get("string", v) for k, v in plugins.items() if isinstance(v, dict)},
            })
        return findings
