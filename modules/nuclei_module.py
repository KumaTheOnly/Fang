"""
nuclei module — template-based vulnerability scanning against every URL
httpx confirmed is live. This is the module that turns "here's what
exists" into "here's what might be exploitable."
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.module_base import FangModule, ModuleResult


class NucleiModule(FangModule):
    name = "nuclei"
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

        url_file = self.output_dir / f"nuclei_urls_{self._safe_target()}.txt"
        url_file.write_text("\n".join(live_urls))

        severity = self.options.get("severity", "low,medium,high,critical")

        return [
            "nuclei",
            "-l", str(url_file),
            "-severity", severity,
            "-jsonl",
            "-silent",
        ]

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            findings.append({
                "template_id": data.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": data.get("matched-at"),
                "description": info.get("description"),
            })
        return findings
