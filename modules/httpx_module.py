"""
httpx module — confirms which HTTP/S ports nmap found are actually alive,
and grabs status code / title / tech for each. Feroxbuster only runs
against URLs this module confirms are live, so we don't waste a fuzzing
run against a port that nmap thought was open but isn't really serving HTTP.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.module_base import FangModule, ModuleResult


class HttpxModule(FangModule):
    name = "httpx"
    depends_on = ["nmap"]

    def _should_skip(self, context: dict[str, ModuleResult]) -> str | None:
        nmap_result = context.get("nmap")
        if not nmap_result or nmap_result.status.value != "success":
            return "nmap did not complete successfully"
        if not any(f.get("is_http") for f in nmap_result.findings):
            return "no HTTP/S ports found by nmap"
        return None

    def _build_command(self, context: dict[str, ModuleResult]) -> list[str]:
        from modules.nmap_module import NmapModule  # local import avoids circular import at module load

        nmap_result = context["nmap"]
        helper = NmapModule(self.target)
        urls = helper.http_urls(nmap_result.findings)

        # Feed URLs via stdin using -l - is unreliable across httpx versions,
        # so write them to a temp file instead.
        url_file = self.output_dir / f"httpx_urls_{self._safe_target()}.txt"
        url_file.write_text("\n".join(urls))

        return [
            "httpx",
            "-l", str(url_file),
            "-status-code",
            "-title",
            "-tech-detect",
            "-json",
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
            findings.append({
                "url": data.get("url"),
                "status_code": data.get("status_code"),
                "title": data.get("title"),
                "tech": data.get("tech", []),
                "webserver": data.get("webserver"),
            })
        return findings

    def live_urls(self, result_findings: list[dict[str, Any]]) -> list[str]:
        """Helper for downstream modules (e.g. feroxbuster) to get confirmed-live URLs."""
        return [f["url"] for f in result_findings if f.get("url")]
