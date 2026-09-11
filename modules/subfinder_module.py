"""
subfinder module — passive subdomain enumeration.

No dependencies, so it starts immediately alongside nmap. Doesn't feed
into the current pipeline's other modules yet (that would mean re-running
nmap/httpx per-subdomain, a bigger architecture change) — for now it just
reports what it finds as its own findings list. A future version can wire
"scan every discovered subdomain too" as an opt-in mode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.module_base import FangModule


class SubfinderModule(FangModule):
    name = "subfinder"
    depends_on: list[str] = []

    def _build_command(self, context: dict[str, Any]) -> list[str]:
        return [
            "subfinder",
            "-d", self.target,
            "-silent",
        ]

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []
        for line in raw_output.strip().splitlines():
            subdomain = line.strip()
            if subdomain:
                findings.append({"subdomain": subdomain})
        return findings
