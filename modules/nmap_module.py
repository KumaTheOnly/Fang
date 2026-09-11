"""
nmap module — the entry point of the Fang pipeline.

Runs a service/version scan against the target and extracts open ports,
their services, and versions. Every other module reads its findings from
here (e.g. feroxbuster only runs against ports this module flags as HTTP/S).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.module_base import FangModule


class NmapModule(FangModule):
    name = "nmap"
    depends_on: list[str] = []

    # Ports/services nmap commonly reports that we treat as "web"
    HTTP_SERVICE_HINTS = ("http", "https", "http-proxy", "ssl/http", "http-alt")

    def _build_command(self, context: dict[str, Any]) -> list[str]:
        ports = self.options.get("ports", "1-1000")
        return [
            "nmap",
            "-sV",                # service/version detection
            "-T4",                # faster timing template
            "-p", ports,
            "-oX", "-",           # XML to stdout, we'll parse it
            self.target,
        ]

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        findings = []

        # Lightweight XML parse without extra deps
        port_blocks = re.findall(r"<port .*?</port>", raw_output, re.DOTALL)
        for block in port_blocks:
            port_match = re.search(r'portid="(\d+)"', block)
            proto_match = re.search(r'protocol="(\w+)"', block)
            state_match = re.search(r'<state state="(\w+)"', block)
            service_match = re.search(r'<service name="([^"]+)"(?:.*?product="([^"]*)")?(?:.*?version="([^"]*)")?', block)

            if not port_match or not state_match:
                continue
            if state_match.group(1) != "open":
                continue

            service_name = service_match.group(1) if service_match else "unknown"
            product = service_match.group(2) if service_match and service_match.group(2) else None
            version = service_match.group(3) if service_match and service_match.group(3) else None

            findings.append({
                "port": int(port_match.group(1)),
                "protocol": proto_match.group(1) if proto_match else "tcp",
                "service": service_name,
                "product": product,
                "version": version,
                "is_http": any(hint in service_name.lower() for hint in self.HTTP_SERVICE_HINTS),
            })

        return findings

    def http_urls(self, result_findings: list[dict[str, Any]]) -> list[str]:
        """Helper other modules call to get scannable URLs from this module's findings."""
        urls = []
        for f in result_findings:
            if not f.get("is_http"):
                continue
            scheme = "https" if "ssl" in f["service"].lower() or f["port"] == 443 else "http"
            port = f["port"]
            # Don't clutter the URL with default ports
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                urls.append(f"{scheme}://{self.target}")
            else:
                urls.append(f"{scheme}://{self.target}:{port}")
        return urls
