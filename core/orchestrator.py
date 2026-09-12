"""
Multi-target orchestrator.

Runs a full Pipeline (nmap -> httpx -> ...) against several targets at
once, instead of just one. Concurrency is bounded by `max_concurrent`
so scanning 50 discovered subdomains doesn't fire 50 simultaneous nmap
processes and hammer both your machine and the target's network.

Used for two things:
  - --scope-file: the user hands us a list of targets directly
  - --expand-scope: subfinder discovers subdomains for the primary
    target, and we treat those as additional targets automatically
"""

from __future__ import annotations

import asyncio
import socket
from typing import Type

from core.module_base import FangModule, ModuleResult
from core.pipeline import Pipeline


class MultiTargetOrchestrator:
    def __init__(
        self,
        targets: list[str],
        modules: list[Type[FangModule]],
        options: dict | None = None,
        max_concurrent: int = 3,
    ):
        # Preserve order but drop exact duplicate target strings
        seen = set()
        self.targets = [t for t in targets if not (t in seen or seen.add(t))]
        self.modules = modules
        self.options = options or {}
        self.max_concurrent = max_concurrent
        self.results: dict[str, dict[str, ModuleResult]] = {}

    async def run(self) -> dict[str, dict[str, ModuleResult]]:
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_one(target: str) -> tuple[str, dict[str, ModuleResult]]:
            async with semaphore:
                pipeline = Pipeline(target, self.modules, self.options)
                result = await pipeline.run()
                return target, result

        tasks = [run_one(t) for t in self.targets]
        completed = await asyncio.gather(*tasks)
        self.results = dict(completed)
        return self.results

    def resolve_ips(self) -> dict[str, str | None]:
        """Resolve every target's IP. Returns {target: ip_or_None}."""
        resolved = {}
        for target in self.targets:
            try:
                resolved[target] = socket.gethostbyname(target)
            except (socket.gaierror, socket.timeout):
                resolved[target] = None
        return resolved

    def group_by_ip(self) -> dict[str, list[str]]:
        """Group targets that resolve to the same IP. Returns {ip: [targets]}.
        Targets that failed to resolve are grouped under the key 'unresolved'."""
        ip_map = self.resolve_ips()
        groups: dict[str, list[str]] = {}
        for target, ip in ip_map.items():
            key = ip if ip else "unresolved"
            groups.setdefault(key, []).append(target)
        return groups

    def summary(self) -> dict:
        """Full report: per-target module results, plus an IP-grouping
        section so duplicate infrastructure is visible at a glance."""
        ip_groups = self.group_by_ip()
        duplicate_groups = {ip: hosts for ip, hosts in ip_groups.items()
                             if ip != "unresolved" and len(hosts) > 1}

        return {
            "targets": {
                target: {name: result.to_dict() for name, result in module_results.items()}
                for target, module_results in self.results.items()
            },
            "ip_groups": ip_groups,
            "duplicate_infrastructure": duplicate_groups,
        }
