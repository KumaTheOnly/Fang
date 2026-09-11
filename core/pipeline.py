"""
Fang pipeline — runs every registered module against a target, respecting
each module's `depends_on`.

Modules with no unmet dependencies start immediately and run concurrently.
A module that depends on others only starts once ALL of its dependencies
have finished — but it doesn't wait for modules outside its dependency
chain. This is what gives us "as parallel as possible, but never runs
ahead of data it needs."
"""

from __future__ import annotations

import asyncio
from typing import Type

from core.module_base import FangModule, ModuleResult, ModuleStatus


class Pipeline:
    def __init__(self, target: str, modules: list[Type[FangModule]], options: dict | None = None):
        self.target = target
        self.module_classes = modules
        self.options = options or {}
        self.results: dict[str, ModuleResult] = {}

    async def run(self) -> dict[str, ModuleResult]:
        pending = {cls.name: cls for cls in self.module_classes}
        in_flight: dict[str, asyncio.Task] = {}

        while pending or in_flight:
            # Find modules whose dependencies are all satisfied and not yet started
            ready = [
                name for name, cls in pending.items()
                if all(dep in self.results for dep in cls.depends_on)
            ]

            for name in ready:
                cls = pending.pop(name)
                module_options = self.options.get(name, {})
                instance = cls(self.target, module_options)
                in_flight[name] = asyncio.create_task(instance.run(self.results))

            if not in_flight:
                # Nothing running and nothing ready means an unmet dependency
                # (e.g. a typo in depends_on) — fail those modules explicitly
                # rather than looping forever.
                for name, cls in pending.items():
                    self.results[name] = ModuleResult(
                        tool=name, target=self.target, status=ModuleStatus.FAILED,
                        error=f"Unmet dependencies: {cls.depends_on}",
                    )
                pending.clear()
                break

            done, _ = await asyncio.wait(in_flight.values(), return_when=asyncio.FIRST_COMPLETED)

            for name in list(in_flight):
                task = in_flight[name]
                if task in done:
                    self.results[name] = task.result()
                    del in_flight[name]

        return self.results

    def summary(self) -> dict:
        return {name: result.to_dict() for name, result in self.results.items()}
