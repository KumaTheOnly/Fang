"""
Fang module interface.

Every tool wrapper (nmap, httpx, feroxbuster, ...) subclasses FangModule
and returns a ModuleResult. This keeps the pipeline, the concurrency
scheduler, and the report generator completely tool-agnostic: they only
ever deal with ModuleResult objects, never with nmap XML or ferox JSON
directly.
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ModuleStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"   # e.g. feroxbuster skipped because no HTTP ports found


@dataclass
class ModuleResult:
    """Standard return shape for every tool wrapper."""
    tool: str
    target: str
    status: ModuleStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_output_path: str | None = None
    duration_seconds: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "status": self.status.value,
            "findings": self.findings,
            "raw_output_path": self.raw_output_path,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
        }


class FangModule:
    """
    Base class for every tool wrapper.

    Subclasses must set `name` and implement `_build_command()` and
    `_parse_output()`. Subclasses that depend on another module's
    findings (e.g. feroxbuster needing nmap's open HTTP ports) declare
    that in `depends_on`.
    """

    name: str = "base"
    depends_on: list[str] = []          # names of modules this one waits on
    output_dir: Path = Path("output")

    def __init__(self, target: str, options: dict[str, Any] | None = None):
        self.target = target
        self.options = options or {}
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_command(self, context: dict[str, "ModuleResult"]) -> list[str]:
        """Return the command (as a list of args) to run. `context` holds
        the ModuleResult of every module this one depends on, keyed by name."""
        raise NotImplementedError

    def _parse_output(self, raw_output: str, raw_path: Path) -> list[dict[str, Any]]:
        """Turn raw tool output into a list of finding dicts."""
        raise NotImplementedError

    def _should_skip(self, context: dict[str, "ModuleResult"]) -> str | None:
        """Return a skip reason string if this module shouldn't run given
        its dependencies' results, or None to proceed."""
        return None

    async def run(self, context: dict[str, "ModuleResult"]) -> ModuleResult:
        skip_reason = self._should_skip(context)
        if skip_reason:
            return ModuleResult(
                tool=self.name,
                target=self.target,
                status=ModuleStatus.SKIPPED,
                error=skip_reason,
            )

        command = self._build_command(context)
        raw_path = self.output_dir / f"{self.name}_{self._safe_target()}.raw"

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            duration = time.monotonic() - start

            raw_text = stdout.decode(errors="replace")
            raw_path.write_text(raw_text)

            if proc.returncode != 0 and not raw_text.strip():
                return ModuleResult(
                    tool=self.name,
                    target=self.target,
                    status=ModuleStatus.FAILED,
                    duration_seconds=duration,
                    error=stderr.decode(errors="replace")[:500],
                    raw_output_path=str(raw_path),
                )

            findings = self._parse_output(raw_text, raw_path)

            return ModuleResult(
                tool=self.name,
                target=self.target,
                status=ModuleStatus.SUCCESS,
                findings=findings,
                raw_output_path=str(raw_path),
                duration_seconds=duration,
            )

        except FileNotFoundError:
            return ModuleResult(
                tool=self.name,
                target=self.target,
                status=ModuleStatus.FAILED,
                error=f"'{command[0]}' not found. Is it installed and on your PATH?",
            )
        except Exception as exc:  # noqa: BLE001 - surface any tool crash as a result
            return ModuleResult(
                tool=self.name,
                target=self.target,
                status=ModuleStatus.FAILED,
                duration_seconds=time.monotonic() - start,
                error=str(exc)[:500],
            )

    def _safe_target(self) -> str:
        return "".join(c if c.isalnum() else "_" for c in self.target)
