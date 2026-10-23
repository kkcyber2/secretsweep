"""Walk a tree, apply the rules, and collect findings."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .entropy import looks_random, shannon_entropy
from .findings import ORDER, Finding, Severity
from .rules import EXCLUDED_DIRS, EXCLUDED_SUFFIXES, RULES, is_allowlisted

MAX_FILE_BYTES = 2_000_000
ENTROPY_MIN_LENGTH = 20
ENTROPY_THRESHOLD = 3.5


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (ORDER[f.severity], f.path, f.line))

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.severity.value] = out.get(finding.severity.value, 0) + 1
        return out

    def public(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "counts": self.counts(),
            "findings": [f.public() for f in self.sorted_findings()],
            "skipped": self.skipped,
        }


def should_skip(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return True
    return path.name.endswith(EXCLUDED_SUFFIXES)


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            candidate = Path(dirpath) / name
            if not should_skip(candidate):
                yield candidate


def scan_text(text: str, path: str) -> list[Finding]:
    """Apply every rule plus the entropy pass to one file's contents."""
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                if is_allowlisted(value):
                    continue
                findings.append(
                    Finding(
                        rule=rule.id,
                        description=rule.description,
                        severity=rule.severity,
                        path=path,
                        line=line_number,
                        column=match.start() + 1,
                        match=value,
                    )
                )
        # Entropy pass: quoted strings that look random.
        for token in _quoted_tokens(line):
            if is_allowlisted(token):
                continue
            if looks_random(token, min_length=ENTROPY_MIN_LENGTH, threshold=ENTROPY_THRESHOLD):
                findings.append(
                    Finding(
                        rule="entropy.high",
                        description="High-entropy string (possible secret)",
                        severity=Severity.MEDIUM,
                        path=path,
                        line=line_number,
                        column=line.find(token) + 1,
                        match=token,
                        entropy=shannon_entropy(token),
                    )
                )
    return _dedupe(findings)


def _quoted_tokens(line: str) -> list[str]:
    import re

    return re.findall(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]", line)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop a finding when a stronger rule already reported the same span."""
    seen: set[tuple[str, int, int]] = set()
    out: list[Finding] = []
    for finding in sorted(findings, key=lambda f: ORDER[f.severity]):
        key = (finding.path, finding.line, finding.column)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def scan_path(root: str | Path) -> ScanResult:
    root_path = Path(root)
    result = ScanResult(root=str(root_path))
    for file_path in iter_files(root_path):
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                result.skipped.append(str(file_path))
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            result.skipped.append(str(file_path))
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, str(file_path)))
    return result
