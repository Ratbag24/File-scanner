"""Data types shared by every part of the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Verdict(IntEnum):
    """Overall result for a file, ordered from safest to worst."""

    CLEAN = 0
    SUSPICIOUS = 1
    RISKY_TOOL = 2
    DANGEROUS = 3

    @property
    def label(self) -> str:
        return {
            Verdict.CLEAN: "Clean",
            Verdict.SUSPICIOUS: "Suspicious",
            Verdict.RISKY_TOOL: "Risky tool",
            Verdict.DANGEROUS: "Dangerous",
        }[self]


# Categories let the verdict tell "known malware" apart from "crack / keygen".
MALWARE = "malware"
HACKTOOL = "hacktool"
HEURISTIC = "heuristic"
INFO = "info"


@dataclass
class Finding:
    check: str
    severity: Severity
    message: str
    category: str = HEURISTIC

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity.name.lower(),
            "category": self.category,
            "message": self.message,
        }


@dataclass
class ScanResult:
    path: str
    size: int = 0
    sha256: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def verdict(self) -> Verdict:
        return verdict_for(self.findings)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "verdict": self.verdict.label,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


def verdict_for(findings: list[Finding]) -> Verdict:
    """Turn a list of findings into one overall verdict.

    - Any critical finding (a known virus signature) means Dangerous.
    - Crack / keygen / hacking-tool indicators mean Risky tool.
    - One high finding, or two or more medium findings, mean Suspicious.
    - Anything less is Clean. A single medium red flag is common in
      legitimate software, so it is reported but does not change the verdict.
    """
    if any(f.severity >= Severity.CRITICAL for f in findings):
        return Verdict.DANGEROUS
    if any(f.category == HACKTOOL and f.severity >= Severity.MEDIUM for f in findings):
        return Verdict.RISKY_TOOL
    if any(f.severity >= Severity.HIGH for f in findings):
        return Verdict.SUSPICIOUS
    if sum(1 for f in findings if f.severity == Severity.MEDIUM) >= 2:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN
