"""Findings — the common output of every audit check.

TLS, HTTP-header and mail-security checks all answer the same question
("what is wrong here, and how bad is it?"), so they share one result type.
That is what lets ``netintel audit`` merge them into a single report and
lets a script filter everything by severity with one ``jq`` expression.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so that ``max()`` over findings gives the worst one.

    INFO sits below OK: a purely informational line says nothing about risk.
    """

    INFO = 0
    OK = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation produced by a check."""

    check: str
    severity: Severity
    title: str
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.label,
            "title": self.title,
            "detail": self.detail,
        }


_MARKS = {
    Severity.OK: "[ ok ]",
    Severity.INFO: "[info]",
    Severity.LOW: "[low ]",
    Severity.MEDIUM: "[med ]",
    Severity.HIGH: "[HIGH]",
}


def worst(findings: Iterable[Finding]) -> Severity:
    return max((f.severity for f in findings), default=Severity.INFO)


def format_findings(findings: Iterable[Finding], *, indent: str = "  ") -> str:
    lines = []
    for finding in findings:
        line = f"{indent}{_MARKS[finding.severity]} {finding.title}"
        if finding.detail:
            line += f" — {finding.detail}"
        lines.append(line)
    return "\n".join(lines)
