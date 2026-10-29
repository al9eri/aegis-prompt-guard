"""Core static & heuristic scanner for untrusted LLM inputs and compliance evidence."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, List


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {
    Severity.LOW: 0.15,
    Severity.MEDIUM: 0.35,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 1.00,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: Severity
    line: int
    offset: int
    description: str
    snippet: str


@dataclass
class ScanReport:
    source: str
    sha256: str
    byte_length: int
    risk_score: float
    verdict: str
    requires_human_review: bool
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["findings"] = [
            {**asdict(f), "severity": f.severity.value} for f in self.findings
        ]
        return data


# Trojan Source (CVE-2021-42574) & Bidirectional control codepoints
BIDI_CODEPOINTS = {
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
}

# Zero-width characters commonly abused to split tokens or hide instructions
ZERO_WIDTH_CODEPOINTS = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (mid-stream)
}


@dataclass(frozen=True)
class _PatternRule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str


PATTERN_RULES: tuple[_PatternRule, ...] = (
    _PatternRule(
        rule_id="AEGIS-INJ-001",
        category="boundary_spoofing",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(<\|im_start\|>\s*system|<\|system\|>|\[INST\]|<<SYS>>|###\s*System\s*Prompt\s*:)",
            re.IGNORECASE,
        ),
        description="Chat-template delimiter or system-role boundary spoofing token detected.",
    ),
    _PatternRule(
        rule_id="AEGIS-INJ-002",
        category="instruction_override",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|system|preceding)\s+"
            r"(instructions?|prompts?|rules?|guardrails?|controls?)\b",
            re.IGNORECASE,
        ),
        description="Explicit instruction-override directive embedded in untrusted text.",
    ),
    _PatternRule(
        rule_id="AEGIS-GRC-003",
        category="verdict_manipulation",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"\b(mark|declare|classify|output|set|approve)\s+(this\s+|all\s+|every\s+)?"
            r"(control|requirement|audit|assessment|status|evidence)s?\s+(as\s+)?"
            r"(fully\s+)?(compliant|passed|approved|certified|satisfied)\b",
            re.IGNORECASE,
        ),
        description="Embedded attempt to coerce automated compliance or audit status.",
    ),
    _PatternRule(
        rule_id="AEGIS-EXF-004",
        category="markdown_exfiltration",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]*(token|secret|key|context|summary|data|prompt)=",
            re.IGNORECASE,
        ),
        description="Suspicious Markdown image beacon URL with query-parameter exfiltration sink.",
    ),
    _PatternRule(
        rule_id="AEGIS-TOOL-005",
        category="tool_hijack",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(execute_command|run_shell|send_email|curl\s+https?://|wget\s+https?://|invoke_tool)\b",
            re.IGNORECASE,
        ),
        description="Embedded agent tool-invocation or shell execution directive inside document.",
    ),
)

BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")
SMUGGLED_KEYWORDS = (
    b"ignore previous",
    b"ignore all previous",
    b"system prompt",
    b"<|im_start|>",
    b"mark all controls",
    b"compliant",
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _clean_snippet(text: str, start: int, end: int, max_len: int = 72) -> str:
    raw = text[max(0, start - 12) : min(len(text), end + 12)]
    escaped = raw.replace("\n", "\\n").replace("\r", "\\r")
    if len(escaped) > max_len:
        return escaped[: max_len - 3] + "..."
    return escaped


def _scan_unicode_stego(text: str) -> Iterable[Finding]:
    tag_chars: list[int] = []
    zw_chars: list[int] = []

    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp in BIDI_CODEPOINTS:
            yield Finding(
                rule_id="AEGIS-UNI-001",
                category="trojan_bidi",
                severity=Severity.CRITICAL,
                line=_line_number(text, idx),
                offset=idx,
                description=f"Unicode bidirectional override U+{cp:04X} (Trojan Source vector).",
                snippet=f"U+{cp:04X} at offset {idx}",
            )
        elif 0xE0000 <= cp <= 0xE007F:
            tag_chars.append(idx)
        elif cp in ZERO_WIDTH_CODEPOINTS and idx > 0:
            zw_chars.append(idx)

    if tag_chars:
        first = tag_chars[0]
        yield Finding(
            rule_id="AEGIS-UNI-002",
            category="unicode_tag_smuggling",
            severity=Severity.CRITICAL,
            line=_line_number(text, first),
            offset=first,
            description=(
                f"Detected {len(tag_chars)} invisible Unicode Plane-14 Tag character(s) "
                "(ASCII prompt smuggling vector)."
            ),
            snippet=f"{len(tag_chars)} hidden tag codepoints starting at offset {first}",
        )

    if len(zw_chars) >= 3:
        first = zw_chars[0]
        yield Finding(
            rule_id="AEGIS-UNI-003",
            category="zero_width_obfuscation",
            severity=Severity.MEDIUM,
            line=_line_number(text, first),
            offset=first,
            description=(
                f"Detected cluster of {len(zw_chars)} zero-width characters "
                "(token-splitting / watermarking obfuscation)."
            ),
            snippet=f"{len(zw_chars)} zero-width codepoints starting at offset {first}",
        )


def _scan_base64_smuggling(text: str) -> Iterable[Finding]:
    for match in BASE64_CANDIDATE_RE.finditer(text):
        blob = match.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        lowered = decoded.lower()
        if any(kw in lowered for kw in SMUGGLED_KEYWORDS):
            preview = decoded.decode("utf-8", errors="replace")[:48]
            yield Finding(
                rule_id="AEGIS-ENC-001",
                category="encoded_payload",
                severity=Severity.HIGH,
                line=_line_number(text, match.start()),
                offset=match.start(),
                description="Base64-encoded prompt-injection payload detected.",
                snippet=f"b64->'{preview}'",
            )


def scan_bytes(payload: bytes, source: str = "<memory>") -> ScanReport:
    digest = hashlib.sha256(payload).hexdigest()
    text = payload.decode("utf-8", errors="replace")
    findings: list[Finding] = []

    findings.extend(_scan_unicode_stego(text))

    for rule in PATTERN_RULES:
        for match in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    line=_line_number(text, match.start()),
                    offset=match.start(),
                    description=rule.description,
                    snippet=_clean_snippet(text, match.start(), match.end()),
                )
            )

    findings.extend(_scan_base64_smuggling(text))
    findings.sort(key=lambda f: (f.offset, f.rule_id))

    raw_score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    risk_score = round(min(1.0, raw_score), 3)

    if any(f.severity == Severity.CRITICAL for f in findings) or risk_score >= 0.70:
        verdict = "QUARANTINE"
    elif findings:
        verdict = "FLAGGED"
    else:
        verdict = "CLEAN"

    return ScanReport(
        source=source,
        sha256=digest,
        byte_length=len(payload),
        risk_score=risk_score,
        verdict=verdict,
        requires_human_review=(verdict != "CLEAN"),
        findings=findings,
    )


def scan_text(text: str, source: str = "<string>") -> ScanReport:
    return scan_bytes(text.encode("utf-8"), source=source)


def scan_file(path: str | Path) -> ScanReport:
    file_path = Path(path)
    return scan_bytes(file_path.read_bytes(), source=str(file_path))
