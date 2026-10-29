"""AEGIS — Untrusted Evidence & Indirect Prompt-Injection Firewall for LLM/GRC Pipelines."""

from .scanner import (
    Finding,
    ScanReport,
    Severity,
    scan_bytes,
    scan_file,
    scan_text,
)

__all__ = [
    "Finding",
    "ScanReport",
    "Severity",
    "scan_bytes",
    "scan_file",
    "scan_text",
]
__version__ = "0.1.0"
