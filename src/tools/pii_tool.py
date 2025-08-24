from __future__ import annotations

import re
from typing import Dict, List


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\.\s]{7,}\d")
ADDRESS_HINTS = ["street", "ave", "road", "rd", "st "]


def detect(text: str) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for m in EMAIL_RE.finditer(text):
        findings.append({"pii_type": "email", "value": m.group(0), "start": m.start(), "end": m.end(), "confidence": 0.99})
    for m in PHONE_RE.finditer(text):
        findings.append({"pii_type": "phone", "value": m.group(0), "start": m.start(), "end": m.end(), "confidence": 0.9})
    low = text.lower()
    if any(h in low for h in ADDRESS_HINTS):
        findings.append({"pii_type": "address", "value": "<context>", "start": 0, "end": 0, "confidence": 0.6})
    return findings


def mask_value(pii_type: str, value: str) -> str:
    if pii_type == "email":
        parts = value.split("@")
        return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "***"
    if pii_type == "phone":
        return "***" + value[-4:]
    return "[REDACTED]"



