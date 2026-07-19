"""Deterministic redaction for public finding evidence and reviewer input."""
# ruff: noqa: E501

import re

_PRIVATE_KEY = re.compile(r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?(?:-----END [^-\n]*PRIVATE KEY-----|\Z)", re.S)
_BEARER = re.compile(r"(?i)(\bbearer\s+)[^\s\"']+")
_DATABASE_URL = re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+")
_API_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16})\b")
_ASSIGNMENT_SECRET = re.compile(r"(?i)\b((?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"'])[^\"']*([\"'])")
_UNQUOTED_SECRET = re.compile(r"(?i)\b((?:api[_-]?key|secret|token|password)\s*[:=]\s*)[^\s\"';,]+")
_JWT_KEY = re.compile(r"(?i)(jwt\.(?:sign|verify)\s*\([^,]+,\s*[\"'])[^\"']*([\"'])")


def redact_sensitive_text(value: str) -> str:
    """Mask credential material while retaining safe variable and rule context."""
    value = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    value = _DATABASE_URL.sub("[REDACTED_DATABASE_URL]", value)
    value = _BEARER.sub(r"\1[REDACTED_BEARER_TOKEN]", value)
    value = _API_KEY.sub("[REDACTED_API_KEY]", value)
    value = _ASSIGNMENT_SECRET.sub(r"\1[REDACTED]\2", value)
    value = _JWT_KEY.sub(r"\1[REDACTED]\2", value)
    return _UNQUOTED_SECRET.sub(r"\1[REDACTED]", value)
