"""Pattern rules and the allowlist."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .findings import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity


def _rule(rule_id: str, description: str, pattern: str, severity: Severity) -> Rule:
    return Rule(rule_id, description, re.compile(pattern), severity)


RULES: tuple[Rule, ...] = (
    _rule(
        "aws.access_key",
        "AWS access key id",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        Severity.CRITICAL,
    ),
    _rule(
        "aws.secret_key",
        "AWS secret access key assignment",
        r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]",
        Severity.CRITICAL,
    ),
    _rule(
        "github.token",
        "GitHub personal access token",
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        Severity.CRITICAL,
    ),
    _rule(
        "slack.token",
        "Slack token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",
        Severity.HIGH,
    ),
    _rule(
        "stripe.key",
        "Stripe secret key",
        r"\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b",
        Severity.CRITICAL,
    ),
    _rule(
        "google.api_key",
        "Google API key",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        Severity.HIGH,
    ),
    _rule(
        "openai.key",
        "OpenAI-style API key",
        r"\bsk-[A-Za-z0-9]{20,}\b",
        Severity.HIGH,
    ),
    _rule(
        "private_key_block",
        "Private key material",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        Severity.CRITICAL,
    ),
    _rule(
        "jwt",
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        Severity.MEDIUM,
    ),
    _rule(
        "generic.assignment",
        "Secret-looking value assigned to a secret-sounding name",
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|auth)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        Severity.MEDIUM,
    ),
    _rule(
        "connection_string",
        "Connection string with inline credentials",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s/]+@",
        Severity.HIGH,
    ),
)

# Values that look like secrets but are documentation, placeholders or test data.
ALLOWLIST: frozenset[str] = frozenset(
    {
        "example",
        "examples",
        "changeme",
        "change-me",
        "placeholder",
        "your-key-here",
        "your_api_key",
        "your-api-key",
        "xxxxxxxx",
        "xxxxxxxxxxxxxxxx",
        "password",
        "secret",
        "token",
        "apikey",
        "api_key",
        "test",
        "testing",
        "dummy",
        "sample",
        "redacted",
        "none",
        "null",
        "undefined",
        "todo",
        "fake",
        "notreal",
        "hunter2",
        "letmein",
        "correct-horse-battery-staple",
    }
)

# Paths that are never worth scanning.
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
        "vendor",
        "site-packages",
    }
)

EXCLUDED_SUFFIXES: tuple[str, ...] = (
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".so",
    ".dylib",
    ".dll",
    ".pyc",
    ".class",
    ".jar",
)


def is_allowlisted(value: str) -> bool:
    """True when a candidate is obviously a placeholder rather than a real secret."""
    normalised = value.strip().strip("'\"").lower()
    if normalised in ALLOWLIST:
        return True
    if len(set(normalised)) <= 2:
        return True
    return any(marker in normalised for marker in ("example.com", "your_", "your-", "<", ">"))
