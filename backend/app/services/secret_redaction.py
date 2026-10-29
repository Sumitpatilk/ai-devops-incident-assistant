import re


# Keep these patterns conservative enough to preserve surrounding log evidence.
_SECRET_PATTERNS = [
    # Authorization headers and bearer credentials.
    (
        re.compile(r"(?i)(\bauthorization\s*:\s*bearer\s+)[^\s,;]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+"),
        r"\1[REDACTED]",
    ),

         # Common key/value secret assignments, including quoted JSON keys.
    (
        re.compile(
            r'(?i)(["\']?\b(?:password|passwd|pwd|token|id[_-]?token|'
            r'session[_-]?token|jwt|client[_-]?secret|clientsecret|'
            r'api[_-]?key|access[_-]?token|refresh[_-]?token|'
            r'auth[_-]?token|secret|secret[_-]?key|private[_-]?key|'
            r'credential|credentials|connection[_-]?string|'
            r'db[_-]?password)\b["\']?\s*[:=]\s*)'
            r'("[^"]*"|\'[^\']*\'|[^\s,;}]+)'
        ),
        lambda match: (
            match.group(1)
            + (
                match.group(2)[0]
                + "[REDACTED]"
                + match.group(2)[0]
                if match.group(2).startswith(('"', "'"))
                else "[REDACTED]"
            )
        ),
    ),

    # URL user information: scheme://username:password@host
    (
        re.compile(r"(?i)(://[^/\s:@]+:)[^@\s/]+(@)"),
        r"\1[REDACTED]\2",
    ),

    # AWS access key IDs.
    (
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED_AWS_ACCESS_KEY]",
    ),

    # Common GitHub token prefixes.
    (
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b"
        ),
        "[REDACTED_GITHUB_TOKEN]",
    ),

    # Common GitLab and Slack token formats.
    (
        re.compile(
            r"\b(?:glpat-[A-Za-z0-9_-]{20,}|"
            r"xox[baprs]-[A-Za-z0-9-]{10,})\b"
        ),
        "[REDACTED_PROVIDER_TOKEN]",
    ),
]

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
    r"PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
    r"PRIVATE KEY-----",
    re.DOTALL,
)


def redact_secrets(text: str) -> str:
    """Redact common secret formats from text before storage or display."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    redacted = _PRIVATE_KEY_PATTERN.sub(
        "[REDACTED_PRIVATE_KEY]",
        text,
    )

    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    return redacted
