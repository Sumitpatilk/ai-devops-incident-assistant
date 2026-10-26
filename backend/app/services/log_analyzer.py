from app.core.rules import RULES


VALID_SOURCES = {
    "github-actions",
    "docker",
    "kubernetes",
}


def analyze_log(source: str, log_text: str) -> dict:
    source = source.strip().lower()

    if source not in VALID_SOURCES:
        raise ValueError(
            f"Unsupported source: {source}"
        )

    if not log_text or not log_text.strip():
        raise ValueError("Log text cannot be empty.")

    normalized_log = log_text.lower()
    findings = []

    for rule in RULES:
        if rule["source"] not in (source, "all"):
            continue

        matched_patterns = [
            pattern
            for pattern in rule["patterns"]
            if pattern.lower() in normalized_log
        ]

        if not matched_patterns:
            continue

        evidence_lines = [
            line.strip()
            for line in log_text.splitlines()
            if any(
                pattern.lower() in line.lower()
                for pattern in matched_patterns
            )
        ]

        findings.append({
            "rule_id": rule["id"],
            "matched_patterns": matched_patterns,
            "evidence": evidence_lines,
            "possible_cause": rule["possible_cause"],
            "recommended_checks": rule["recommended_checks"],
        })

    return {
        "source": source,
        "status": "findings" if findings else "no_match",
        "findings": findings,
        "note": (
            "These are pattern-based findings, not confirmed "
            "root causes."
        ),
    }
