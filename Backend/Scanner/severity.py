
"""Severity classification and scan-result summaries."""

from collections import Counter


SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}

DEFAULT_SEVERITY = "Info"


# =============================================
# SEVERITY NORMALIZATION
# =============================================

def normalize_severity(severity):
    """
    Normalize a severity value to a supported classification.
    """
    if not isinstance(severity, str):
        return DEFAULT_SEVERITY

    normalized = severity.strip().lower()

    for supported in SEVERITY_ORDER:
        if normalized == supported.lower():
            return supported

    return DEFAULT_SEVERITY


# =============================================
# SEVERITY CLASSIFICATION
# =============================================

def classify_severity(category: str, evidence: str = "") -> str:
    """
    Classify finding severity based on vulnerability category
    and available evidence.

    Returns:
        Critical, High, Medium, Low, or Info.
    """
    category = str(category or "").strip().lower()
    evidence = str(evidence or "").strip().lower()

    # SQL Injection
    if "sql injection" in category or "sqli" in category:
        if any(keyword in evidence for keyword in (
            "confirmed",
            "database error",
            "sql syntax error",
            "successful injection",
        )):
            return "Critical"

        return "High"

    # Cross-Site Scripting
    if "cross-site scripting" in category or "xss" in category:
        if any(keyword in evidence for keyword in (
            "confirmed",
            "executed",
            "reflected payload",
        )):
            return "High"

        return "Medium"

    # Cross-Site Request Forgery
    if "csrf" in category:
        return "Medium"

    # Open TCP ports
    if "port" in category:
        return "Info"

    # Security headers
    if "security header" in category:
        return "Low"

    # Information disclosure
    if any(keyword in category for keyword in (
        "information disclosure",
        "sensitive information",
        "directory listing",
    )):
        return "Low"

    return DEFAULT_SEVERITY


# =============================================
# FINDINGS SUMMARY
# =============================================

def summarize_findings(findings):
    """
    Generate a summary of findings grouped by severity.

    Returns:
        {
            "total": int,
            "by_severity": {
                "Critical": int,
                "High": int,
                "Medium": int,
                "Low": int,
                "Info": int
            }
        }
    """
    counts = Counter({
        severity: 0
        for severity in SEVERITY_ORDER
    })

    if not isinstance(findings, (list, tuple)):
        findings = []

    total = 0

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(
            finding.get("severity", DEFAULT_SEVERITY)
        )

        counts[severity] += 1
        total += 1

    return {
        "total": total,
        "by_severity": dict(counts),
    }


# =============================================
# HIGHEST SEVERITY
# =============================================

def get_highest_severity(findings):
    """
    Return the highest severity present in findings.
    """
    highest = DEFAULT_SEVERITY

    if not isinstance(findings, (list, tuple)):
        return highest

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(
            finding.get("severity", DEFAULT_SEVERITY)
        )

        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity

    return highest


# =============================================
# SEVERITY SORTING
# =============================================

def sort_findings(findings, descending=True):
    """
    Sort findings by severity.

    Critical findings appear first by default.
    """
    if not isinstance(findings, (list, tuple)):
        return []

    valid_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]

    return sorted(
        valid_findings,
        key=lambda finding: SEVERITY_ORDER[
            normalize_severity(finding.get("severity"))
        ],
        reverse=descending,
    )
