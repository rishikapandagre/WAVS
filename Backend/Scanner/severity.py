
"""Severity classification and scan-result summaries."""


SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def classify_severity(category: str, evidence: str = "") -> str:
    """
    Classify finding severity based on its category
    and available evidence.

    Returns:
        A severity string: Critical, High, Medium, Low, or Info.
    """

    category = str(category or "").strip().lower()
    evidence = str(evidence or "").strip().lower()

    # SQL Injection
    if "sql injection" in category:

        if "confirmed" in evidence:
            return "Critical"

        return "High"

    # Cross-Site Scripting
    if "xss" in category:

        if "reflected" in evidence:
            return "High"

        return "Medium"

    # Cross-Site Request Forgery
    if "csrf" in category:
        return "Medium"

    # Port scanning results
    if "port" in category:
        return "Info"

    # Security header findings
    if "security header" in category:
        return "Low"

    # Default severity
    return "Info"


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

    findings = findings or []

    counts = {
        severity: 0
        for severity in SEVERITY_ORDER
    }

    total = 0

    for item in findings:

        # Ignore malformed finding entries.
        if not isinstance(item, dict):
            continue

        severity = item.get("severity", "Info")

        # Normalize severity capitalization.
        if isinstance(severity, str):

            severity = severity.strip().capitalize()

        # Handle unexpected severity values gracefully.
        if severity not in SEVERITY_ORDER:
            severity = "Info"

        counts[severity] += 1
        total += 1

    return {
        "total": total,
        "by_severity": counts,
    }
