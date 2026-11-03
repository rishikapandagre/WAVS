
"""Low-impact CSRF checks for WAVS.

Identifies state-changing forms without obvious anti-CSRF
token fields. Forms are never submitted or modified.
"""

# ==================================================
# CONFIGURATION
# ==================================================

TOKEN_PATTERNS = (
    "csrf",
    "xsrf",
    "authenticity",
    "requestverificationtoken",
    "anti-csrf",
    "antcsrf",
    "csrfmiddlewaretoken",
    "__requestverificationtoken",
)

STATE_CHANGING_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}

DEFAULT_SEVERITY = "Medium"


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def _normalize_method(method):
    """Normalize and validate an HTTP method."""

    return str(
        method or "GET"
    ).strip().upper()


def _extract_field_names(fields):
    """Safely extract normalized form field names."""

    if not isinstance(fields, list):
        return set()

    names = set()

    for field in fields:

        if not isinstance(field, dict):
            continue

        name = field.get("name")

        if not name:
            continue

        names.add(
            str(name).strip().lower()
        )

    return names


def _has_csrf_token(fields):
    """Check whether a form contains an obvious CSRF token."""

    names = _extract_field_names(
        fields
    )

    return any(
        pattern in name
        for name in names
        for pattern in TOKEN_PATTERNS
    )


def _build_finding(form, method):
    """Construct a standardized CSRF finding."""

    return {
        "type": "Potential CSRF Protection Missing",
        "url": form.get("page", ""),
        "parameter": "(form)",
        "method": method,
        "severity": DEFAULT_SEVERITY,
        "evidence": (
            "A state-changing form contains no obvious "
            "anti-CSRF token field. Cookie SameSite "
            "attributes and server-side validation "
            "were not verified."
        ),
        "recommendation": (
            "Implement framework-provided CSRF protection, "
            "validate tokens server-side, and configure "
            "appropriate SameSite cookie attributes. "
            "Consider Origin and Referer validation "
            "as additional defense-in-depth."
        ),
    }


# ==================================================
# MAIN CSRF SCANNER
# ==================================================

def scan_csrf(forms):
    """
    Analyze discovered forms for potential CSRF risks.

    This scanner is passive and does not submit forms.

    Args:
        forms (list): Forms collected by the crawler.

    Returns:
        list: Potential CSRF findings.
    """

    findings = []

    if not isinstance(forms, list):
        return findings

    for form in forms:

        # ------------------------------------------
        # VALIDATE FORM
        # ------------------------------------------

        if not isinstance(form, dict):
            continue

        # ------------------------------------------
        # CHECK HTTP METHOD
        # ------------------------------------------

        method = _normalize_method(
            form.get("method")
        )

        if method not in STATE_CHANGING_METHODS:
            continue

        # ------------------------------------------
        # CHECK CSRF TOKEN
        # ------------------------------------------

        fields = form.get(
            "fields",
            [],
        )

        if _has_csrf_token(fields):
            continue

        # ------------------------------------------
        # GENERATE FINDING
        # ------------------------------------------

        findings.append(
            _build_finding(
                form,
                method,
            )
        )

    return findings
