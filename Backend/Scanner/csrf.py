
"""
Low-impact CSRF checks.

Identifies state-changing forms without obvious anti-CSRF
token fields. Does not submit forms or modify state.
"""


def scan_csrf(forms):
    findings = []

    token_names = (
        "csrf",
        "xsrf",
        "authenticity",
        "requestverificationtoken",
    )

    state_changing_methods = {
        "post",
        "put",
        "patch",
        "delete",
    }

    for form in forms or []:

        if not isinstance(form, dict):
            continue

        method = str(form.get("method") or "get").strip().lower()

        # Only check state-changing HTTP methods.
        if method not in state_changing_methods:
            continue

        fields = form.get("fields") or []

        # Extract field names safely.
        names = {
            str(field.get("name", "")).strip().lower()
            for field in fields
            if isinstance(field, dict) and field.get("name")
        }

        # Check for common anti-CSRF token names.
        token_like = any(
            token in name
            for name in names
            for token in token_names
        )

        # Report only forms without an obvious CSRF token.
        if not token_like:
            findings.append({
                "type": "Potential CSRF Protection Missing",
                "url": form.get("page"),
                "parameter": "(form)",
                "method": method.upper(),
                "severity": "Medium",
                "evidence": (
                    "A state-changing form contains no obvious "
                    "anti-CSRF token field. Cookie SameSite "
                    "and server-side validation were not verified."
                ),
                "recommendation": (
                    "Use framework CSRF protection, validate "
                    "tokens server-side, and configure "
                 
                   "appropriate SameSite cookie attributes."
                )
            })

    return findings
