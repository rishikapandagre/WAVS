
"""Benign marker strings for low-impact security checks.

These markers are not exploit chains and must only be
used against authorized security assessment targets.
"""

# =============================================
# MARKER CONFIGURATION
# =============================================

XSS_MARKER = "WAVS_XSS_TEST_7f31"
SQL_MARKER = "WAVS_SQL_TEST_4c92"


# =============================================
# MARKER VALIDATION
# =============================================

def validate_marker(marker):
    """Check whether a marker is a valid non-empty string."""
    return (
        isinstance(marker, str)
        and bool(marker.strip())
        and len(marker) <= 128
    )
