
"""Low-impact SQL error fingerprinting."""

import re
from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)

from Utils.request_handler import safe_get
from Utils.payloads import SQL_MARKER
from Utils.logger import logger


SQL_ERRORS = re.compile(
    r"(SQL syntax.*MySQL|mysql_fetch|ORA-\d{4,5}|"
    r"SQLite error|sqlite3\.OperationalError|"
    r"PostgreSQL.*ERROR|pg_query\(\)|"
    r"SQL Server.*error|ODBC SQL Server Driver)",
    re.IGNORECASE,
)


MAX_RESPONSE_SIZE = 500_000


def _mutate_query(url, key, value):
    """
    Replace the first occurrence of a query parameter
    while preserving the remaining query parameters.
    """

    parsed = urlparse(url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    output = []
    replaced = False

    for parameter, current_value in pairs:

        if parameter == key and not replaced:
            output.append((parameter, value))
            replaced = True

        else:
            output.append((parameter, current_value))

    # If the parameter does not exist, return the
    # original URL unchanged.
    if not replaced:
        return url

    return urlunparse(
        parsed._replace(
            query=urlencode(output, doseq=True)
        )
    )


def scan_sql_injection(pages, forms=None):
    """
    Detect potential error-based SQL injection through
    GET query parameters.

    Forms are not submitted to avoid modifying state.

    Returns:
        A list of potential SQL injection findings.
    """

    findings = []
    forms = forms or []

    # Collect unique URLs containing query parameters.
    urls = list(dict.fromkeys(
        page.get("url", "")
        for page in (pages or [])
        if isinstance(page, dict)
        and page.get("url")
        and parse_qsl(
            urlparse(page.get("url", "")).query,
            keep_blank_values=True,
        )
    ))

    tested = set()

    for url in urls:

        parameters = parse_qsl(
            urlparse(url).query,
            keep_blank_values=True,
        )

        for key, original_value in parameters:

            # Avoid testing the same parameter repeatedly.
            test_key = (url, key)

            if test_key in tested:
                continue

            tested.add(test_key)

            baseline = None
            test_response = None

            try:
                # Fetch the original response.
                baseline = safe_get(url)

                if baseline is None:
                    continue

                # Inject a benign error-triggering marker.
                test_url = _mutate_query(
                    url,
                    key,
                    f"{SQL_MARKER}'",
                )

                if test_url == url:
                    continue

                test_response = safe_get(test_url)

                if test_response is None:
                    continue

                # Limit response processing to avoid
                # excessive memory consumption.
                baseline_body = (
                    baseline.text[:MAX_RESPONSE_SIZE]
                )

                test_body = (
                    test_response.text[:MAX_RESPONSE_SIZE]
                )

                # Report only when a recognizable database
                # error appears in the test response but
                # not in the baseline response.
                baseline_has_error = bool(
                    SQL_ERRORS.search(baseline_body)
                )

                test_has_error = bool(
                    SQL_ERRORS.search(test_body)
                )

                if test_has_error and not baseline_has_error:

                    findings.append({
                        "type": (
                            "Potential SQL Injection "
                            "(error-based)"
                        ),
                        "url": test_url,
                        "parameter": key,
                        "method": "GET",
                        "severity": "High",
                        "evidence": (
                            "A database error fingerprint appeared "
                            "only after a benign test input. "
                            "Manual verification is required."
                        ),
                        "recommendation": (
                            "Use parameterized queries or prepared "
                            "statements. Avoid exposing database "
                            "errors in public responses."
                        ),
                    })

            except Exception as exc:
                logger.info(
                    "SQL check skipped %s: %s",
                    url,
                    exc,
                )

            finally:
                # Always release response resources.
                if baseline is not None:
                    baseline.close()

                if test_response is not None:
                    test_response.close()

    # Forms are catalogued but never automatically
    # submitted to prevent unintended state changes.

    return findings
