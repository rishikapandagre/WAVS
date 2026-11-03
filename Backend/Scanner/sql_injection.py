
"""Low-impact SQL error fingerprinting for authorized assessments."""

import re

from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)

from Backend.config import REQUEST_TIMEOUT
from Backend.Utils.request_handler import safe_get
from Backend.Utils.payloads import SQL_MARKER
from Backend.Utils.logger import logger


SQL_ERRORS = re.compile(
    r"("
    r"SQL syntax.*MySQL|"
    r"mysql_fetch|"
    r"mysql_query|"
    r"mysqli?_.*error|"
    r"ORA-\d{4,5}|"
    r"SQLite error|"
    r"sqlite3\.OperationalError|"
    r"PostgreSQL.*ERROR|"
    r"pg_query\(\)|"
    r"SQL Server.*error|"
    r"ODBC SQL Server Driver|"
    r"Unclosed quotation mark after the character string|"
    r"Microsoft SQL Native Client|"
    r"syntax error at or near"
    r")",
    re.IGNORECASE,
)

MAX_RESPONSE_SIZE = 500_000
MAX_PARAMETERS_PER_URL = 50


# =============================================
# URL PARAMETER MUTATION
# =============================================

def _mutate_query(url, key, value):
    """
    Replace the first occurrence of a query parameter
    while preserving the remaining parameters.
    """
    try:
        parsed = urlparse(url)

        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            max_num_fields=MAX_PARAMETERS_PER_URL,
        )

        output = []
        replaced = False

        for parameter, current_value in pairs:

            if parameter == key and not replaced:
                output.append((parameter, value))
                replaced = True

            else:
                output.append((parameter, current_value))

        if not replaced:
            return url

        return urlunparse(
            parsed._replace(
                query=urlencode(output, doseq=True)
            )
        )

    except (ValueError, TypeError) as exc:
        logger.debug("Unable to mutate query parameter: %s", exc)
        return url


# =============================================
# RESPONSE PROCESSING
# =============================================

def _get_response_body(response):
    """Safely retrieve a bounded response body."""
    try:
        body = response.text

        if not isinstance(body, str):
            return ""

        return body[:MAX_RESPONSE_SIZE]

    except Exception:
        return ""


def _contains_sql_error(response):
    """Check whether a response contains a SQL error fingerprint."""
    body = _get_response_body(response)
    return bool(SQL_ERRORS.search(body))


# =============================================
# SQL INJECTION SCANNER
# =============================================

def scan_sql_injection(pages, forms=None):
    """
    Detect potential error-based SQL injection in GET parameters.

    Forms are catalogued but never submitted automatically.

    Returns:
        A list of potential SQL injection findings.
    """
    findings = []
    forms = forms or []

    if not isinstance(pages, (list, tuple)):
        logger.warning("SQL scanner received invalid pages input.")
        return findings

    # Collect unique URLs containing query parameters.
    urls = []

    for page in pages:

        if not isinstance(page, dict):
            continue

        url = page.get("url")

        if not isinstance(url, str) or not url:
            continue

        try:
            parsed = urlparse(url)

            if not parsed.query:
                continue

            parameters = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=MAX_PARAMETERS_PER_URL,
            )

            if parameters:
                urls.append(url)

        except (ValueError, TypeError):
            logger.debug("Skipping malformed scanner URL.")

    urls = list(dict.fromkeys(urls))

    tested = set()

    # =============================================
    # PARAMETER TESTING
    # =============================================

    for url in urls:

        try:
            parsed = urlparse(url)

            parameters = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=MAX_PARAMETERS_PER_URL,
            )

        except (ValueError, TypeError):
            continue

        for key, original_value in parameters:

            test_key = (url, key)

            if test_key in tested:
                continue

            tested.add(test_key)

            baseline = None
            test_response = None

            try:
                # Obtain the original response.
                baseline = safe_get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                )

                if baseline is None:
                    continue

                # Generate a minimally modified test URL.
                test_url = _mutate_query(
                    url,
                    key,
                    f"{SQL_MARKER}'",
                )

                if not test_url or test_url == url:
                    continue

                # Send the test request.
                test_response = safe_get(
                    test_url,
                    timeout=REQUEST_TIMEOUT,
                )

                if test_response is None:
                    continue

                # Compare the baseline and test responses.
                baseline_has_error = _contains_sql_error(
                    baseline
                )

                test_has_error = _contains_sql_error(
                    test_response
                )

                if test_has_error and not baseline_has_error:

                    findings.append({
                        "type": "Potential SQL Injection (error-based)",
                        "url": test_url,
                        "parameter": key,
                        "method": "GET",
                        "severity": "High",
                        "evidence": (
                            "A recognizable database error fingerprint "
                            "appeared only after a modified parameter. "
                            "This is a potential vulnerability and "
                            "requires manual verification."
                        ),
                        "recommendation": (
                            "Use parameterized queries or prepared "
                            "statements. Validate input server-side "
                            "and avoid exposing database errors "
                            "in client-facing responses."
                        ),
                    })

            except Exception as exc:
                logger.debug(
                    "SQL injection check failed for parameter %s: %s",
                    key,
                    exc,
                )

            finally:
                # Ensure network resources are released.
                for response in (baseline, test_response):

                    if response is not None:

                        try:
                            response.close()

                        except Exception:
                            pass

    logger.info(
        "SQL injection scan completed: %d potential findings",
        len(findings),
    )

    return findings
