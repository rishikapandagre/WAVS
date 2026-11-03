
"""Low-impact reflected XSS detection for authorized assessments.

Uses harmless marker strings only.
Does not execute JavaScript or automatically submit forms.
"""

from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)

from Backend.config import REQUEST_TIMEOUT
from Backend.Utils.request_handler import safe_get
from Backend.Utils.payloads import XSS_MARKER
from Backend.Utils.logger import logger


MAX_RESPONSE_SIZE = 500_000
MAX_PARAMETERS_PER_URL = 50


# =============================================
# QUERY PARAMETER REPLACEMENT
# =============================================

def _replace_param(url, key, value):
    """
    Replace the first occurrence of a query parameter
    while preserving all remaining query parameters.
    """
    try:
        parsed = urlparse(url)

        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            max_num_fields=MAX_PARAMETERS_PER_URL,
        )

        output = []
        changed = False

        for parameter, current_value in pairs:

            if parameter == key and not changed:
                output.append((parameter, value))
                changed = True

            else:
                output.append((parameter, current_value))

        if not changed:
            return url

        return urlunparse(
            parsed._replace(
                query=urlencode(output, doseq=True)
            )
        )

    except (ValueError, TypeError) as exc:
        logger.debug("Unable to replace query parameter: %s", exc)
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


def _contains_marker(response):
    """Check whether the harmless marker appears in the response."""
    return XSS_MARKER in _get_response_body(response)


# =============================================
# REFLECTED XSS SCANNER
# =============================================

def scan_xss(pages, forms=None):
    """
    Detect potential reflected XSS through GET parameters.

    Does not execute JavaScript or submit forms.

    Returns:
        A list of potential reflected XSS findings.
    """
    findings = []
    tested = set()

    if not isinstance(pages, (list, tuple)):
        logger.warning("XSS scanner received invalid pages input.")
        return findings

    for page in pages:

        if not isinstance(page, dict):
            continue

        url = page.get("url")

        if not isinstance(url, str) or not url:
            continue

        try:
            parsed = urlparse(url)

            parameters = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=MAX_PARAMETERS_PER_URL,
            )

        except (ValueError, TypeError):
            logger.debug("Skipping malformed URL during XSS scan.")
            continue

        for key, _ in parameters:

            test_key = (url, key)

            if test_key in tested:
                continue

            tested.add(test_key)

            response = None

            try:
                # Replace the selected parameter with a harmless marker.
                test_url = _replace_param(
                    url,
                    key,
                    XSS_MARKER,
                )

                if not test_url or test_url == url:
                    continue

                response = safe_get(
                    test_url,
                    timeout=REQUEST_TIMEOUT,
                )

                if response is None:
                    continue

                # Detect whether the marker is reflected.
                if _contains_marker(response):

                    findings.append({
                        "type": "Potential Reflected XSS",
                        "url": response.url or test_url,
                        "parameter": key,
                        "method": "GET",
                        "severity": "Medium",
                        "evidence": (
                            "A harmless unique marker was reflected "
                            "in the response. HTML context, output "
                            "encoding, and JavaScript execution were "
                            "not evaluated. Manual verification "
                            "is required."
                        ),
                        "recommendation": (
                            "Apply context-aware output encoding, "
                            "validate input, and use safe templating "
                            "practices. Confirm manually in an "
                            "authorized test environment."
                        ),
                    })

            except Exception as exc:
                logger.debug(
                    "XSS check failed for parameter %s: %s",
                    key,
                    exc,
                )

            finally:
                if response is not None:

                    try:
                        response.close()

                    except Exception:
                        pass

    logger.info(
        "Reflected XSS scan completed: %d potential findings",
        len(findings),
    )

    return findings
