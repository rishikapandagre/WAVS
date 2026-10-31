
"""Low-impact reflected XSS detection.

Uses harmless marker strings only.
Does not execute JavaScript or submit forms.
Only use against authorized targets.
"""

from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)

from Utils.request_handler import safe_get
from Utils.payloads import XSS_MARKER
from Utils.logger import logger


MAX_RESPONSE_SIZE = 500_000


def _replace_param(url, key, value):
    """
    Replace the first occurrence of a query parameter
    while preserving all remaining query parameters.
    """

    parsed = urlparse(url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    output = []
    changed = False

    for parameter, current_value in pairs:

        if parameter == key and not changed:
            output.append((parameter, value))
            changed = True

        else:
            output.append((parameter, current_value))

    # Return the original URL if the parameter
    # could not be found.
    if not changed:
        return url

    return urlunparse(
        parsed._replace(
            query=urlencode(output, doseq=True)
        )
    )


def scan_xss(pages, forms=None):
    """
    Detect potential reflected XSS through GET parameters.

    Uses harmless marker strings without executing
    JavaScript or submitting forms.

    Returns:
        A list of potential reflected XSS findings.
    """

    findings = []
    tested = set()

    # Safely process crawled pages.
    for page in pages or []:

        if not isinstance(page, dict):
            continue

        url = page.get("url", "")

        if not url:
            continue

        parameters = parse_qsl(
            urlparse(url).query,
            keep_blank_values=True,
        )

        for key, _ in parameters:

            # Avoid testing the same parameter repeatedly.
            test_key = (url, key)

            if test_key in tested:
                continue

            tested.add(test_key)

            response = None

            try:
                # Replace the parameter with a harmless marker.
                test_url = _replace_param(
                    url,
                    key,
                    XSS_MARKER,
                )

                if test_url == url:
                    continue

                response = safe_get(test_url)

                if response is None:
                    continue

                # Limit response content processing.
                body = response.text[:MAX_RESPONSE_SIZE]

                # Detect marker reflection.
                if XSS_MARKER in body:

                    findings.append({
                        "type": "Potential Reflected XSS",
                        "url": response.url or test_url,
                        "parameter": key,
                        "method": "GET",
                        "severity": "Medium",
                        "evidence": (
                            "A harmless unique marker was reflected "
                            "in the response. Context, HTML encoding, "
                            "and JavaScript execution were not evaluated."
                        ),
                        "recommendation": (
                            "Apply context-aware output encoding "
                            "and validate input. Confirm manually "
                            "in a safe test environment."
                        ),
                    })

            except Exception as exc:
                logger.info(
                    "XSS check skipped %s: %s",
                    url,
                    exc,
                )

            finally:
                # Always release response resources.
                if response is not None:
                    response.close()

    # Forms are intentionally not submitted because
    # submissions may trigger server-side side effects.

    return findings
