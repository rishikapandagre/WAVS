
"""Low-impact same-origin web crawler for WAVS."""

from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from config import MAX_CRAWL_PAGES

from Utils.request_handler import (
    normalize_target,
    safe_get,
    same_origin,
    canonical_url,
    TargetError,
)

from Utils.logger import logger


# Maximum HTML content processed per page (1.5 MB).
MAX_HTML_SIZE = 1_500_000

# Maximum forms discovered per page.
MAX_FORMS_PER_PAGE = 100

# Maximum fields collected from one form.
MAX_FIELDS_PER_FORM = 100

# Links that may trigger state-changing actions.
SKIP_LINK_PATTERNS = (
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "delete",
    "remove",
    "unsubscribe",
    "deactivate",
    "disable",
    "reset",
    "destroy",
)


def _should_skip_link(url: str) -> bool:
    """
    Determine whether a URL should be skipped during crawling.

    Skips common state-changing routes to reduce unintended effects.
    """

    try:
        parsed = urlparse(url)

        path = parsed.path.lower()

        segments = path.split("/")

        return any(
            pattern in segment
            for segment in segments
            for pattern in SKIP_LINK_PATTERNS
        )

    except Exception:
        return True


def crawl(target: str, max_pages: int = MAX_CRAWL_PAGES):
    """
    Crawl HTML pages within the same origin.

    Forms are discovered but never submitted.

    Returns:
        {
            "target": str,
            "pages": list,
            "forms": list,
            "visited_count": int
        }
    """

    # Normalize and validate the target URL.
    target = normalize_target(target)

    # Validate the crawl limit.
    try:
        max_pages = int(max_pages)

    except (TypeError, ValueError, OverflowError):
        max_pages = MAX_CRAWL_PAGES

    max_pages = max(
        1,
        min(max_pages, MAX_CRAWL_PAGES)
    )

    queue = deque([target])

    visited = set()
    queued = {canonical_url(target)}

    pages = []
    forms = []

    # Track forms to avoid duplicates.
    discovered_forms = set()

    origin = target

    while queue and len(pages) < max_pages:

        current_url = canonical_url(
            queue.popleft()
        )

        queued.discard(current_url)

        if current_url in visited:
            continue

        visited.add(current_url)

        response = None

        try:
            # Fetch the current page safely.
            response = safe_get(current_url)

            # Skip non-HTML responses.
            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                continue

            # Skip pages with excessively large declared content.
            content_length = response.headers.get(
                "Content-Length"
            )

            if content_length:

                try:
                    if int(content_length) > MAX_HTML_SIZE:
                        logger.warning(
                            "Skipped oversized page: %s",
                            current_url,
                        )
                        continue

                except ValueError:
                    pass

            # Limit HTML processing.
            html_content = response.text[:MAX_HTML_SIZE]

            soup = BeautifulSoup(
                html_content,
                "html.parser"
            )

            # Use final URL after redirects.
            final_url = canonical_url(
                response.url
            )

            # Confirm the final response remains same-origin.
            if not same_origin(origin, final_url):

                logger.warning(
                    "Cross-origin response skipped: %s",
                    final_url,
                )

                continue

            # Extract the page title.
            title = ""

            if soup.title:
                title = soup.title.get_text(
                    strip=True
                )[:500]

            # Record the crawled page.
            pages.append({
                "url": final_url,
                "status": response.status_code,
                "title": title,
            })

            # =========================================
            # FORM DISCOVERY
            # =========================================

            for form in soup.find_all(
                "form",
                limit=MAX_FORMS_PER_PAGE
            ):

                fields = []

                for element in form.find_all(
                    ["input", "textarea", "select", "button"],
                    limit=MAX_FIELDS_PER_FORM
                ):

                    name = element.get("name")

                    if not name:
                        continue

                    field_type = element.get(
                        "type",
                        element.name
                    )

                    value = element.get(
                        "value",
                        ""
                    )

                    fields.append({
                        "name": str(name)[:300],
                        "type": str(field_type)[:100],
                        "value": str(value)[:500],
                    })

                # Resolve relative form actions.
                action = urljoin(
                    final_url,
                    form.get("action") or final_url
                )

                action = canonical_url(action)

                method = (
                    form.get("method") or "GET"
                ).strip().upper()

                # Keep only recognized HTTP methods.
                if method not in (
                    "GET",
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                ):
                    method = "GET"

                # Ignore external form actions.
                if not same_origin(origin, action):

                    logger.debug(
                        "External form action skipped: %s",
                        action,
                    )

                    continue

                # Avoid duplicate form records.
                form_key = (
                    final_url,
                    action,
                    method,
                    tuple(
                        field["name"]
                        for field in fields
                    ),
                )

                if form_key in discovered_forms:
                    continue

                discovered_forms.add(form_key)

                forms.append({
                    "page": final_url,
                    "action": action,
                    "method": method,
                    "fields": fields,
                })

            # =========================================
            # INTERNAL LINK DISCOVERY
            # =========================================

            for tag in soup.find_all(
                "a",
                href=True
            ):

                href = tag.get(
                    "href",
                    ""
                ).strip()

                if not href:
                    continue

                # Skip unsupported URL schemes.
                if href.lower().startswith(
                    (
                        "javascript:",
                        "mailto:",
                        "tel:",
                        "data:",
                        "file:",
                    )
                ):
                    continue

                try:
                    absolute_url = urljoin(
                        final_url,
                        href
                    )

                    link = canonical_url(
                        absolute_url
                    )

                    parsed_link = urlparse(link)

                    # Accept only HTTP and HTTPS links.
                    if parsed_link.scheme.lower() not in (
                        "http",
                        "https",
                    ):
                        continue

                    # Stay within the target's origin.
                    if not same_origin(origin, link):
                        continue

                    # Skip potentially state-changing links.
                    if _should_skip_link(link):
                        continue

                    # Avoid duplicate URLs in queue and visited set.
                    if (
                        link not in visited
                        and link not in queued
                    ):

                        queue.append(link)
                        queued.add(link)

                except (
                    ValueError,
                    TypeError,
                ) as exc:

                    logger.debug(
                        "Crawler skipped malformed link %s: %s",
                        href,
                        exc,
                    )

        except TargetError as exc:

            logger.warning(
                "Crawler blocked unsafe URL %s: %s",
                current_url,
                exc,
            )

        except Exception as exc:

            logger.exception(
                "Crawler encountered an error on %s: %s",
                current_url,
                exc,
            )

        finally:

            if response is not None:

                try:
                    response.close()

                except Exception:
                    pass

    # =============================================
    # CRAWL SUMMARY
    # =============================================

    logger.info(
        "Crawl completed for %s: %d pages, %d forms",
        target,
        len(pages),
        len(forms),
    )

    return {
        "target": target,
        "pages": pages,
        "forms": forms,
        "visited_count": len(pages),
    }
