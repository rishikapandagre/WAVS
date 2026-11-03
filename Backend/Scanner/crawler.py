
"""Low-impact, configurable same-origin web crawler for WAVS."""

from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from Backend.config import (
    MAX_CRAWL_PAGES,
    REQUEST_TIMEOUT,
    MAX_SCAN_REQUESTS,
)

from Backend.Utils.request_handler import (
    normalize_target,
    safe_get,
    same_origin,
    canonical_url,
    TargetError,
)

from Backend.Utils.logger import logger


# ==================================================
# CRAWLER CONFIGURATION
# ==================================================

MAX_HTML_SIZE = 1_500_000

MAX_FORMS_PER_PAGE = 100

MAX_FIELDS_PER_FORM = 100

MAX_LINKS_PER_PAGE = 1000

MAX_TITLE_LENGTH = 500

MAX_FIELD_NAME_LENGTH = 300

MAX_FIELD_VALUE_LENGTH = 500


# ==================================================
# UNSAFE LINK PATTERNS
# ==================================================

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


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def _should_skip_link(url: str) -> bool:
    """Skip common state-changing routes."""

    try:
        parsed = urlparse(url)

        segments = [
            segment.lower()
            for segment in parsed.path.split("/")
        ]

        return any(
            pattern in segment
            for segment in segments
            for pattern in SKIP_LINK_PATTERNS
        )

    except (ValueError, TypeError):
        return True


def _is_valid_content_type(response) -> bool:
    """Determine whether a response contains HTML."""

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
    )


def _is_oversized_response(response) -> bool:
    """Check declared response size before processing."""

    content_length = response.headers.get(
        "Content-Length",
    )

    if not content_length:
        return False

    try:
        return int(content_length) > MAX_HTML_SIZE

    except (ValueError, TypeError):
        return False


def _extract_title(soup) -> str:
    """Extract and normalize the page title."""

    if not soup.title:
        return ""

    return soup.title.get_text(
        separator=" ",
        strip=True,
    )[:MAX_TITLE_LENGTH]


def _extract_form_fields(form):
    """Extract form fields without submitting the form."""

    fields = []

    for element in form.find_all(
        ["input", "textarea", "select", "button"],
        limit=MAX_FIELDS_PER_FORM,
    ):

        name = element.get("name")

        if not name:
            continue

        field_type = element.get(
            "type",
            element.name,
        )

        value = element.get(
            "value",
            "",
        )

        fields.append({
            "name": str(name)[:MAX_FIELD_NAME_LENGTH],
            "type": str(field_type)[:100],
            "value": str(value)[:MAX_FIELD_VALUE_LENGTH],
        })

    return fields


def _normalize_form_method(method):
    """Normalize the HTML form method."""

    method = (
        method or "GET"
    ).strip().upper()

    if method not in ("GET", "POST"):
        method = "GET"

    return method


def _resolve_link(base_url, href):
    """Resolve and validate a discovered link."""

    if not href:
        return None

    href = href.strip()

    if href.lower().startswith(
        (
            "javascript:",
            "mailto:",
            "tel:",
            "data:",
            "file:",
        )
    ):
        return None

    try:

        absolute_url = urljoin(
            base_url,
            href,
        )

        link = canonical_url(
            absolute_url,
        )

        parsed = urlparse(link)

        if parsed.scheme.lower() not in (
            "http",
            "https",
        ):
            return None

        return link

    except (
        ValueError,
        TypeError,
    TargetError,
    Exception,
    ):
        return None


# ==================================================
# MAIN CRAWLER
# ==================================================

def crawl(
    target: str,
    max_pages: int = MAX_CRAWL_PAGES,
):
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

    # --------------------------------------------------
    # VALIDATE TARGET
    # --------------------------------------------------

    target = normalize_target(target)

    # --------------------------------------------------
    # VALIDATE CRAWL LIMIT
    # --------------------------------------------------

    try:

        if isinstance(max_pages, bool):
            raise ValueError

        max_pages = int(max_pages)

    except (
        TypeError,
        ValueError,
        OverflowError,
    ):

        max_pages = MAX_CRAWL_PAGES

    max_pages = max(
        1,
        min(
            max_pages,
            MAX_CRAWL_PAGES,
        ),
    )

    # --------------------------------------------------
    # INITIALIZE CRAWLER
    # --------------------------------------------------

    origin = target

    queue = deque([
        canonical_url(target)
    ])

    queued = {
        canonical_url(target)
    }

    visited = set()

    pages = []

    forms = []

    discovered_forms = set()

    total_requests = 0

    # --------------------------------------------------
    # CRAWL LOOP
    # --------------------------------------------------

    while queue and len(pages) < max_pages:

        # Respect the overall request budget.
        if total_requests >= MAX_SCAN_REQUESTS:

            logger.warning(
                "Crawler reached request limit: %s",
                MAX_SCAN_REQUESTS,
            )

            break

        current_url = canonical_url(
            queue.popleft()
        )

        queued.discard(current_url)

        if current_url in visited:
            continue

        visited.add(current_url)

        response = None

        try:

            # ------------------------------------------
            # FETCH PAGE
            # ------------------------------------------

            response = safe_get(
                current_url,
                timeout=REQUEST_TIMEOUT,
            )

            total_requests += 1

            # ------------------------------------------
            # VALIDATE RESPONSE
            # ------------------------------------------

            if not _is_valid_content_type(response):
                continue

            if _is_oversized_response(response):

                logger.warning(
                    "Skipped oversized page: %s",
                    current_url,
                )

                continue

            # ------------------------------------------
            # PROCESS HTML
            # ------------------------------------------

            html_content = response.text[
                :MAX_HTML_SIZE
            ]

            soup = BeautifulSoup(
                html_content,
                "html.parser",
            )

            # ------------------------------------------
            # VALIDATE REDIRECT
            # ------------------------------------------

            final_url = canonical_url(
                response.url
            )

            if not same_origin(
                origin,
                final_url,
            ):

                logger.warning(
                    "Cross-origin redirect blocked: %s",
                    final_url,
                )

                continue

            # ------------------------------------------
            # EXTRACT PAGE INFORMATION
            # ------------------------------------------

            title = _extract_title(
                soup
            )

            pages.append({
                "url": final_url,
                "status": response.status_code,
                "title": title,
            })

            logger.debug(
                "Crawled page: %s",
                final_url,
            )

            # ==========================================
            # FORM DISCOVERY
            # ==========================================

            for form in soup.find_all(
                "form",
                limit=MAX_FORMS_PER_PAGE,
            ):

                fields = _extract_form_fields(
                    form
                )

                action = urljoin(
                    final_url,
                    form.get("action") or final_url,
                )

                try:

                    action = canonical_url(
                        action
                    )

                except TargetError:

                    logger.debug(
                        "Invalid form action skipped."
                    )

                    continue

                method = _normalize_form_method(
                    form.get("method")
                )

                # --------------------------------------
                # SAME-ORIGIN VALIDATION
                # --------------------------------------

                if not same_origin(
                    origin,
                    action,
                ):

                    logger.debug(
                        "External form skipped: %s",
                        action,
                    )

                    continue

                # --------------------------------------
                # DEDUPLICATE FORMS
                # --------------------------------------

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

                discovered_forms.add(
                    form_key
                )

                forms.append({
                    "page": final_url,
                    "action": action,
                    "method": method,
                    "fields": fields,
                })

            # ==========================================
            # LINK DISCOVERY
            # ==========================================

            links = soup.find_all(
                "a",
                href=True,
                limit=MAX_LINKS_PER_PAGE,
            )

            for tag in links:

                href = tag.get(
                    "href",
                    "",
                )

                link = _resolve_link(
                    final_url,
                    href,
                )

                if not link:
                    continue

                # --------------------------------------
                # SAME-ORIGIN RESTRICTION
                # --------------------------------------

                if not same_origin(
                    origin,
                    link,
                ):
                    continue

                # --------------------------------------
                # SKIP UNSAFE ROUTES
                # --------------------------------------

                if _should_skip_link(link):
                    continue

                # --------------------------------------
                # AVOID DUPLICATE QUEUE ENTRIES
                # --------------------------------------

                if (
                    link not in visited
                    and link not in queued
                ):

                    queue.append(link)

                    queued.add(link)

        # --------------------------------------------------
        # EXCEPTION HANDLING
        # --------------------------------------------------

        except TargetError as exc:

            logger.warning(
                "Blocked unsafe URL %s: %s",
                current_url,
                exc,
            )

        except Exception:

            logger.exception(
                "Crawler failed on page: %s",
                current_url,
            )

        finally:

            if response is not None:

                try:
                    response.close()

                except Exception:
                    pass

    # ==================================================
    # CRAWL SUMMARY
    # ==================================================

    logger.info(
        "Crawl completed | Target: %s | Pages: %d | "
        "Forms: %d | Requests: %d",
        target,
        len(pages),
        len(forms),
        total_requests,
    )

    return {
        "target": target,
        "pages": pages,
        "forms": forms,
        "visited_count": len(pages),
    }
