
"""Centralized and security-conscious HTTP request handling for WAVS."""

import ipaddress
import os
import socket

from urllib.parse import urlparse, urljoin, urldefrag

import requests

from Backend.config import REQUEST_TIMEOUT, USER_AGENT, ALLOWED_SCHEMES


class TargetError(ValueError):
    """Raised when a target URL is invalid or unsafe."""


# ==================================================
# CONFIGURATION
# ==================================================

MAX_REDIRECTS = 5
MAX_URL_LENGTH = 4096

ALLOW_PRIVATE_TARGETS = (
    os.getenv("WAVS_ALLOW_PRIVATE_TARGETS", "0")
    .strip()
    .lower()
    in {"1", "true", "yes"}
)


# ==================================================
# HTTP SESSION
# ==================================================

def _create_session():
    """Create a reusable HTTP session with safe defaults."""
    session = requests.Session()

    # Do not inherit proxy settings from the environment.
    # This prevents unexpected proxy routing.
    session.trust_env = False

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,"
                 "application/xml;q=0.9,*/*;q=0.8",
    })

    return session


SESSION = _create_session()


# ==================================================
# URL NORMALIZATION
# ==================================================

def normalize_target(url: str) -> str:
    """
    Validate and normalize a target URL.

    - Defaults to HTTPS when no scheme is specified.
    - Accepts only HTTP and HTTPS.
    - Rejects embedded credentials.
    - Validates hostname and port.
    - Removes fragments.
    - Preserves query parameters.
    """
    if not isinstance(url, str):
        raise TargetError("Please provide a valid target URL.")

    url = url.strip()

    if not url:
        raise TargetError("Please provide a target URL.")

    if len(url) > MAX_URL_LENGTH:
        raise TargetError("The target URL is too long.")

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in ALLOWED_SCHEMES:
            raise TargetError(
                "Only HTTP and HTTPS URLs are accepted."
            )

        hostname = parsed.hostname

        if not hostname:
            raise TargetError("The target URL has no valid hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise TargetError(
                "URLs containing credentials are not accepted."
            )

        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetError(
                "The target URL contains an invalid port."
            ) from exc

        if port is not None and not 1 <= port <= 65535:
            raise TargetError(
                "Port must be between 1 and 65535."
            )

        hostname = hostname.lower()

        # Normalize internationalized domain names.
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetError("Invalid hostname.") from exc

        # Preserve IPv6 brackets.
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        # Remove default ports.
        if port is not None:
            if not (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            ):
                hostname = f"{hostname}:{port}"

        normalized = parsed._replace(
            scheme=scheme,
            netloc=hostname,
            path=parsed.path or "/",
            fragment="",
        )

        return normalized.geturl()

    except TargetError:
        raise

    except (ValueError, TypeError, UnicodeError) as exc:
        raise TargetError(
            "Invalid URL format. Please provide a valid HTTP/HTTPS URL."
        ) from exc


# ==================================================
# HOST VALIDATION
# ==================================================

def _is_blocked_hostname(hostname):
    """Check for local and special-use hostnames."""
    hostname = hostname.lower().rstrip(".")

    if hostname in {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }:
        return True

    if hostname.endswith(".localhost"):
        return True

    if hostname.endswith(".local"):
        return True

    return False


def _resolve_public_addresses(hostname, port):
    """
    Resolve a hostname and reject non-global addresses.

    Reject the entire hostname if any resolved address is
    private, reserved, loopback, or otherwise non-global.
    """
    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

    except socket.gaierror as exc:
        raise TargetError(
            "The target hostname could not be resolved."
        ) from exc

    if not results:
        raise TargetError(
            "No IP addresses were found for the target."
        )

    addresses = set()

    for result in results:
        raw_address = result[4][0]

        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise TargetError(
                "The target resolved to an invalid IP address."
            ) from exc

        if not ALLOW_PRIVATE_TARGETS and not address.is_global:
            raise TargetError(
                "The target resolves to a private, loopback, "
                "reserved, or non-public IP address."
            )

        addresses.add(str(address))

    return addresses


def _validate_http_url(url: str) -> str:
    """
    Validate a URL before making an HTTP request.

    Returns:
        The validated URL.

    Raises:
        TargetError: If the destination is unsafe.
    """
    if not isinstance(url, str) or not url:
        raise TargetError("Invalid request URL.")

    if len(url) > MAX_URL_LENGTH:
        raise TargetError("The request URL is too long.")

    try:
        parsed = urlparse(url)

        scheme = parsed.scheme.lower()

        if scheme not in ALLOWED_SCHEMES:
            raise TargetError(
                "Only HTTP and HTTPS requests are allowed."
            )

        hostname = parsed.hostname

        if not hostname:
            raise TargetError(
                "The request URL has no valid hostname."
            )

        if parsed.username is not None or parsed.password is not None:
            raise TargetError(
                "URLs containing credentials are not accepted."
            )

        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetError(
                "The request URL contains an invalid port."
            ) from exc

        if port is not None and not 1 <= port <= 65535:
            raise TargetError("Invalid destination port.")

        if ALLOW_PRIVATE_TARGETS:
            return url

        if _is_blocked_hostname(hostname):
            raise TargetError(
                "Local and special-use hostnames are blocked."
            )

        try:
            ipaddress.ip_address(hostname)

        except ValueError:
            # Hostname: resolve and validate its IP addresses.
            _resolve_public_addresses(
                hostname,
                port or (443 if scheme == "https" else 80),
            )

        else:
            # Literal IP address.
            address = ipaddress.ip_address(hostname)

            if not address.is_global:
                raise TargetError(
                    "Private, loopback, reserved, and "
                    "non-public IP addresses are blocked."
                )

        return url

    except TargetError:
        raise

    except (ValueError, TypeError, OSError) as exc:
        raise TargetError(
            "The request URL is invalid or unsafe."
        ) from exc


# ==================================================
# ORIGIN VALIDATION
# ==================================================

def _get_origin(url):
    """Return normalized scheme, hostname, and effective port."""
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else None

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80

    return scheme, hostname, port


def same_origin(a: str, b: str) -> bool:
    """
    Determine whether two URLs belong to the same origin.

    Origin consists of scheme, hostname, and effective port.
    """
    try:
        origin_a = _get_origin(a)
        origin_b = _get_origin(b)

        if origin_a is None or origin_b is None:
            return False

        return origin_a == origin_b

    except (ValueError, AttributeError, TypeError):
        return False


# ==================================================
# SAFE HTTP GET
# ==================================================

def safe_get(url: str, session=None, **kwargs):
    """
    Perform a controlled HTTP GET request.

    Features:
    - Validates initial and redirected destinations.
    - Enforces request timeouts.
    - Limits redirect count.
    - Blocks cross-origin redirects.
    - Disables automatic redirect handling.
    - Returns requests.Response.

    Raises:
        TargetError: Unsafe URL or redirect.
        requests.RequestException: Request failure.
    """
    client = session or SESSION

    current_url = url
    original_url = url

    # Validate the initial URL.
    _validate_http_url(current_url)

    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("User-Agent", USER_AGENT)

    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT)

    # Prevent callers from overriding security controls.
    kwargs.pop("allow_redirects", None)
    kwargs.pop("verify", None)

    kwargs["verify"] = True

    for redirect_count in range(MAX_REDIRECTS + 1):

        response = client.get(
            current_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            **kwargs,
        )

        if response.status_code not in {
            301, 302, 303, 307, 308
        }:
            return response

        if redirect_count >= MAX_REDIRECTS:
            response.close()

            raise TargetError(
                "Maximum redirect limit exceeded."
            )

        location = response.headers.get("Location")

        if not location:
            return response

        # Resolve relative redirects.
        next_url = urljoin(current_url, location)

        try:
            _validate_http_url(next_url)

        except TargetError:
            response.close()
            raise

        # Prevent redirects outside the original origin.
        if not same_origin(original_url, next_url):
            response.close()

            raise TargetError(
                "Cross-origin redirect blocked for security."
            )

        response.close()
        current_url = next_url

    raise TargetError(
        "Unable to complete HTTP request safely."
    )


# ==================================================
# CANONICAL URL
# ==================================================

def canonical_url(url: str) -> str:
    """
    Remove URL fragments for consistent crawler comparison.

    Fragments are not sent to the server and should not
    create duplicate crawler entries.
    """
    if not isinstance(url, str):
        return ""

    url, _ = urldefrag(url)

    return url
