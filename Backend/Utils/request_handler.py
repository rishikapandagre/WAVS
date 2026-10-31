
import os
import ipaddress
import socket

from urllib.parse import urlparse, urljoin, urldefrag

import requests

from config import REQUEST_TIMEOUT, USER_AGENT, ALLOWED_SCHEMES


class TargetError(ValueError):
    """Raised when a target URL is invalid or unsafe."""
    pass


# Reusable HTTP session for connection management.
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

# Maximum number of redirects allowed per request.
MAX_REDIRECTS = 5

# Private/local targets are blocked by default to reduce SSRF risks.
# Enable this only for authorized local testing environments.
ALLOW_PRIVATE_TARGETS = (
    os.getenv("WAVS_ALLOW_PRIVATE_TARGETS", "0").strip().lower()
    in {"1", "true", "yes"}
)


def normalize_target(url: str) -> str:
    """
    Validate and normalize a target URL.

    Features:
    - Adds HTTPS if no scheme is provided.
    - Accepts only HTTP and HTTPS.
    - Rejects embedded credentials.
    - Validates hostname and port.
    - Removes URL fragments.
    """

    url = (url or "").strip()

    if not url:
        raise TargetError("Please provide a target URL.")

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)

        scheme = parsed.scheme.lower()

        if scheme not in ALLOWED_SCHEMES:
            raise TargetError(
                "Only valid HTTP/HTTPS URLs are accepted."
            )

        if not parsed.hostname:
            raise TargetError(
                "The provided URL has no valid hostname."
            )

        if parsed.username or parsed.password:
            raise TargetError(
                "URLs containing credentials are not accepted."
            )

        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetError(
                "The provided URL contains an invalid port."
            ) from exc

        if port is not None and not (1 <= port <= 65535):
            raise TargetError(
                "Port must be between 1 and 65535."
            )

        hostname = parsed.hostname.lower()

        # Preserve IPv6 brackets when constructing the netloc.
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        # Remove default ports for cleaner normalization.
        if port is not None:
            if not (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            ):
                hostname = f"{hostname}:{port}"

        path = parsed.path.rstrip("/")

        normalized = parsed._replace(
            scheme=scheme,
            netloc=hostname,
            path=path,
            fragment=""
        )

        result = normalized.geturl().rstrip("/")

        if not result:
            return f"{scheme}://{hostname}"

        return result

    except TargetError:
        raise

    except Exception as exc:
        raise TargetError(
            "Invalid URL format. Please provide a valid HTTP/HTTPS URL."
        ) from exc


def _validate_http_url(url: str) -> str:
    """
    Validate a URL before making an HTTP request.

    Rejects:
    - Unsupported schemes.
    - Missing hostnames.
    - Embedded credentials.
    - Invalid ports.
    - Local/private IP addresses unless explicitly permitted.

    Returns the validated URL.
    """

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise TargetError(
                "Only HTTP and HTTPS requests are allowed."
            )

        hostname = parsed.hostname

        if not hostname:
            raise TargetError(
                "The request URL has no valid hostname."
            )

        if parsed.username or parsed.password:
            raise TargetError(
                "URLs containing credentials are not accepted."
            )

        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetError(
                "The request URL contains an invalid port."
            ) from exc

        if port is not None and not (1 <= port <= 65535):
            raise TargetError(
                "Port must be between 1 and 65535."
            )

        if ALLOW_PRIVATE_TARGETS:
            return url

        # Reject local hostnames.
        if hostname.lower() == "localhost" or hostname.lower().endswith(
            ".localhost"
        ):
            raise TargetError(
                "Localhost targets are blocked. "
                "Set WAVS_ALLOW_PRIVATE_TARGETS=1 for authorized local testing."
            )

        # Check literal IP addresses.
        try:
            ip = ipaddress.ip_address(hostname)

            if not ip.is_global:
                raise TargetError(
                    "Private, loopback, or reserved IP addresses are blocked."
                )

            return url

        except ValueError:
            # Hostname is not a literal IP address.
            pass

        # Resolve hostname and reject internal/private destinations.
        try:
            addresses = socket.getaddrinfo(
                hostname,
                port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM
            )

            if not addresses:
                raise TargetError(
                    "The target hostname could not be resolved."
                )

            for address_info in addresses:
                resolved_ip = ipaddress.ip_address(
                    address_info[4][0]
                )

                if not resolved_ip.is_global:
                    raise TargetError(
                        "The target resolves to a private, loopback, "
                        "or reserved IP address."
                    )

        except TargetError:
            raise

        except socket.gaierror as exc:
            raise TargetError(
                "The target hostname could not be resolved."
            ) from exc

        return url

    except TargetError:
        raise

    except Exception as exc:
        raise TargetError(
            "The request URL is invalid or unsafe."
        ) from exc


def same_origin(a: str, b: str) -> bool:
    """
    Check whether two URLs belong to the same origin.

    Origin consists of scheme, hostname, and effective port.
    """

    try:
        pa = urlparse(a)
        pb = urlparse(b)

        scheme_a = pa.scheme.lower()
        scheme_b = pb.scheme.lower()

        port_a = pa.port or (
            443 if scheme_a == "https" else 80
        )
        port_b = pb.port or (
            443 if scheme_b == "https" else 80
        )

        return (
            scheme_a,
            pa.hostname.lower() if pa.hostname else None,
            port_a
        ) == (
            scheme_b,
            pb.hostname.lower() if pb.hostname else None,
            port_b
        )

    except (ValueError, AttributeError):
        return False


def safe_get(url: str, session=None, **kwargs):
    """
    Perform a controlled HTTP GET request.

    Features:
    - Uses configured timeout and User-Agent.
    - Validates the initial destination.
    - Limits redirects.
    - Validates each redirect destination.
    - Blocks cross-origin redirects.
    - Disables automatic redirect handling.

    Returns:
        requests.Response

    Raises:
        TargetError: If a destination or redirect is unsafe.
        requests.RequestException: If the request fails.
    """

    client = session or SESSION

    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("User-Agent", USER_AGENT)

    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT)

    current_url = url
    original_url = url

    # Validate the initial destination before making a request.
    _validate_http_url(current_url)

    for redirect_count in range(MAX_REDIRECTS + 1):

        response = client.get(
            current_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            **kwargs
        )

        # Return response if it is not a redirect.
        if response.status_code not in (
            301, 302, 303, 307, 308
        ):
            return response

        # Stop if maximum redirect limit is reached.
        if redirect_count >= MAX_REDIRECTS:
            response.close()

            raise TargetError(
                "Maximum redirect limit exceeded."
            )

        redirect_location = response.headers.get("Location")

        if not redirect_location:
            return response

        # Resolve relative redirect URLs.
        next_url = urljoin(current_url, redirect_location)

        try:
            # Validate the redirect destination.
            _validate_http_url(next_url)

        except TargetError:
            response.close()
            raise

        # Block redirects to different origins.
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


def canonical_url(url: str) -> str:
    """
    Remove URL fragments for consistent URL comparison.

    Fragments are not sent to the server and should not create
    duplicate crawler entries.
    """

    url, _ = urldefrag(url)

    parsed = urlparse(url)

    return parsed._replace(fragment="").geturl()
