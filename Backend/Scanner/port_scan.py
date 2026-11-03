
"""TCP port scanner for authorized security assessments."""

import ipaddress
import socket

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from Backend.config import DEFAULT_PORTS, MAX_PORTS
from Backend.Utils.request_handler import normalize_target
from Backend.Utils.logger import logger


DEFAULT_TIMEOUT = 0.45
MAX_TIMEOUT = 3.0
DEFAULT_WORKERS = 32
MAX_WORKERS = 64


def _validate_ports(ports):
    """Validate, deduplicate, and limit TCP ports."""
    if ports is None:
        ports = DEFAULT_PORTS

    if isinstance(ports, (str, bytes)):
        logger.warning("Ports must be an iterable of integers.")
        return []

    try:
        iterator = iter(ports)
    except TypeError:
        logger.warning("Invalid ports collection.")
        return []

    valid_ports = []

    for port in iterator:
        if isinstance(port, bool):
            continue

        try:
            if isinstance(port, float) and not port.is_integer():
                continue

            if isinstance(port, str):
                port = port.strip()
                if not port.isdigit():
                    continue

            port = int(port)

        except (ValueError, TypeError, OverflowError):
            continue

        if 1 <= port <= 65535:
            valid_ports.append(port)

    return list(dict.fromkeys(valid_ports))[:MAX_PORTS]


def _validate_timeout(timeout):
    """Return a bounded socket timeout."""
    try:
        timeout = float(timeout)
        if not 0 < timeout < float("inf"):
            raise ValueError
        return max(0.1, min(timeout, MAX_TIMEOUT))
    except (ValueError, TypeError, OverflowError):
        return DEFAULT_TIMEOUT


def _validate_workers(workers):
    """Return a bounded worker count."""
    try:
        if isinstance(workers, bool):
            raise ValueError

        workers = int(workers)

    except (ValueError, TypeError, OverflowError):
        workers = DEFAULT_WORKERS

    return max(1, min(workers, MAX_WORKERS))


def _resolve_host(host):
    """
    Resolve the hostname and reject non-public IP addresses.

    This protects the scanner from accidentally probing internal,
    loopback, link-local, and reserved network addresses.
    """
    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

    except socket.gaierror as exc:
        logger.warning("DNS resolution failed for %s: %s", host, exc)
        return None

    if not addresses:
        return None

    unique_addresses = {}

    for result in addresses:
        address = result[4][0]

        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue

        # Reject the target if ANY resolved address is non-public.
        if not ip.is_global:
            logger.warning(
                "Port scan rejected: %s resolved to a non-public IP.",
                host,
            )
            return None

        unique_addresses[str(ip)] = (
            socket.AF_INET6
            if isinstance(ip, ipaddress.IPv6Address)
            else socket.AF_INET,
            address,
        )

    return list(unique_addresses.values())


def scan_ports(target, ports=None, timeout=DEFAULT_TIMEOUT, workers=DEFAULT_WORKERS):
    """
    Scan TCP ports on an authorized public target.

    Args:
        target: Target URL, hostname, or IP address.
        ports: Iterable of TCP ports to scan.
        timeout: Socket timeout in seconds.
        workers: Maximum concurrent workers.

    Returns:
        Sorted list of dictionaries describing open TCP ports.
    """
    try:
        normalized = normalize_target(target)
        parsed = urlparse(normalized)
        host = parsed.hostname

    except (ValueError, TypeError) as exc:
        logger.warning("Invalid port scan target: %s", exc)
        return []

    if not host:
        logger.warning("Unable to extract hostname from target.")
        return []

    selected_ports = _validate_ports(ports)

    if not selected_ports:
        logger.info("No valid ports selected for scanning.")
        return []

    timeout = _validate_timeout(timeout)
    workers = _validate_workers(workers)

    resolved_addresses = _resolve_host(host)

    if not resolved_addresses:
        logger.warning("No safe addresses available for %s.", host)
        return []

    # Use a single resolved address to prevent unintended multi-host scans.
    socket_family, resolved_address = resolved_addresses[0]

    def check_port(port):
        """Attempt a TCP connection without sending application payloads."""
        try:
            with socket.socket(
                socket_family,
                socket.SOCK_STREAM,
            ) as sock:

                sock.settimeout(timeout)

                if socket_family == socket.AF_INET6:
                    address = (resolved_address, port, 0, 0)
                else:
                    address = (resolved_address, port)

                result = sock.connect_ex(address)

                if result != 0:
                    return None

                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"

                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                }

        except (socket.timeout, OSError) as exc:
            logger.debug("Port %s check failed: %s", port, exc)
            return None

    results = []
    max_workers = min(workers, len(selected_ports))

    logger.info(
        "Starting TCP port scan: host=%s ports=%d workers=%d",
        host,
        len(selected_ports),
        max_workers,
    )

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:

            futures = {
                executor.submit(check_port, port): port
                for port in selected_ports
            }

            for future in as_completed(futures):
                try:
                    result = future.result()

                    if result:
                        results.append(result)

                except Exception:
                    logger.exception(
                        "Port scan worker failed for port %s",
                        futures[future],
                    )

    except Exception:
        logger.exception("TCP port scan failed for host %s", host)
        return results

    results.sort(key=lambda item: item["port"])

    logger.info(
        "TCP port scan completed: host=%s open_ports=%d",
        host,
        len(results),
    )

    return results
