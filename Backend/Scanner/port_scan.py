
"""TCP port scanner for authorized security assessments."""

import socket
import ipaddress

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from config import DEFAULT_PORTS, MAX_PORTS
from Utils.request_handler import normalize_target
from Utils.logger import logger


def scan_ports(target, ports=None, timeout=0.45, workers=32):
    """
    Scan a limited list of TCP ports on an authorized target.

    Args:
        target: Target URL, hostname, or IP address.
        ports: Iterable of TCP ports to scan.
        timeout: Socket timeout in seconds.
        workers: Maximum concurrent workers.

    Returns:
        A sorted list of open-port dictionaries.
    """

    # =============================================
    # TARGET VALIDATION
    # =============================================

    try:
        normalized = normalize_target(target)
        parsed = urlparse(normalized)
        host = parsed.hostname

    except (ValueError, TypeError) as exc:
        logger.warning("Invalid port scan target: %s", exc)
        return []

    if not host:
        logger.warning(
            "Unable to extract hostname from target."
        )
        return []

    # Determine address family where possible.
    try:
        ip_address = ipaddress.ip_address(host)

        if isinstance(ip_address, ipaddress.IPv6Address):
            address_family = socket.AF_INET6
        else:
            address_family = socket.AF_INET

    except ValueError:
        # Hostname: let getaddrinfo resolve it.
        address_family = socket.AF_UNSPEC

    # =============================================
    # PORT VALIDATION
    # =============================================

    if ports is None:
        ports = DEFAULT_PORTS

    valid_ports = []

    try:
        for port in ports:

            try:
                port = int(port)

                if 1 <= port <= 65535:
                    valid_ports.append(port)

                else:
                    logger.warning(
                        "Port out of range, skipped: %s",
                        port
                    )

            except (TypeError, ValueError, OverflowError):
                logger.warning(
                    "Invalid port skipped: %s",
                    port
                )

    except TypeError:
        logger.warning(
            "Invalid ports collection provided."
        )
        return []

    # Deduplicate and enforce configured maximum.
    ports = list(dict.fromkeys(valid_ports))[:MAX_PORTS]

    if not ports:
        logger.info("No valid ports selected for scanning.")
        return []

    # =============================================
    # TIMEOUT VALIDATION
    # =============================================

    try:
        timeout = float(timeout)

    except (TypeError, ValueError, OverflowError):
        timeout = 0.45

    # Keep timeout within reasonable limits.
    timeout = max(
        0.1,
        min(timeout, 3.0)
    )

    # =============================================
    # WORKER VALIDATION
    # =============================================

    try:
        workers = int(workers)

    except (TypeError, ValueError, OverflowError):
        workers = 32

    workers = max(
        1,
        min(workers, 64)
    )

    # =============================================
    # HOST RESOLUTION
    # =============================================

    try:
        resolved_addresses = socket.getaddrinfo(
            host,
            None,
            family=address_family,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror as exc:
        logger.warning(
            "Unable to resolve target hostname %s: %s",
            host,
            exc
        )
        return []

    if not resolved_addresses:
        logger.warning(
            "No addresses found for target: %s",
            host
        )
        return []

    # Use one resolved address to avoid scanning multiple
    # addresses unintentionally for a single hostname.
    resolved_address = resolved_addresses[0][4][0]

    # Determine socket family from resolved address.
    resolved_ip = ipaddress.ip_address(
        resolved_address
    )

    if isinstance(resolved_ip, ipaddress.IPv6Address):
        socket_family = socket.AF_INET6
    else:
        socket_family = socket.AF_INET

    # =============================================
    # PORT CHECK
    # =============================================

    def check(port):
        """
        Check whether a single TCP port is open.

        Uses a TCP connection attempt only.
        No service exploitation or payload transmission.
        """

        try:
            with socket.socket(
                socket_family,
                socket.SOCK_STREAM
            ) as sock:

                sock.settimeout(timeout)

                connection_code = sock.connect_ex(
                    (resolved_address, port)
                )

                if connection_code != 0:
                    return None

                # Resolve the registered TCP service name.
                try:
                    service = socket.getservbyport(
                        port,
                        "tcp"
                    )

                except OSError:
                    service = "unknown"

                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                }

        except (socket.timeout, OSError) as exc:
            logger.debug(
                "Port %s check failed: %s",
                port,
                exc
            )

        except Exception as exc:
            logger.warning(
                "Unexpected port scan error on port %s: %s",
                port,
                exc
            )

        return None

    # =============================================
    # CONCURRENT SCANNING
    # =============================================

    results = []

    max_workers = min(
        workers,
        len(ports)
    )

    logger.info(
        "Starting TCP port scan on %s (%d ports)",
        host,
        len(ports)
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as pool:

        futures = {
            pool.submit(check, port): port
            for port in ports
        }

        for future in as_completed(futures):

            try:
                result = future.result()

                if result is not None:
                    results.append(result)

            except Exception as exc:

                port = futures[future]

                logger.warning(
                    "Port scan worker failed on port %s: %s",
                    port,
                    exc
                )

    # =============================================
    # RESULTS
    # =============================================

    results.sort(
        key=lambda item: item["port"]
    )

    logger.info(
        "Port scan completed for %s: %d open ports found",
        host,
        len(results)
    )

    return results
