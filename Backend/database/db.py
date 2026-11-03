
"""SQLite database operations for WAVS scan history."""

import sqlite3
import json

from pathlib import Path
from datetime import datetime, timezone

from Backend.config import DATABASE_PATH


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    """
    Create and return a SQLite database connection.

    Features:
        - Automatically creates the database directory.
        - Enables dictionary-like row access.
        - Sets a database timeout.
        - Enables foreign key support.
        - Configures busy timeout.
    """

    database_path = Path(DATABASE_PATH)

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    conn = sqlite3.connect(
        str(database_path),
        timeout=15
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA busy_timeout = 15000"
    )

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    return conn


# =========================================================
# JSON SERIALIZATION HELPERS
# =========================================================

def _serialize_json(data, default=None):
    """
    Safely serialize Python data into JSON.

    Returns:
        str: Serialized JSON string.
    """

    if default is None:
        default = {}

    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            default=str
        )

    except (TypeError, ValueError, OverflowError):
        return json.dumps(
            default,
            ensure_ascii=False
        )


def _deserialize_json(data, default=None):
    """
    Safely deserialize JSON from the database.

    Returns the supplied default if data is missing
    or invalid.
    """

    if default is None:
        default = {}

    if not data:
        return default

    try:
        return json.loads(data)

    except (
        json.JSONDecodeError,
        TypeError,
        ValueError,
        OverflowError
    ):
        return default


# =========================================================
# VALIDATION HELPERS
# =========================================================

def _validate_scan_id(scan_id):
    """
    Validate a scan ID.

    Args:
        scan_id: Scan identifier.

    Returns:
        int: Validated positive scan ID.

    Raises:
        ValueError: If the ID is invalid.
    """

    try:
        validated_id = int(scan_id)

    except (
        TypeError,
        ValueError,
        OverflowError
    ) as exc:

        raise ValueError(
            "Scan ID must be a valid integer."
        ) from exc

    if validated_id <= 0:

        raise ValueError(
            "Scan ID must be a positive integer."
        )

    return validated_id


def _validate_limit(limit, default=50, maximum=100):
    """
    Validate and normalize database query limits.
    """

    try:
        limit = int(limit)

    except (
        TypeError,
        ValueError,
        OverflowError
    ):
        limit = default

    return max(
        1,
        min(limit, maximum)
    )


def _normalize_findings(findings):
    """
    Normalize findings into a list of dictionaries.
    """

    if not isinstance(findings, list):
        return []

    return [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]


def _normalize_summary(summary):
    """
    Normalize summary data into a dictionary.
    """

    if not isinstance(summary, dict):
        return {}

    return summary


def _normalize_ports(ports):
    """
    Normalize port scan results into a list.
    """

    if not isinstance(ports, list):
        return []

    return ports


def _normalize_pages_count(pages_count):
    """
    Validate the number of crawled pages.
    """

    try:
        pages_count = int(pages_count)

    except (
        TypeError,
        ValueError,
        OverflowError
    ):
        return 0

    return max(
        0,
        pages_count
    )


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_db():
    """
    Initialize the WAVS SQLite database.

    Creates the scans table and indexes if they
    do not already exist.
    """

    with get_connection() as conn:

        # Enable Write-Ahead Logging.
        conn.execute(
            "PRAGMA journal_mode = WAL"
        )

        # Configure synchronous writes.
        conn.execute(
            "PRAGMA synchronous = NORMAL"
        )

        # Create scans table.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                target TEXT NOT NULL,

                status TEXT NOT NULL
                    DEFAULT 'completed',

                created_at TEXT NOT NULL,

                pages_count INTEGER NOT NULL
                    DEFAULT 0,

                findings_json TEXT NOT NULL
                    DEFAULT '[]',

                summary_json TEXT NOT NULL
                    DEFAULT '{}',

                ports_json TEXT NOT NULL
                    DEFAULT '[]'

            )
        """)

        # Index scan history by creation time.
        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_scans_created_at
            ON scans(created_at)
        """)

        # Index scans by target.
        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_scans_target
            ON scans(target)
        """)

        conn.commit()


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    target,
    findings,
    summary,
    pages_count,
    ports
):
    """
    Save completed scan results to the database.

    Args:
        target (str): Scanned target URL.
        findings (list): Vulnerability findings.
        summary (dict): Scan summary information.
        pages_count (int): Number of crawled pages.
        ports (list): Port scan results.

    Returns:
        int: Newly created scan ID.
    """

    if not target:

        raise ValueError(
            "Scan target cannot be empty."
        )

    target = str(target).strip()

    if not target:

        raise ValueError(
            "Scan target cannot be empty."
        )

    # Timestamp in UTC.
    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    # Normalize scan information.
    findings = _normalize_findings(
        findings
    )

    summary = _normalize_summary(
        summary
    )

    ports = _normalize_ports(
        ports
    )

    pages_count = _normalize_pages_count(
        pages_count
    )

    # Serialize scan results.
    findings_json = _serialize_json(
        findings,
        []
    )

    summary_json = _serialize_json(
        summary,
        {}
    )

    ports_json = _serialize_json(
        ports,
        []
    )

    # Insert scan into database.
    with get_connection() as conn:

        cursor = conn.execute("""
            INSERT INTO scans (

                target,
                status,
                created_at,
                pages_count,
                findings_json,
                summary_json,
                ports_json

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)

        """, (
            target,
            "completed",
            created_at,
            pages_count,
            findings_json,
            summary_json,
            ports_json
        ))

        conn.commit()

        return cursor.lastrowid


# =========================================================
# GET SINGLE SCAN
# =========================================================

def get_scan(scan_id):
    """
    Retrieve a scan by its database ID.

    Args:
        scan_id: Unique scan identifier.

    Returns:
        dict: Scan details if found.
        None: If the scan does not exist.
    """

    scan_id = _validate_scan_id(
        scan_id
    )

    with get_connection() as conn:

        row = conn.execute(
            """
            SELECT *
            FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)

    # Deserialize stored JSON fields.
    result["findings"] = _deserialize_json(
        result.pop("findings_json", None),
        []
    )

    result["summary"] = _deserialize_json(
        result.pop("summary_json", None),
        {}
    )

    result["ports"] = _deserialize_json(
        result.pop("ports_json", None),
        []
    )

    return result


# =========================================================
# LIST SCAN HISTORY
# =========================================================

def list_scans(limit=50):
    """
    Retrieve recent scan history.

    Args:
        limit (int): Maximum number of records (1-100).

    Returns:
        list: Scan history records.
    """

    limit = _validate_limit(
        limit,
        default=50,
        maximum=100
    )

    with get_connection() as conn:

        rows = conn.execute("""
            SELECT

                id,
                target,
                status,
                created_at,
                pages_count,
                summary_json

            FROM scans

            ORDER BY id DESC

            LIMIT ?

        """, (limit,)).fetchall()

    scans = []

    for row in rows:

        item = dict(row)

        item["summary"] = _deserialize_json(
            item.pop("summary_json", None),
            {}
        )

        scans.append(item)

    return scans


# =========================================================
# SEARCH SCANS BY TARGET
# =========================================================

def search_scans(target, limit=50):
    """
    Search scan history by target URL.

    Args:
        target (str): Target URL or hostname.
        limit (int): Maximum number of results.

    Returns:
        list: Matching scan records.
    """

    if not target:

        return []

    target = str(target).strip()

    if not target:

        return []

    limit = _validate_limit(
        limit,
        default=50,
        maximum=100
    )

    with get_connection() as conn:

        rows = conn.execute("""
            SELECT

                id,
                target,
                status,
                created_at,
                pages_count,
                summary_json

            FROM scans

            WHERE target LIKE ?

            ORDER BY id DESC

            LIMIT ?

        """, (
            f"%{target}%",
            limit
        )).fetchall()

    results = []

    for row in rows:

        item = dict(row)

        item["summary"] = _deserialize_json(
            item.pop("summary_json", None),
            {}
        )

        results.append(item)

    return results


# =========================================================
# DELETE SINGLE SCAN
# =========================================================

def delete_scan(scan_id):
    """
    Delete a scan record by its ID.

    Args:
        scan_id: Unique scan identifier.

    Returns:
        bool: True if a scan was deleted.
        False if the scan was not found.
    """

    scan_id = _validate_scan_id(
        scan_id
    )

    with get_connection() as conn:

        cursor = conn.execute(
            """
            DELETE FROM scans
            WHERE id = ?
            """,
            (scan_id,)
        )

        conn.commit()

        return cursor.rowcount > 0


# =========================================================
# DELETE ALL SCANS
# =========================================================

def delete_all_scans():
    """
    Delete all scan history records.

    Returns:
        int: Number of deleted records.
    """

    with get_connection() as conn:

        cursor = conn.execute(
            "DELETE FROM scans"
        )

        conn.commit()

        return cursor.rowcount


# =========================================================
# DATABASE STATISTICS
# =========================================================

def get_database_stats():
    """
    Retrieve basic database statistics.

    Returns:
        dict: Total scans, findings, and crawled pages.
    """

    with get_connection() as conn:

        row = conn.execute("""
            SELECT

                COUNT(*) AS total_scans,

                COALESCE(
                    SUM(pages_count),
                    0
                ) AS total_pages

            FROM scans

        """).fetchone()

    total_scans = row["total_scans"]
    total_pages = row["total_pages"]

    total_findings = 0

    rows = conn.execute("""
        SELECT findings_json
        FROM scans
    """).fetchall()

    for item in rows:

        findings = _deserialize_json(
            item["findings_json"],
            []
        )

        if isinstance(findings, list):

            total_findings += len(
                [
                    finding
                    for finding in findings
                    if isinstance(finding, dict)
                ]
            )

    return {
        "total_scans": total_scans,
        "total_pages": total_pages,
        "total_findings": total_findings,
    }
