
"""SQLite database operations for WAVS scan history."""

import sqlite3
import json

from pathlib import Path
from datetime import datetime, timezone

from config import DATABASE_PATH


# --------------------------------------------------
# Database Connection
# --------------------------------------------------

def get_connection():
    """
    Create and return a SQLite database connection.

    Ensures that the database directory exists and enables
    dictionary-like row access.
    """

    Path(DATABASE_PATH).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=15
    )

    conn.row_factory = sqlite3.Row

    # Improve concurrency and reduce database locking.
    conn.execute("PRAGMA busy_timeout = 15000")

    return conn


# --------------------------------------------------
# JSON Helpers
# --------------------------------------------------

def _serialize_json(data, default):
    """
    Safely serialize data into JSON.

    Falls back to a default value if serialization fails.
    """

    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            default=str
        )

    except (TypeError, ValueError):
        return json.dumps(default)


def _deserialize_json(data, default):
    """
    Safely deserialize JSON stored in the database.

    Returns a default value if the stored JSON is corrupted.
    """

    if not data:
        return default

    try:
        return json.loads(data)

    except (json.JSONDecodeError, TypeError, ValueError):
        return default


def _validate_scan_id(scan_id):
    """
    Validate a scan ID before database operations.

    Returns:
        int: Validated scan ID.

    Raises:
        ValueError: If the scan ID is invalid.
    """

    try:
        scan_id = int(scan_id)

    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            "Scan ID must be a valid integer."
        ) from exc

    if scan_id <= 0:
        raise ValueError(
            "Scan ID must be a positive integer."
        )

    return scan_id


# --------------------------------------------------
# Initialize Database
# --------------------------------------------------

def init_db():
    """
    Initialize the WAVS database.

    Creates the scans table if it does not already exist.
    """

    with get_connection() as conn:

        conn.execute("PRAGMA journal_mode = WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                target TEXT NOT NULL,

                status TEXT NOT NULL
                    DEFAULT 'completed',

                created_at TEXT NOT NULL,

                pages_count INTEGER
                    DEFAULT 0,

                findings_json TEXT NOT NULL
                    DEFAULT '[]',

                summary_json TEXT NOT NULL
                    DEFAULT '{}',

                ports_json TEXT NOT NULL
                    DEFAULT '[]'

            )
        """)

        conn.commit()


# --------------------------------------------------
# Save Scan
# --------------------------------------------------

def save_scan(
    target,
    findings,
    summary,
    pages_count,
    ports
):
    """
    Save completed scan results to the database.

    Returns:
        int: Newly created scan ID.
    """

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    findings_json = _serialize_json(
        findings if isinstance(findings, list) else [],
        []
    )

    summary_json = _serialize_json(
        summary if isinstance(summary, dict) else {},
        {}
    )

    ports_json = _serialize_json(
        ports if isinstance(ports, list) else [],
        []
    )

    try:
        pages_count = max(
            0,
            int(pages_count)
        )

    except (TypeError, ValueError, OverflowError):
        pages_count = 0

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
            str(target),
            "completed",
            created_at,
            pages_count,
            findings_json,
            summary_json,
            ports_json
        ))

        conn.commit()

        return cursor.lastrowid


# --------------------------------------------------
# Get Single Scan
# --------------------------------------------------

def get_scan(scan_id):
    """
    Retrieve a scan by ID.

    Returns:
        dict: Scan details, or None if not found.
    """

    scan_id = _validate_scan_id(scan_id)

    with get_connection() as conn:

        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)

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


# --------------------------------------------------
# List Scan History
# --------------------------------------------------

def list_scans(limit=50):
    """
    Retrieve recent scan history.

    Args:
        limit: Maximum number of records to return (1-100).

    Returns:
        list: Scan history records.
    """

    try:
        limit = int(limit)

    except (TypeError, ValueError, OverflowError):
        limit = 50

    limit = max(
        1,
        min(limit, 100)
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


# --------------------------------------------------
# Delete Scan
# --------------------------------------------------

def delete_scan(scan_id):
    """
    Delete a scan record by ID.

    Returns:
        bool: True if deleted, otherwise False.
    """

    scan_id = _validate_scan_id(scan_id)

    with get_connection() as conn:

        cursor = conn.execute(
            "DELETE FROM scans WHERE id = ?",
            (scan_id,)
        )

        conn.commit()

        return cursor.rowcount > 0
