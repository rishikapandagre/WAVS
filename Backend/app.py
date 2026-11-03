
"""WAVS - Web Application Vulnerability Scanner API."""

import os
from pathlib import Path

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from Backend.config import MAX_CRAWL_PAGES

from Backend.Utils.request_handler import normalize_target, TargetError
from Backend.Utils.logger import logger

from Backend.Scanner.crawler import crawl
from Backend.Scanner.sql_injection import scan_sql_injection
from Backend.Scanner.xss import scan_xss
from Backend.Scanner.csrf import scan_csrf
from Backend.Scanner.port_scan import scan_ports
from Backend.Scanner.severity import summarize_findings

from Backend.database.db import (
    init_db,
    save_scan,
    get_scan,
    list_scans,
    delete_scan
)

from Backend.Reports.report_generator import generate_html_report


# =========================================================
# PATHS & APPLICATION SETUP
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = Flask(
    __name__,
    instance_relative_config=True,
)

app.config.update(
    JSON_SORT_KEYS=False,
    MAX_CONTENT_LENGTH=int(
        os.getenv("MAX_CONTENT_LENGTH", 1024 * 1024)
    ),
    API_VERSION=os.getenv("API_VERSION", "1.0"),
    DEBUG=os.getenv("FLASK_DEBUG", "false").lower()
    in ("1", "true", "yes"),
    TESTING=os.getenv("FLASK_TESTING", "false").lower()
    in ("1", "true", "yes"),
)


# =========================================================
# CORS
# =========================================================

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500",
    ).split(",")
    if origin.strip()
]

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": cors_origins,
            "methods": ["GET", "POST", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    },
)


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

try:
    init_db()
    logger.info("WAVS database initialized successfully.")
except Exception:
    logger.exception("Database initialization failed.")
    raise


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


# =========================================================
# API RESPONSE HELPERS
# =========================================================

def success(data=None, message=None, status=200):
    response = {"success": True}

    if message:
        response["message"] = message

    if data is not None:
        response.update(data)

    return jsonify(response), status


def error(message, status=400):
    return jsonify({
        "success": False,
        "error": str(message),
    }), status


# =========================================================
# VALIDATION HELPERS
# =========================================================

def validate_integer(value, name, minimum, maximum):
    """Validate an integer within a specified range."""

    if isinstance(value, bool):
        raise ValueError(f"{name} must be a valid integer.")

    try:
        if isinstance(value, float) and not value.is_integer():
            raise ValueError

        if isinstance(value, str):
            value = value.strip()

            if not value or not value.isdigit():
                raise ValueError

        result = int(value)

    except (ValueError, TypeError, OverflowError):
        raise ValueError(f"{name} must be a valid integer.")

    if not minimum <= result <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}."
        )

    return result


def get_selected_modules(data):
    """Validate and return the selected scanner modules."""

    modules = data.get("modules", {})

    if not isinstance(modules, dict):
        raise ValueError("'modules' must be a JSON object.")

    selected = {
        "crawler": modules.get("crawler", True),
        "sqli": modules.get("sqli", True),
        "xss": modules.get("xss", True),
        "csrf": modules.get("csrf", True),
        "ports": modules.get(
            "ports",
            data.get("port_scan", False),
        ),
    }

    for name, enabled in selected.items():
        if not isinstance(enabled, bool):
            raise ValueError(
                f"Module '{name}' must be true or false."
            )

    return selected


def validate_ports(raw_ports):
    """Validate user-supplied ports."""

    if raw_ports is None:
        return None

    if not isinstance(raw_ports, list):
        raise ValueError("'ports' must be a list of integers.")

    if not raw_ports:
        raise ValueError("'ports' cannot be empty when provided.")

    validated = []

    for port in raw_ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("Every port must be an integer.")

        if not 1 <= port <= 65535:
            raise ValueError(
                "Ports must be between 1 and 65535."
            )

        validated.append(port)

    return list(dict.fromkeys(validated))


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return success({
        "name": "WAVS API",
        "version": app.config["API_VERSION"],
        "status": "running",
        "endpoints": {
            "scan": "POST /api/scan",
            "history": "GET /api/scans",
            "details": "GET /api/scans/<id>",
            "report": "GET /api/scans/<id>/report",
            "delete": "DELETE /api/scans/<id>",
            "health": "GET /api/health",
        },
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health():
    return success({"status": "healthy"})


# =========================================================
# START SCAN
# =========================================================

@app.post("/api/scan")
def start_scan():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error(
            "Request body must contain a valid JSON object."
        )

    # Validate target URL.
    raw_target = data.get("target") or data.get("url")

    if not isinstance(raw_target, str) or not raw_target.strip():
        return error("Please provide a valid target URL.")

    try:
        target = normalize_target(raw_target)
    except TargetError as exc:
        return error(str(exc))

    # Validate selected modules.
    try:
        modules = get_selected_modules(data)
    except ValueError as exc:
        return error(str(exc))

    if not any(modules.values()):
        return error(
            "Please select at least one scanner module."
        )

    # Validate crawler limit.
    try:
        limit = validate_integer(
            data.get("max_pages", MAX_CRAWL_PAGES),
            "max_pages",
            1,
            MAX_CRAWL_PAGES,
        )
    except ValueError as exc:
        return error(str(exc))

    # Validate ports.
    try:
        ports = validate_ports(data.get("ports"))
    except ValueError as exc:
        return error(str(exc))

    findings = []
    port_results = []
    forms = []
    pages = []
    visited_count = 0

    logger.info("Scan initiated | Target: %s", target)
    logger.info("Selected modules: %s", modules)

    try:

        # -------------------------------------------------
        # CRAWLER
        # -------------------------------------------------

        if modules["crawler"]:

            logger.info("Crawler started.")

            crawled = crawl(target, limit)

            if not isinstance(crawled, dict):
                raise RuntimeError(
                    "Crawler returned an invalid result."
                )

            pages = crawled.get("pages") or []
            forms = crawled.get("forms") or []

            visited_count = crawled.get(
                "visited_count",
                len(pages),
            )

            logger.info(
                "Crawler completed | Pages: %s | Forms: %s",
                visited_count,
                len(forms),
            )

        else:
            # When crawling is disabled, scan only the
            # explicitly supplied target URL.
            pages = [target]
            forms = []
            visited_count = 1

            logger.info("Crawler skipped.")

        # -------------------------------------------------
        # SQL INJECTION
        # -------------------------------------------------

        if modules["sqli"]:

            logger.info("SQL Injection scanner started.")

            result = scan_sql_injection(pages, forms)
            result = result or []

            if not isinstance(result, list):
                raise RuntimeError(
                    "SQL Injection scanner returned invalid results."
                )

            findings.extend(result)

            logger.info(
                "SQL Injection scan completed | Findings: %s",
                len(result),
            )

        # -------------------------------------------------
        # XSS
        # -------------------------------------------------

        if modules["xss"]:

            logger.info("XSS scanner started.")

            result = scan_xss(pages, forms)
            result = result or []

            if not isinstance(result, list):
                raise RuntimeError(
                    "XSS scanner returned invalid results."
                )

            findings.extend(result)

            logger.info(
                "XSS scan completed | Findings: %s",
                len(result),
            )

        # -------------------------------------------------
        # CSRF
        # -------------------------------------------------

        if modules["csrf"]:

            logger.info("CSRF scanner started.")

            result = scan_csrf(forms)
            result = result or []

            if not isinstance(result, list):
                raise RuntimeError(
                    "CSRF scanner returned invalid results."
                )

            findings.extend(result)

            logger.info(
                "CSRF scan completed | Findings: %s",
                len(result),
            )

        # -------------------------------------------------
        # PORT SCANNER
        # -------------------------------------------------

        if modules["ports"]:

            logger.info("Port scanner started.")

            result = scan_ports(target, ports)
            port_results = result or []

            logger.info(
                "Port scan completed | Open ports: %s",
                len(port_results),
            )

        # -------------------------------------------------
        # SUMMARY
        # -------------------------------------------------

        summary = summarize_findings(findings)

        # -------------------------------------------------
        # SAVE TO DATABASE
        # -------------------------------------------------

        scan_id = save_scan(
            target=target,
            findings=findings,
            summary=summary,
            pages_count=visited_count,
            ports=port_results,
        )

        if scan_id is None:
            raise RuntimeError(
                "Database failed to save scan results."
            )

        # -------------------------------------------------
        # RESPONSE
        # -------------------------------------------------

        scan_result = {
            "id": scan_id,
            "target": target,
            "status": "completed",
            "pages_scanned": visited_count,
            "forms_found": len(forms),
            "findings": findings,
            "summary": summary,
            "ports": port_results,
            "modules": modules,
        }

        logger.info(
            "Scan completed | ID: %s | Target: %s",
            scan_id,
            target,
        )

        return success({"scan": scan_result})

    except Exception:
        logger.exception(
            "Scan execution failed | Target: %s",
            target,
        )

        return error(
            "Scan failed. Please check server logs.",
            500,
        )


# =========================================================
# SCAN HISTORY
# =========================================================

@app.get("/api/scans")
def history():

    try:
        limit = validate_integer(
            request.args.get("limit", "50"),
            "limit",
            1,
            100,
        )

        scans = list_scans(limit)

        return success({"scans": scans})

    except ValueError as exc:
        return error(str(exc))

    except Exception:
        logger.exception("Failed to retrieve scan history.")

        return error(
            "Could not retrieve scan history.",
            500,
        )


# =========================================================
# SCAN DETAILS
# =========================================================

@app.get("/api/scans/<int:scan_id>")
def scan_detail(scan_id):

    try:
        scan = get_scan(scan_id)

        if not scan:
            return error("Scan not found.", 404)

        return success({"scan": scan})

    except Exception:
        logger.exception(
            "Failed to retrieve scan | ID: %s",
            scan_id,
        )

        return error(
            "Could not retrieve scan details.",
            500,
        )


# =========================================================
# HTML REPORT
# =========================================================

@app.get("/api/scans/<int:scan_id>/report")
def scan_report(scan_id):

    try:
        scan = get_scan(scan_id)

        if not scan:
            return error("Scan not found.", 404)

        report_path = generate_html_report(scan)

        if not report_path:
            raise RuntimeError(
                "Report generator did not return a file path."
            )

        report_path = Path(report_path).resolve()

        if not report_path.is_file():
            raise FileNotFoundError(
                "Generated report file does not exist."
            )

        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"WAVS_report_{scan_id}.html",
            mimetype="text/html",
        )

    except Exception:
        logger.exception(
            "Report generation failed | ID: %s",
            scan_id,
        )

        return error(
            "Could not generate report.",
            500,
        )


# =========================================================
# DELETE SCAN
# =========================================================

@app.delete("/api/scans/<int:scan_id>")
def remove_scan(scan_id):

    try:
        deleted = delete_scan(scan_id)

        if not deleted:
            return error("Scan not found.", 404)

        logger.info("Scan deleted | ID: %s", scan_id)

        return success(
            message="Scan deleted successfully."
        )

    except Exception:
        logger.exception(
            "Failed to delete scan | ID: %s",
            scan_id,
        )

        return error(
            "Could not delete scan.",
            500,
        )


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(400)
def bad_request(_exception):
    return error("Invalid request.", 400)


@app.errorhandler(404)
def not_found(_exception):
    return error("Endpoint not found.", 404)


@app.errorhandler(405)
def method_not_allowed(_exception):
    return error("Method not allowed.", 405)


@app.errorhandler(413)
def payload_too_large(_exception):
    return error("Request payload is too large.", 413)


@app.errorhandler(500)
def internal_server_error(_exception):
    return error("Internal server error.", 500)


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":

    host = os.getenv("HOST", "127.0.0.1")

    try:
        port = validate_integer(
            os.getenv("PORT", "5000"),
            "PORT",
            1,
            65535,
        )
    except ValueError as exc:
        raise SystemExit(str(exc))

    app.run(
        host=host,
        port=port,
        debug=app.config["DEBUG"],
    )
