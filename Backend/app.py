
"""WAVS - Web Application Vulnerability Scanner API."""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from config import MAX_CRAWL_PAGES

from Utils.request_handler import normalize_target, TargetError
from Utils.logger import logger

from Scanner.crawler import crawl
from Scanner.sql_injection import scan_sql_injection
from Scanner.xss import scan_xss
from Scanner.csrf import scan_csrf
from Scanner.port_scan import scan_ports
from Scanner.severity import summarize_findings

from database.db import (
    init_db,
    save_scan,
    get_scan,
    list_scans,
    delete_scan,
)

from Reports.report_generator import generate_html_report


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*",
        }
    },
)

app.config["JSON_SORT_KEYS"] = False

# Initialize database.
init_db()


# =========================================================
# ERROR RESPONSE HELPER
# =========================================================

def error(message, status=400):
    """Return a standardized API error response."""

    return jsonify({
        "success": False,
        "error": message,
    }), status


# =========================================================
# HOME ROUTE
# =========================================================

@app.get("/")
def home():
    """Return API information and available endpoints."""

    return jsonify({
        "name": "WAVS API",
        "version": "1.0",
        "status": "running",
        "endpoints": [
            "POST /api/scan",
            "GET /api/scans",
            "GET /api/scans/<id>",
            "GET /api/scans/<id>/report",
            "DELETE /api/scans/<id>",
            "GET /api/health",
        ],
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health():
    """Check whether the API is running."""

    return jsonify({
        "success": True,
        "status": "healthy",
    })


# =========================================================
# MODULE CONFIGURATION HELPER
# =========================================================

def get_selected_modules(data):
    """
    Read scanner module selections from the frontend.

    If modules are not provided, enable web scanner
    modules by default for backward compatibility.
    """

    modules = data.get("modules", {})

    if not isinstance(modules, dict):
        raise ValueError(
            "'modules' must be a JSON object."
        )

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


# =========================================================
# SCAN ROUTE
# =========================================================

@app.post("/api/scan")
def start_scan():
    """Execute the requested security scan."""

    # -----------------------------------------------------
    # READ REQUEST
    # -----------------------------------------------------

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error(
            "Request body must contain a valid JSON object."
        )

    # -----------------------------------------------------
    # VALIDATE TARGET
    # -----------------------------------------------------

    try:
        target = normalize_target(
            data.get("target") or
            data.get("url") or
            ""
        )

    except TargetError as exc:
        return error(str(exc))

    # -----------------------------------------------------
    # VALIDATE MODULE CONFIGURATION
    # -----------------------------------------------------

    try:
        modules = get_selected_modules(data)

    except ValueError as exc:
        return error(str(exc))

    # -----------------------------------------------------
    # VALIDATE PAGE LIMIT
    # -----------------------------------------------------

    raw_limit = data.get(
        "max_pages",
        MAX_CRAWL_PAGES,
    )

    try:
        if isinstance(raw_limit, bool):
            raise ValueError

        limit = int(raw_limit)

    except (ValueError, TypeError):
        return error(
            "max_pages must be a valid integer."
        )

    limit = max(
        1,
        min(limit, MAX_CRAWL_PAGES),
    )

    # -----------------------------------------------------
    # VALIDATE PORTS
    # -----------------------------------------------------

    raw_ports = data.get("ports")

    if raw_ports is not None:

        if not isinstance(raw_ports, list):
            return error(
                "ports must be a list of integers."
            )

        for port in raw_ports:

            if (
                not isinstance(port, int)
                or isinstance(port, bool)
            ):
                return error(
                    "Every port must be an integer."
                )

            if not 1 <= port <= 65535:
                return error(
                    "Port numbers must be between 1 and 65535."
                )

    # -----------------------------------------------------
    # CHECK MODULE SELECTION
    # -----------------------------------------------------

    if not any(modules.values()):
        return error(
            "Please select at least one scanner module."
        )

    # -----------------------------------------------------
    # INITIALIZE SCAN RESULTS
    # -----------------------------------------------------

    findings = []
    ports = []
    forms = []
    pages = []
    visited_count = 0

    # -----------------------------------------------------
    # EXECUTE SCAN
    # -----------------------------------------------------

    try:

        logger.info(
            "WAVS scan initiated for %s",
            target,
        )

        logger.info(
            "Selected modules: %s",
            modules,
        )

        # =================================================
        # 1. CRAWLER
        # =================================================

        if modules["crawler"]:

            logger.info(
                "Crawler started for %s",
                target,
            )

            crawled = crawl(
                target,
                limit,
            )

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
                "Crawler completed. Pages: %s | Forms: %s",
                visited_count,
                len(forms),
            )

        else:

            # Without crawling, query-based scanners
            # can inspect only the supplied target.
            pages = [target]
            forms = []
            visited_count = 0

            logger.info("Crawler module skipped.")

        # =================================================
        # 2. SQL INJECTION SCANNER
        # =================================================

        if modules["sqli"]:

            logger.info(
                "SQL Injection scanner started."
            )

            sqli_findings = scan_sql_injection(
                pages,
                forms,
            )

            findings.extend(
                sqli_findings or []
            )

            logger.info(
                "SQL Injection scanner completed. Findings: %s",
                len(sqli_findings or []),
            )

        else:
            logger.info(
                "SQL Injection scanner skipped."
            )

        # =================================================
        # 3. XSS SCANNER
        # =================================================

        if modules["xss"]:

            logger.info("XSS scanner started.")

            xss_findings = scan_xss(
                pages,
                forms,
            )

            findings.extend(
                xss_findings or []
            )

            logger.info(
                "XSS scanner completed. Findings: %s",
                len(xss_findings or []),
            )

        else:
            logger.info(
                "XSS scanner skipped."
            )

        # =================================================
        # 4. CSRF SCANNER
        # =================================================

        if modules["csrf"]:

            logger.info("CSRF scanner started.")

            csrf_findings = scan_csrf(forms)

            findings.extend(
                csrf_findings or []
            )

            logger.info(
                "CSRF scanner completed. Findings: %s",
                len(csrf_findings or []),
            )

        else:
            logger.info(
                "CSRF scanner skipped."
            )

        # =================================================
        # 5. PORT SCANNER
        # =================================================

        if modules["ports"]:

            logger.info(
                "Port scanner started for %s",
                target,
            )

            ports = scan_ports(
                target,
                raw_ports,
            )

            ports = ports or []

            logger.info(
                "Port scanner completed. Results: %s",
                len(ports),
            )

        else:
            logger.info(
                "Port scanner skipped."
            )

        # =================================================
        # GENERATE SUMMARY
        # =================================================

        summary = summarize_findings(findings)

        # =================================================
        # SAVE SCAN TO DATABASE
        # =================================================

        scan_id = save_scan(
            target,
            findings,
            summary,
            visited_count,
            ports,
        )

        if scan_id is None:
            raise RuntimeError(
                "Database failed to save the scan."
            )

        # =================================================
        # BUILD RESPONSE
        # =================================================

        result = {
            "id": scan_id,
            "target": target,
            "status": "completed",
            "pages_scanned": visited_count,
            "forms_found": len(forms),
            "findings": findings,
            "summary": summary,
            "ports": ports,
            "modules": modules,
        }

        # =================================================
        # LOG COMPLETION
        # =================================================

        logger.info(
            "Scan #%s completed for %s",
            scan_id,
            target,
        )

        # =================================================
        # RETURN RESPONSE
        # =================================================

        return jsonify({
            "success": True,
            "scan": result,
        }), 200

    # =====================================================
    # EXCEPTION HANDLING
    # =====================================================

    except Exception:

        logger.exception(
            "Scan failed for %s",
            target,
        )

        return error(
            "Scan failed. Check server logs for details.",
            500,
        )


# =========================================================
# SCAN HISTORY
# =========================================================

@app.get("/api/scans")
def history():
    """Return previous scans."""

    try:
        raw_limit = request.args.get(
            "limit",
            50,
        )

        limit = int(raw_limit)

    except (ValueError, TypeError):
        return error(
            "limit must be an integer."
        )

    limit = max(
        1,
        min(limit, 100),
    )

    try:
        scans = list_scans(limit)

        return jsonify({
            "success": True,
            "scans": scans,
        })

    except Exception:

        logger.exception(
            "Failed to retrieve scan history."
        )

        return error(
            "Could not retrieve scan history.",
            500,
        )


# =========================================================
# SCAN DETAILS
# =========================================================

@app.get("/api/scans/<int:scan_id>")
def scan_detail(scan_id):
    """Return details of a specific scan."""

    try:
        scan = get_scan(scan_id)

    except Exception:

        logger.exception(
            "Failed to retrieve scan #%s",
            scan_id,
        )

        return error(
            "Could not retrieve scan details.",
            500,
        )

    if not scan:
        return error(
            "Scan not found.",
            404,
        )

    return jsonify({
        "success": True,
        "scan": scan,
    })


# =========================================================
# HTML REPORT DOWNLOAD
# =========================================================

@app.get("/api/scans/<int:scan_id>/report")
def scan_report(scan_id):
    """Generate and download an HTML scan report."""

    try:
        scan = get_scan(scan_id)

        if not scan:
            return error(
                "Scan not found.",
                404,
            )

        path = generate_html_report(scan)

        return send_file(
            path,
            as_attachment=True,
            download_name=f"WAVS_report_{scan_id}.html",
        )

    except Exception:

        logger.exception(
            "Report generation failed for scan #%s",
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
    """Delete a scan from history."""

    try:
        deleted = delete_scan(scan_id)

    except Exception:

        logger.exception(
            "Failed to delete scan #%s",
            scan_id,
        )

        return error(
            "Could not delete scan.",
            500,
        )

    if deleted:
        return jsonify({
            "success": True,
            "message": "Scan deleted.",
        })

    return error(
        "Scan not found.",
        404,
    )


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(_):
    return error(
        "Endpoint not found.",
        404,
    )


@app.errorhandler(405)
def method_not_allowed(_):
    return error(
        "Method not allowed.",
        405,
    )


@app.errorhandler(500)
def internal_server_error(_):
    return error(
        "Internal server error.",
        500,
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
