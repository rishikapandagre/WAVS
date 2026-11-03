
"""Generate downloadable standalone HTML reports for WAVS scans."""

from datetime import datetime, timezone
from html import escape
import re

from Backend.config import REPORT_DIR


# =========================================================
# SEVERITY CONFIGURATION
# =========================================================

SEVERITY_LEVELS = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)

SEVERITY_COLORS = {
    "Critical": "#ff4d6d",
    "High": "#ff8c42",
    "Medium": "#f5c542",
    "Low": "#4ade80",
    "Informational": "#a78bfa",
}


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def safe_html(value):
    """Convert a value to safely escaped HTML text."""
    if value is None:
        return "N/A"

    return escape(str(value), quote=True)


def normalize_severity(value):
    """Normalize severity labels for consistent report styling."""

    if not value:
        return "Informational"

    severity = str(value).strip().lower()

    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
        "none": "Informational",
    }

    return mapping.get(severity, "Informational")


def generate_severity_summary(findings):
    """Count findings by severity."""

    summary = {
        level: 0
        for level in SEVERITY_LEVELS
    }

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(
            finding.get("severity")
        )

        summary[severity] += 1

    return summary


def generate_summary_cards(severity_counts):
    """Generate HTML severity summary cards."""

    cards = []

    for level in SEVERITY_LEVELS:

        count = severity_counts.get(level, 0)

        cards.append(
            f"""
            <div class="summary-box {level}">
                <div class="summary-count">{count}</div>
                <div class="summary-label">{level}</div>
            </div>
            """
        )

    return "\n".join(cards)


def generate_findings_rows(findings):
    """Generate safely escaped HTML table rows."""

    rows = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(
            finding.get("severity")
        )

        finding_type = safe_html(
            finding.get(
                "type",
                finding.get("title", "Unknown Finding")
            )
        )

        location = safe_html(
            finding.get(
                "location",
                finding.get(
                    "url",
                "N/A")
            )
        )

        parameter = safe_html(
            finding.get("parameter", "N/A")
        )

        method = safe_html(
            finding.get("method", "N/A")
        )

        evidence = safe_html(
            finding.get("evidence", "N/A")
        )

        explanation = safe_html(
            finding.get(
                "explanation",
                finding.get(
                    "description",
                "No explanation provided.")
            )
        )

        remediation = safe_html(
            finding.get(
                "remediation",
                finding.get(
                    "recommendation",
                "No remediation provided.")
            )
        )

        rows.append(
            f"""
            <tr>
                <td>{finding_type}</td>

                <td>
                    <span class="badge {severity}">
                        {severity}
                    </span>
                </td>

                <td>{location}</td>

                <td>{parameter}</td>

                <td>{method}</td>

                <td>{evidence}</td>

                <td>{explanation}</td>

                <td>{remediation}</td>
            </tr>
            """
        )

    if not rows:

        return """
        <tr>
            <td colspan="8" class="empty">
                No findings recorded for this scan.
            </td>
        </tr>
        """

    return "\n".join(rows)


# =========================================================
# MAIN REPORT GENERATOR
# =========================================================

def generate_html_report(scan):
    """
    Generate a standalone HTML security assessment report.

    Args:
        scan (dict): Completed WAVS scan information.

    Returns:
        str: Absolute path to the generated HTML report.
    """

    if not isinstance(scan, dict):
        raise ValueError(
            "Scan data must be a dictionary."
        )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Extract scan information
    # -----------------------------------------------------

    findings = scan.get("findings", [])

    if not isinstance(findings, list):
        findings = []

    valid_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]

    target = safe_html(
        scan.get(
            "target_url",
            scan.get(
                "target",
                "Unknown Target"
            )
        )
    )

    scan_id = safe_html(
        scan.get("id", "Unknown")
    )

    started_at = safe_html(
        scan.get("started_at", "N/A")
    )

    finished_at = safe_html(
        scan.get("finished_at", "N/A")
    )

    generated_at = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    generated = safe_html(generated_at)

    findings_count = len(valid_findings)

    severity_counts = generate_severity_summary(
        valid_findings
    )

    summary_cards = generate_summary_cards(
        severity_counts
    )

    table_rows = generate_findings_rows(
        valid_findings
    )

    # -----------------------------------------------------
    # Sanitize report filename
    # -----------------------------------------------------

    raw_report_id = str(
        scan.get("id", "unknown")
    )

    safe_report_id = re.sub(
        r"[^a-zA-Z0-9_-]",
        "_",
        raw_report_id
    )[:100] or "unknown"

    report_filename = (
        f"wavs_report_{safe_report_id}.html"
    )

    report_path = REPORT_DIR / report_filename

    # -----------------------------------------------------
    # Standalone HTML report
    # -----------------------------------------------------

    html = f"""<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <meta
        name="description"
        content="WAVS Web Application Vulnerability Scanner - Security Assessment Report"
    >

    <title>WAVS | Vulnerability Assessment Report</title>

    <style>

        /* =============================================
           WAVS DESIGN SYSTEM
        ============================================= */

        :root {{
            --bg-primary: #08080d;
            --bg-secondary: #101018;
            --bg-card: #15151f;
            --bg-card-hover: #1c1c29;

            --text-primary: #f5f5f7;
            --text-secondary: #c4c4d0;
            --text-muted: #9292a5;

            --accent-gold: #f5c542;
            --accent-gold-light: #ffe082;

            --accent-magenta: #e879f9;
            --accent-violet: #a78bfa;
            --accent-green: #4ade80;

            --border-color: #30303d;
            --border-highlight: #4a405c;

            --critical: #ff4d6d;
            --high: #ff8c42;
            --medium: #f5c542;
            --low: #4ade80;
            --info: #a78bfa;

            --shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
        }}


        /* =============================================
           RESET AND GLOBAL STYLES
        ============================================= */

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        html {{
            scroll-behavior: smooth;
        }}

        body {{
            font-family:
                "Segoe UI",
                "Inter",
                "Roboto",
                Arial,
                sans-serif;

            background: var(--bg-primary);
            color: var(--text-primary);

            font-size: 16px;
            line-height: 1.7;

            padding: 40px;

            -webkit-font-smoothing: antialiased;
        }}


        /* =============================================
           MAIN CONTAINER
        ============================================= */

        .container {{
            max-width: 1600px;
            margin: 0 auto;

            padding: 45px;

            background: var(--bg-secondary);

            border: 1px solid var(--border-color);
            border-radius: 18px;

            box-shadow: var(--shadow);
        }}


        /* =============================================
           REPORT HEADER
        ============================================= */

        .report-header {{
            margin-bottom: 40px;
            padding-bottom: 25px;

            border-bottom: 2px solid var(--accent-gold);
        }}

        .brand {{
            display: inline-block;

            color: var(--accent-gold);

            font-size: 18px;
            font-weight: 900;

            letter-spacing: 5px;
            text-transform: uppercase;

            margin-bottom: 15px;
        }}

        h1 {{
            color: var(--text-primary);

            font-size: 36px;
            font-weight: 800;

            line-height: 1.3;

            margin-bottom: 15px;
        }}

        .subtitle {{
            color: var(--text-secondary);

            font-size: 17px;

            margin-bottom: 20px;
        }}

        .header-label {{
            display: inline-block;

            padding: 7px 15px;

            color: var(--accent-gold);

            background: rgba(245, 197, 66, 0.10);

            border: 1px solid rgba(245, 197, 66, 0.30);
            border-radius: 6px;

            font-size: 13px;
            font-weight: 700;

            letter-spacing: 1px;
            text-transform: uppercase;
        }}


        /* =============================================
           SECTION HEADINGS
        ============================================= */

        h2 {{
            color: var(--accent-gold);

            font-size: 25px;
            font-weight: 800;

            margin-bottom: 22px;
        }}

        .section {{
            margin-bottom: 40px;
        }}


        /* =============================================
           SCAN METADATA
        ============================================= */

        .meta {{
            background: var(--bg-card);

            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-violet);

            border-radius: 10px;

            padding: 25px;

            margin-bottom: 35px;

            color: var(--text-secondary);

            font-size: 17px;

            overflow-wrap: anywhere;
        }}

        .meta-row {{
            display: flex;
            flex-wrap: wrap;

            gap: 10px;

            margin-bottom: 12px;
        }}

        .meta-row:last-child {{
            margin-bottom: 0;
        }}

        .meta-label {{
            color: var(--accent-gold);

            font-weight: 700;

            min-width: 180px;
        }}

        .meta-value {{
            color: var(--text-primary);

            overflow-wrap: anywhere;
        }}


        /* =============================================
           SUMMARY CARDS
        ============================================= */

        .summary {{
            display: grid;

            grid-template-columns:
                repeat(5, minmax(130px, 1fr));

            gap: 18px;

            margin-bottom: 35px;
        }}

        .summary-box {{
            display: flex;
            flex-direction: column;

            justify-content: center;
            align-items: center;

            min-height: 110px;

            padding: 20px;

            background: var(--bg-card);

            border: 1px solid var(--border-color);
            border-radius: 12px;

            transition:
                transform 0.2s ease,
                border-color 0.2s ease;
        }}

        .summary-box:hover {{
            transform: translateY(-3px);

            border-color: var(--border-highlight);
        }}

        .summary-count {{
            font-size: 32px;
            font-weight: 900;

            line-height: 1.2;

            margin-bottom: 8px;
        }}

        .summary-label {{
            font-size: 14px;
            font-weight: 800;

            text-transform: uppercase;

            letter-spacing: 1.5px;
        }}

        .Critical {{
            color: var(--critical);
        }}

        .High {{
            color: var(--high);
        }}

        .Medium {{
            color: var(--medium);
        }}

        .Low {{
            color: var(--low);
        }}

        .Informational,
        .Info {{
            color: var(--info);
        }}


        /* =============================================
           FINDINGS TABLE
        ============================================= */

        .table-wrapper {{
            width: 100%;

            overflow-x: auto;

            background: var(--bg-card);

            border: 1px solid var(--border-color);
            border-radius: 10px;
        }}

        table {{
            width: 100%;

            min-width: 1200px;

            border-collapse: collapse;

            font-size: 15px;
        }}

        thead {{
            background: #20202c;
        }}

        th {{
            color: var(--accent-gold);

            font-size: 14px;
            font-weight: 800;

            text-transform: uppercase;
            letter-spacing: 0.8px;

            text-align: left;

            padding: 18px 16px;

            border-bottom: 2px solid var(--border-highlight);

            white-space: nowrap;
        }}

        td {{
            color: var(--text-secondary);

            font-size: 15px;

            padding: 18px 16px;

            text-align: left;
            vertical-align: top;

            border-bottom: 1px solid var(--border-color);

            overflow-wrap: anywhere;
            word-break: break-word;

            line-height: 1.7;
        }}

        tbody tr {{
            transition: background 0.2s ease;
        }}

        tbody tr:hover {{
            background: var(--bg-card-hover);
        }}

        tbody tr:last-child td {{
            border-bottom: none;
        }}

        td:first-child {{
            color: var(--text-primary);

            font-weight: 700;

            min-width: 180px;
        }}

        td:nth-child(3) {{
            min-width: 220px;
        }}

        td:nth-child(6),
        td:nth-child(7),
        td:nth-child(8) {{
            min-width: 250px;
        }}


        /* =============================================
           SEVERITY BADGES
        ============================================= */

        .badge {{
            display: inline-block;

            padding: 6px 12px;

            border-radius: 6px;

            font-size: 13px;
            font-weight: 900;

            letter-spacing: 0.5px;

            text-transform: uppercase;

            white-space: nowrap;
        }}

        .badge.Critical {{
            color: #ffb6c2;

            background: rgba(255, 77, 109, 0.15);

            border: 1px solid rgba(255, 77, 109, 0.45);
        }}

        .badge.High {{
            color: #ffc49b;

            background: rgba(255, 140, 66, 0.15);

            border: 1px solid rgba(255, 140, 66, 0.45);
        }}

        .badge.Medium {{
            color: #ffe082;

            background: rgba(245, 197, 66, 0.15);

            border: 1px solid rgba(245, 197, 66, 0.45);
        }}

        .badge.Low {{
            color: #a7f3c0;

            background: rgba(74, 222, 128, 0.15);

            border: 1px solid rgba(74, 222, 128, 0.45);
        }}

        .badge.Informational,
        .badge.Info {{
            color: #d0bcff;

            background: rgba(167, 139, 250, 0.15);

            border: 1px solid rgba(167, 139, 250, 0.45);
        }}


        /* =============================================
           EMPTY STATE
        ============================================= */

        .empty {{
            padding: 35px;

            text-align: center;

            color: var(--text-muted);

            font-size: 17px;
        }}

        .empty-state {{
            padding: 35px;

            margin-top: 25px;

            text-align: center;

            background: rgba(74, 222, 128, 0.06);

            border: 1px solid rgba(74, 222, 128, 0.25);
            border-radius: 12px;
        }}

        .empty-state h3 {{
            color: var(--accent-green);

            font-size: 23px;

            margin-bottom: 10px;
        }}

        .empty-state p {{
            color: var(--text-secondary);

            font-size: 16px;
        }}


        /* =============================================
           DISCLAIMER
        ============================================= */

        .disclaimer {{
            padding: 22px;

            margin-top: 35px;

            background: rgba(167, 139, 250, 0.06);

            border: 1px solid rgba(167, 139, 250, 0.20);
            border-radius: 10px;

            color: var(--text-secondary);

            font-size: 14px;
        }}

        .disclaimer strong {{
            color: var(--accent-violet);
        }}


        /* =============================================
           FOOTER
        ============================================= */

        .footer {{
            margin-top: 45px;

            padding-top: 22px;

            border-top: 1px solid var(--border-color);

            text-align: center;

            color: var(--text-muted);

            font-size: 14px;
        }}

        .footer-brand {{
            color: var(--accent-gold);

            font-weight: 900;

            letter-spacing: 2px;
        }}


        /* =============================================
           RESPONSIVE DESIGN
        ============================================= */

        @media (max-width: 1100px) {{

            body {{
                padding: 25px;
            }}

            .container {{
                padding: 30px;
            }}

            .summary {{
                grid-template-columns:
                    repeat(3, minmax(130px, 1fr));
            }}
        }}

        @media (max-width: 768px) {{

            body {{
                padding: 12px;

                font-size: 15px;
            }}

            .container {{
                padding: 20px;

                border-radius: 12px;
            }}

            h1 {{
                font-size: 28px;
            }}

            h2 {{
                font-size: 22px;
            }}

            .meta {{
                padding: 18px;

                font-size: 15px;
            }}

            .meta-row {{
                flex-direction: column;

                gap: 3px;
            }}

            .meta-label {{
                min-width: unset;
            }}

            .summary {{
                grid-template-columns:
                    repeat(2, minmax(120px, 1fr));

                gap: 12px;
            }}

            .summary-box {{
                min-height: 90px;

                padding: 15px;
            }}

            .summary-count {{
                font-size: 26px;
            }}

            .summary-label {{
                font-size: 12px;
            }}

            th,
            td {{
                padding: 14px 12px;
            }}
        }}

        @media (max-width: 480px) {{

            .summary {{
                grid-template-columns: 1fr 1fr;
            }}

            h1 {{
                font-size: 24px;
            }}

            .subtitle {{
                font-size: 15px;
            }}
        }}


        /* =============================================
           PRINT / SAVE AS PDF
        ============================================= */

        @media print {{

            @page {{
                size: A4 landscape;
                margin: 12mm;
            }}

            body {{
                background: #ffffff !important;

                color: #222222 !important;

                padding: 0;

                font-size: 11px;
            }}

            .container {{
                max-width: none;

                padding: 0;

                background: #ffffff !important;

                border: none;
                border-radius: 0;

                box-shadow: none;
            }}

            .report-header {{
                border-bottom: 2px solid #b8860b;
            }}

            .brand,
            h2,
            .meta-label,
            .footer-brand {{
                color: #8a6500 !important;
            }}

            h1,
            h3 {{
                color: #222222 !important;
            }}

            .subtitle,
            .meta,
            .meta-value,
            td,
            .footer,
            .disclaimer {{
                color: #333333 !important;
            }}

            .meta,
            .summary-box,
            .table-wrapper,
            .disclaimer,
            .empty-state {{
                background: #ffffff !important;

                border-color: #cccccc !important;
            }}

            .summary {{
                grid-template-columns: repeat(5, 1fr);
            }}

            .summary-box {{
                min-height: auto;

                padding: 10px;
            }}

            table {{
                min-width: 0;

                font-size: 9px;

                table-layout: fixed;
            }}

            th {{
                color: #ffffff !important;

                background: #252538 !important;

                font-size: 9px;

                padding: 8px;
            }}

            td {{
                font-size: 9px;

                padding: 8px;

                overflow-wrap: anywhere;
            }}

            .badge {{
                print-color-adjust: exact;
                -webkit-print-color-adjust: exact;
            }}

            tr {{
                break-inside: avoid;
            }}

            thead {{
                display: table-header-group;
            }}

            .section,
            .report-header,
            .meta,
            .summary,
            .disclaimer {{
                break-inside: avoid;
            }}

            .footer {{
                margin-top: 20px;
            }}
        }}

    </style>

</head>

<body>

    <div class="container">

        <!-- =====================================
             REPORT HEADER
        ====================================== -->

        <header class="report-header">

            <div class="brand">
                WAVS
            </div>

            <h1>Web Application Vulnerability Report</h1>

            <p class="subtitle">
                Web Application Vulnerability Scanner
                — Automated Security Assessment
            </p>

            <div class="header-label">
                Security Assessment Report
            </div>

        </header>


        <!-- =====================================
             SCAN INFORMATION
        ====================================== -->

        <section class="section">

            <h2>Scan Information</h2>

            <div class="meta">

                <div class="meta-row">
                    <span class="meta-label">Target URL:</span>

                    <span class="meta-value">
                        {target}
                    </span>
                </div>

                <div class="meta-row">
                    <span class="meta-label">Scan ID:</span>

                    <span class="meta-value">
                        {scan_id}
                    </span>
                </div>

                <div class="meta-row">
                    <span class="meta-label">Scan Started:</span>

                    <span class="meta-value">
                        {started_at}
                    </span>
                </div>

                <div class="meta-row">
                    <span class="meta-label">Scan Finished:</span>

                    <span class="meta-value">
                        {finished_at}
                    </span>
                </div>

                <div class="meta-row">
                    <span class="meta-label">Report Generated:</span>

                    <span class="meta-value">
                        {generated}
                    </span>
                </div>

            </div>

        </section>


        <!-- =====================================
             SEVERITY SUMMARY
        ====================================== -->

        <section class="section">

            <h2>Vulnerability Summary</h2>

            <div class="summary">

                {summary_cards}

            </div>

        </section>


        <!-- =====================================
             FINDINGS TABLE
        ====================================== -->

        <section class="section">

            <h2>Security Findings ({findings_count})</h2>

            <div class="table-wrapper">

                <table>

                    <thead>

                        <tr>
                            <th>Finding Type</th>
                            <th>Severity</th>
                            <th>Location</th>
                            <th>Parameter</th>
                            <th>Method</th>
                            <th>Evidence</th>
                            <th>Explanation</th>
                            <th>Remediation</th>
                        </tr>

                    </thead>

                    <tbody>

                        {table_rows}

                    </tbody>

                </table>

            </div>

        </section>


        <!-- =====================================
             EMPTY STATE
        ====================================== -->

        {"<div class='empty-state'><h3>No Vulnerabilities Detected</h3><p>WAVS did not identify any vulnerabilities during this scan. This does not guarantee that the target application is completely secure.</p></div>" if findings_count == 0 else ""}


        <!-- =====================================
             DISCLAIMER
        ====================================== -->

        <section class="disclaimer">

            <strong>Security Disclaimer:</strong>

            This report is generated through automated security testing.
            Findings may include false positives or false negatives.
            Results should be manually verified by a qualified security professional.

            This assessment should only be performed against web applications
            for which explicit testing authorization has been obtained.

        </section>


        <!-- =====================================
             FOOTER
        ====================================== -->

        <footer class="footer">

            <p>
                Generated by
                <span class="footer-brand">WAVS</span>
                — Web Application Vulnerability Scanner
            </p>

            <p>
                Automated Web Security Analysis |
                Security Research &amp; Assessment
            </p>

        </footer>

    </div>

</body>

</html>
"""

    # -----------------------------------------------------
    # Save report
    # -----------------------------------------------------

    report_path.write_text(
        html,
        encoding="utf-8"
    )

    return str(report_path)
