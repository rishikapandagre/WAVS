
"""Generate downloadable HTML reports for WAVS scans."""

from datetime import datetime, timezone
from html import escape
import re

from config import REPORT_DIR


def generate_html_report(scan):
    """
    Generate a standalone HTML report for a completed WAVS scan.

    Returns:
        str: Path to the generated HTML report.
    """

    if not isinstance(scan, dict):
        raise ValueError("Scan data must be a dictionary.")

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    findings = scan.get("findings", [])

    if not isinstance(findings, list):
        findings = []

    columns = (
        "severity",
        "type",
        "url",
        "parameter",
        "method",
        "evidence",
        "recommendation"
    )

    rows = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        cells = "".join(
            f"<td>{escape(str(finding.get(key, '')))}</td>"
            for key in columns
        )

        rows.append(f"<tr>{cells}</tr>")

    target = escape(str(scan.get("target", "Unknown")))
    scan_id = escape(str(scan.get("id", "Unknown")))

    generated = escape(
        datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    )

    findings_count = len(findings)

    table_rows = "".join(rows)

    if not table_rows:
        table_rows = (
            '<tr><td colspan="7" class="empty">'
            'No findings recorded for this scan.'
            '</td></tr>'
        )

    # Use a sanitized scan ID for the report filename.
    raw_report_id = str(scan.get("id", "unknown"))

    safe_report_id = re.sub(
        r"[^a-zA-Z0-9_-]",
        "_",
        raw_report_id
    )[:100] or "unknown"

    report_filename = f"wavs_report_{safe_report_id}.html"

    report_path = REPORT_DIR / report_filename

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>WAVS — Scan Report</title>

    <style>
        :root {{
            --primary: #7952c7;
            --primary-light: #f0eaff;
            --background: #f7f8fc;
            --surface: #ffffff;
            --text: #202533;
            --muted: #687083;
            --border: #e3e6ed;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: Arial, Helvetica, sans-serif;
            font-size: 16px;
            line-height: 1.7;
            margin: 0;
            padding: 32px;
            background: var(--background);
            color: var(--text);
        }}

        .container {{
            max-width: 1500px;
            margin: 0 auto;
        }}

        h1 {{
            color: var(--primary);
            font-size: 30px;
            margin-bottom: 8px;
        }}

        .subtitle {{
            color: var(--muted);
            margin-top: 0;
            margin-bottom: 28px;
        }}

        .meta {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 5px solid var(--primary);
            padding: 22px;
            margin-bottom: 28px;
            border-radius: 10px;
            overflow-wrap: anywhere;
        }}

        .meta p {{
            margin: 8px 0;
        }}

        .count {{
            display: inline-block;
            background: var(--primary-light);
            color: var(--primary);
            font-weight: bold;
            padding: 4px 12px;
            border-radius: 20px;
        }}

        h2 {{
            font-size: 22px;
            margin-bottom: 16px;
        }}

        .table-wrapper {{
            width: 100%;
            overflow-x: auto;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
        }}

        table {{
            width: 100%;
            min-width: 900px;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            text-align: left;
            vertical-align: top;
            overflow-wrap: anywhere;
        }}

        th {{
            background: var(--primary-light);
            color: #49318b;
            font-weight: bold;
            white-space: nowrap;
        }}

        tbody tr:nth-child(even) {{
            background: #fafaff;
        }}

        tbody tr:hover {{
            background: #f1edff;
        }}

        tbody tr:last-child td {{
            border-bottom: none;
        }}

        .empty {{
            text-align: center;
            color: var(--muted);
            padding: 30px;
        }}

        .footer {{
            margin-top: 30px;
            padding: 18px;
            color: var(--muted);
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 14px;
        }}

        .footer strong {{
            color: var(--text);
        }}

        @media (max-width: 768px) {{
            body {{
                padding: 16px;
                font-size: 15px;
            }}

            h1 {{
                font-size: 24px;
            }}

            .meta {{
                padding: 16px;
            }}
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            .table-wrapper {{
                overflow: visible;
            }}

            table {{
                min-width: 0;
                font-size: 11px;
            }}

            th, td {{
                padding: 8px;
            }}

            .footer {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>

<body>

<div class="container">

    <h1>WAVS — Web Application Scan Report</h1>

    <p class="subtitle">
        Web Application Vulnerability Scanner
    </p>

    <div class="meta">
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan ID:</strong> {scan_id}</p>
        <p><strong>Generated:</strong> {generated}</p>
        <p>
            <strong>Total Findings:</strong>
            <span class="count">{findings_count}</span>
        </p>
    </div>

    <h2>Vulnerability Findings</h2>

    <div class="table-wrapper">

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Finding Type</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Method</th>
                    <th>Evidence</th>
                    <th>Recommendation</th>
                </tr>
            </thead>

            <tbody>
                {table_rows}
            </tbody>
        </table>

    </div>

    <div class="footer">
        <strong>Disclaimer:</strong>
        WAVS is an automated security assessment tool.
        Findings are indicative and should be manually verified.
        This report is intended for authorized security testing only.
    </div>

</div>

</body>
</html>
"""

    report_path.write_text(
        html,
        encoding="utf-8"
    )

    return str(report_path)
