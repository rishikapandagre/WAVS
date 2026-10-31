# WAVS - Web Application Vulnerability Scanner

A Python-based web application security scanner designed to identify common web vulnerabilities, analyze potential security risks, and generate structured scan reports through a user-friendly web interface.

---

## Overview

The **Web App Vulnerability Scanner (WAVS)** is a web-based security assessment tool developed to assist in identifying common vulnerabilities in web applications.

The project combines a Python-based backend with a web-based frontend to provide an integrated vulnerability scanning experience. It performs security checks on a specified target, analyzes responses, identifies potential vulnerabilities, classifies findings according to severity, and presents results through a dashboard.

WAVS aims to make basic web application security testing more accessible to students, developers, and cybersecurity learners while demonstrating the practical implementation of vulnerability detection techniques.

> **Disclaimer:** This project is intended strictly for educational purposes and authorized security testing.

## Objectives

- Develop a functional web-based vulnerability scanning system.
- Identify common security weaknesses in web applications.
- Automate selected web security assessment techniques.
- Implement modular vulnerability detection mechanisms.
- Classify identified vulnerabilities based on severity.
- Generate structured and readable security assessment reports.
- Provide an interactive dashboard for displaying scan results.
- Demonstrate practical applications of web security and ethical hacking concepts.

## Features

### Web Application Scanning
- Accepts a target URL for security assessment.
- Sends HTTP requests to interact with the target application.
- Crawls accessible pages and identifies relevant endpoints.
- Collects URLs, forms, and parameters for further analysis.

### Vulnerability Detection
- SQL Injection (SQLi) detection
- Cross-Site Scripting (XSS) detection
- Cross-Site Request Forgery (CSRF) analysis
- TCP port scanning
- Basic HTTP response and security-related analysis

### Security Assessment
- Identifies potential security weaknesses.
- Categorizes vulnerabilities by severity.
- Records relevant information about detected issues.
- Maintains scan logs for debugging and monitoring.

### Dashboard and Reporting
- Interactive web-based frontend.
- Displays scan status and vulnerability findings.
- Presents vulnerability counts and severity distribution.
- Generates structured security reports.
- Stores scan results in an SQLite database.

---

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python |
| Frontend | HTML5 |
| Styling | CSS3 |
| Client-side functionality | JavaScript |
| HTTP communication | Requests |
| Web crawling | BeautifulSoup |
| Concurrent scanning | ThreadPoolExecutor |
| Database | SQLite |
| Report generation | Python-based HTML reporting |
| Development environment | Visual Studio Code |

---

## Project Structure

```text
web-vuln-scanner/
│
├── Backend/
│   ├── app.py
│   ├── config.py
│   │
│   ├── Scanner/
│   │   ├── __init__.py
│   │   ├── crawler.py
│   │   ├── sql_injection.py
│   │   ├── xss.py
│   │   ├── csrf.py
│   │   ├── port_scan.py
│   │   └── severity.py
│   │
│   ├── Reports/
│   │   ├── report_generator.py
│   │   └── templates/
│   │       └── report_template.html
│   │
│   ├── Utils/
│   │   ├── request_handler.py
│   │   ├── payloads.py
│   │   └── logger.py
│   │
│   └── database/
│       └── scan_results.db
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── main.js
│
├── requirements.txt
├── README.md
└── run.py
```

### Backend Components

| File / Module | Description |
|---|---|
| `app.py` | Initializes the backend application and handles API requests. |
| `config.py` | Contains configuration settings for the scanner. |
| `Scanner/crawler.py` | Crawls the target website and discovers accessible endpoints. |
| `Scanner/sql_injection.py` | Implements SQL injection detection logic. |
| `Scanner/xss.py` | Implements Cross-Site Scripting detection logic. |
| `Scanner/csrf.py` | Analyzes forms for potential CSRF weaknesses. |
| `Scanner/port_scan.py` | Performs TCP port scanning on authorized targets. |
| `Scanner/severity.py` | Assigns severity classifications to findings. |
| `Reports/report_generator.py` | Generates structured vulnerability reports. |
| `Reports/templates/report_template.html` | HTML template used to render reports. |
| `Utils/request_handler.py` | Handles and normalizes HTTP requests and target URLs. |
| `Utils/payloads.py` | Stores test payloads used by detection modules. |
| `Utils/logger.py` | Provides logging and debugging functionality. |
| `database/scan_results.db` | SQLite database for storing scan results. |

### Frontend Components

| File | Description |
|---|---|
| `index.html` | Defines the scanner dashboard structure. |
| `style.css` | Provides styling, layout, and responsive design. |
| `main.js` | Handles user interactions, API communication, and dynamic result rendering. |

---

## Vulnerability Detection Modules

### 1. SQL Injection (SQLi)

The SQL injection module examines accessible application parameters for potential SQL injection vulnerabilities.

**Detection approach:**
- Identifies parameterized URLs and form inputs.
- Submits controlled test inputs.
- Analyzes responses for database-related error messages and abnormal behavior.
- Identifies indicators of potential SQL injection.

**Potential impact:**
- Unauthorized database access
- Data exposure
- Authentication bypass
- Database manipulation

### 2. Cross-Site Scripting (XSS)

The XSS detection module tests whether user-controlled input is reflected in web responses without appropriate sanitization or encoding.

**Detection approach:**
- Identifies relevant input parameters and forms.
- Submits controlled test strings.
- Examines returned HTML for reflected input.
- Evaluates whether the input appears in potentially executable contexts.

**Potential impact:**
- Client-side script execution
- Session compromise
- Phishing attacks
- Unauthorized actions performed in a user's browser

### 3. Cross-Site Request Forgery (CSRF)

The CSRF module examines forms and request patterns for indicators of inadequate cross-site request protection.

**Detection approach:**
- Identifies state-changing forms.
- Inspects form fields for anti-CSRF tokens.
- Examines relevant request methods and form attributes.
- Reports forms that may lack appropriate protections.

**Potential impact:**
- Unauthorized actions on behalf of authenticated users
- Account modification
- Unintended transactions or state changes

**Note:** The absence of a visible token alone does not conclusively establish a CSRF vulnerability. Further contextual verification is required.

### 4. TCP Port Scanning

The port scanning module checks selected TCP ports on an authorized target to identify accessible network services.

**Detection approach:**
- Attempts TCP connections to configured ports.
- Identifies ports that accept connections.
- Records discovered open ports.
- Reports potential exposure of unnecessary services.

**Potential impact:**
- Increased attack surface
- Exposure of unnecessary services
- Potentially insecure network configurations

### 5. Severity Classification

The severity module assigns risk categories to findings based on their vulnerability type and potential impact.

Severity levels include:

- Critical
- High
- Medium
- Low
- Informational

---

## System Architecture

WAVS follows a modular client-server architecture.

```text
                 USER
                  |
                  v
       +----------------------+
       |   Frontend UI       |
       | HTML / CSS / JS     |
       +----------------------+
                  |
                  | HTTP API Requests
                  v
       +----------------------+
       |   Backend Server    |
       |      app.py         |
       +----------------------+
                  |
                  v
       +----------------------+
       |   Request Handler   |
       | URL Validation      |
       +----------------------+
                  |
                  v
       +----------------------+
       |   Web Crawler        |
       | Endpoint Discovery   |
       +----------------------+
                  |
                  v
       +-------------------------------+
       |    Scanning Engine           |
       |-------------------------------|
       | SQL Injection Detection       |
       | XSS Detection                |
       | CSRF Analysis                |
       | TCP Port Scanning            |
       +-------------------------------+
                  |
                  v
       +----------------------+
       | Severity Assessment  |
       +----------------------+
                  |
          +-------+--------+
          |                |
          v                v
 +---------------+  +------------------+
 | SQLite       |  | Report Generator |
 | Database     |  | HTML Reports     |
 +---------------+  +------------------+
          |                |
          +-------+--------+
                  |
                  v
       +----------------------+
       |  Frontend Dashboard |
       |  Scan Results       |
       +----------------------+
```

---

## Installation and Setup

### Prerequisites

Ensure the following are installed:

- Python 3.10 or later
- pip (Python package manager)
- Git
- Visual Studio Code or another Python-compatible IDE

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/web-vuln-scanner.git
```

Navigate to the project directory:

```bash
cd web-vuln-scanner
```

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
```

Activate the virtual environment.

**Windows (PowerShell):**

```powershell
.\venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**

```cmd
venv\Scripts\activate.bat
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure the Scanner

Review `Backend/config.py` and update the configuration according to your testing environment.

Ensure the configured scanning limits, request timeouts, and port settings are appropriate for your environment.

### Step 5: Run the Application

From the root directory:

```bash
python run.py
```

Once the server starts, open the local URL displayed in the terminal in your web browser.

---

## Usage

### Step 1: Launch WAVS

Start the backend using:

```bash
python run.py
```

### Step 2: Access the Dashboard

Open the application in your browser using the local server address.

### Step 3: Enter the Target URL

Enter the URL of the web application you own or have explicit permission to test.

Example:

```text
http://127.0.0.1:5000
```

### Step 4: Initiate the Scan

Start the scan using the dashboard interface.

The backend processes the request and executes the configured scanning modules.

### Step 5: Review Results

The dashboard displays the scan results, including:

- Scan status
- Discovered endpoints
- Detected vulnerabilities
- Vulnerability type
- Severity classification
- Relevant technical details

### Step 6: Generate a Report

Generate a security assessment report to review and document the identified findings.

---

## Scan Workflow

The scanner follows a structured workflow:

1. **Target Input:** The user provides a target URL.
2. **Validation:** The backend validates and normalizes the target.
3. **Crawling:** The crawler discovers accessible pages, forms, and parameters.
4. **Analysis:** The scanning engine executes the configured vulnerability checks.
5. **Detection:** Each module evaluates the collected responses for vulnerability indicators.
6. **Classification:** The severity module categorizes identified findings.
7. **Storage:** Scan information and results are stored in the SQLite database.
8. **Reporting:** The report generator prepares a structured security report.
9. **Visualization:** The frontend retrieves and displays the results.

---

## Severity Classification

| Severity | Description |
|---|---|
| Critical | Vulnerabilities with potentially severe consequences, such as extensive unauthorized access or critical compromise. |
| High | Vulnerabilities that may result in significant security impact. |
| Medium | Vulnerabilities with moderate impact or requiring additional conditions to exploit. |
| Low | Vulnerabilities with limited direct security impact. |
| Informational | Observations, configuration details, or security recommendations without a confirmed direct vulnerability. |

Severity assignments are intended to support prioritization and should be reviewed in the context of the target application.

---

## Report Generation

WAVS includes a report generation module designed to produce structured HTML-based security assessment reports.

Reports may include:

- Target URL
- Scan date and time
- Scan summary
- Total findings
- Vulnerability distribution by severity
- Vulnerability descriptions
- Affected endpoints
- Technical observations
- Recommended remediation steps

The report template is located at:

```text
Backend/Reports/templates/report_template.html
```

The report generator is located at:

```text
Backend/Reports/report_generator.py
```

---

## Security and Ethical Considerations

WAVS is developed for **educational purposes, controlled security experiments, and authorized security assessments.**

Users must:

- Obtain explicit permission before scanning any website.
- Test only applications they own or are authorized to assess.
- Avoid disrupting production services.
- Use responsible request rates and scanning limits.
- Protect sensitive information collected during testing.
- Follow applicable cybersecurity laws and regulations.
- Report discovered vulnerabilities responsibly.

### Important

This tool is not intended for unauthorized penetration testing, exploitation, service disruption, or malicious activity.

The author assumes no responsibility for misuse of this software.

---

## Limitations

The current implementation has certain limitations:

- Detection results may include false positives or false negatives.
- SQL injection and XSS checks depend on observable response behavior.
- CSRF analysis may require manual verification.
- JavaScript-rendered content may not be fully accessible to a basic HTTP crawler.
- Authentication-protected pages may require additional session handling.
- Complex application workflows may not be discovered automatically.
- Port scanning covers only the configured ports and scope.
- Findings should not be considered a substitute for comprehensive manual security testing.

---

## Future Enhancements

Potential improvements for future development include:

- Authentication-aware crawling and scanning.
- Advanced SQL injection detection techniques.
- DOM-based and stored XSS analysis.
- Improved CSRF verification.
- Directory and endpoint discovery enhancements.
- SSL/TLS configuration analysis.
- Security header analysis.
- Cookie security attribute assessment.
- REST API security testing.
- Export reports in PDF and JSON formats.
- Historical scan comparison.
- Scan scheduling and monitoring.
- Improved false-positive reduction.
- Integration with industry-standard vulnerability databases.
- Enhanced dashboard visualizations.
- CVSS-based risk scoring.
- More comprehensive automated testing.

---

## Research and Academic Scope

WAVS can serve as a practical foundation for academic research in web application security.

Possible areas of investigation include:

- Effectiveness of automated vulnerability detection.
- Comparison of detection techniques for common web vulnerabilities.
- Accuracy and limitations of lightweight vulnerability scanners.
- False-positive and false-negative analysis.
- Performance evaluation of concurrent scanning.
- Comparative analysis with existing web security tools.

The project demonstrates the integration of software development, web technologies, networking, database management, and cybersecurity principles.

---

## Contributing

Contributions, suggestions, bug reports, and feature requests are welcome.

To contribute:

1. Fork this repository.
2. Create a new feature branch.
3. Implement your changes.
4. Test your modifications.
5. Commit your changes with a descriptive message.
6. Submit a pull request.

Please ensure that contributions follow secure coding practices and responsible cybersecurity principles.

---

## License

This project is intended for educational and research purposes.

If you plan to publish it publicly, consider adding an open-source license such as the [MIT License](https://opensource.org/licenses/MIT) to clearly define usage, modification, and distribution permissions.

---

## Author

**WAVS — Web App Vulnerability Scanner**

Developed as a cybersecurity and web application security project focused on automated vulnerability detection, security analysis, and reporting.

