
/* =========================================================
   WAVS
   Web Application Vulnerability Scanner
   Main JavaScript — Frontend / Flask Integration
========================================================= */

"use strict";

/* =========================================================
   CONFIGURATION
========================================================= */

const API_BASE_URL = "http://127.0.0.1:5000/api";

const CONFIG = {
    maxPages: 20,
    requestTimeout: 300000,

    defaultPorts: [
        21, 22, 25, 53, 80,
        110, 143, 443, 3306, 8080, 8443
    ]
};

/* =========================================================
   APPLICATION STATE
========================================================= */

const state = {
    isScanning: false,
    stopRequested: false,

    currentScan: null,
    currentScanId: null,

    findings: [],
    filteredFindings: [],

    selectedFinding: null,
    selectedProfile: "full",

    scanStartTime: null,
    scanEndTime: null,

    scanHistory: [],
    consoleMessages: [],

    abortController: null,

    modules: {
        crawler: true,
        sqli: true,
        xss: true,
        csrf: true,
        ports: true
    }
};

/* =========================================================
   DOM ELEMENTS
========================================================= */

const elements = {
    targetUrl: document.getElementById("targetUrl"),

    startScanButton: document.getElementById("startScanButton"),
    stopScanButton: document.getElementById("stopScanButton"),
    settingsButton: document.getElementById("settingsButton"),
    refreshResultsButton: document.getElementById("refreshResultsButton"),

    profileOptions: document.querySelectorAll("[data-profile]"),
    moduleCheckboxes: document.querySelectorAll('input[name="module"]'),

    endpointCount: document.getElementById("endpointCount"),
    requestCount: document.getElementById("requestCount"),
    findingCount: document.getElementById("findingCount"),
    scanTime: document.getElementById("scanTime"),
    scanTargetDisplay: document.getElementById("scanTargetDisplay"),

    securityScore: document.getElementById("securityScore"),
    securityScoreRing: document.getElementById("securityScoreRing"),
    scoreStatus: document.getElementById("scoreStatus"),
    scoreStatusIndicator: document.getElementById("scoreStatusIndicator"),

    criticalCount: document.getElementById("criticalCount"),
    highCount: document.getElementById("highCount"),
    mediumCount: document.getElementById("mediumCount"),
    lowCount: document.getElementById("lowCount"),

    scanStatusBadge: document.getElementById("scanStatusBadge"),
    scanProgressValue: document.getElementById("scanProgressValue"),
    scanProgressBar: document.getElementById("scanProgressBar"),
    currentScanStage: document.getElementById("currentScanStage"),
    progressTarget: document.getElementById("progressTarget"),
    activeModule: document.getElementById("activeModule"),
    scanEta: document.getElementById("scanEta"),

    moduleStatusCards: document.querySelectorAll(".module-status-card"),

    crawlerStatus: document.getElementById("crawlerStatus"),
    sqliStatus: document.getElementById("sqliStatus"),
    xssStatus: document.getElementById("xssStatus"),
    csrfStatus: document.getElementById("csrfStatus"),
    portsStatus: document.getElementById("portsStatus"),

    crawlerCount: document.getElementById("crawlerCount"),
    sqliCount: document.getElementById("sqliCount"),
    xssCount: document.getElementById("xssCount"),
    csrfCount: document.getElementById("csrfCount"),
    portsCount: document.getElementById("portsCount"),

    consoleOutput: document.getElementById("consoleOutput"),
    clearConsoleButton: document.getElementById("clearConsoleButton"),

    severityFilter: document.getElementById("severityFilter"),
    moduleFilter: document.getElementById("moduleFilter"),
    findingsTableBody: document.getElementById("findingsTableBody"),

    findingDetails: document.getElementById("findingDetails"),
    closeFindingDetails: document.getElementById("closeFindingDetails"),

    detailSeverity: document.getElementById("detailSeverity"),
    detailTitle: document.getElementById("detailTitle"),
    detailUrl: document.getElementById("detailUrl"),
    detailModule: document.getElementById("detailModule"),
    detailParameter: document.getElementById("detailParameter"),
    detailDetected: document.getElementById("detailDetected"),
    detailDescription: document.getElementById("detailDescription"),
    detailImpact: document.getElementById("detailImpact"),
    detailEvidence: document.getElementById("detailEvidence"),
    detailRemediation: document.getElementById("detailRemediation"),

    telemetryRequests: document.getElementById("telemetryRequests"),
    telemetryEndpoints: document.getElementById("telemetryEndpoints"),
    telemetryParameters: document.getElementById("telemetryParameters"),
    telemetryPorts: document.getElementById("telemetryPorts"),
    telemetryErrors: document.getElementById("telemetryErrors"),

    jsonReportButton: document.getElementById("jsonReportButton"),
    pdfReportButton: document.getElementById("pdfReportButton")
};

/* =========================================================
   INITIALIZATION
========================================================= */

function initializeWAVS() {
    bindEventListeners();
    initializeProfiles();
    updateModuleCheckboxes();
    updateModuleSelection();
    resetDashboard();

    checkBackendHealth();
    loadScanHistory();

    addConsoleMessage(
        "SYSTEM",
        "WAVS dashboard initialized successfully."
    );

    addConsoleMessage(
        "SYSTEM",
        "Waiting for target configuration..."
    );
}

if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initializeWAVS,
        { once: true }
    );
} else {
    initializeWAVS();
}

/* =========================================================
   EVENT LISTENERS
========================================================= */

function bindEventListeners() {
    elements.startScanButton?.addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();
        startScan();
    });

    elements.stopScanButton?.addEventListener("click", event => {
        event.preventDefault();
        stopScan();
    });

    elements.profileOptions.forEach(button => {
        button.addEventListener("click", event => {
            event.preventDefault();
            selectProfile(button.dataset.profile);
        });
    });

    elements.moduleCheckboxes.forEach(checkbox => {
        checkbox.addEventListener("change", () => {
            const moduleName = checkbox.value;

            if (
                Object.prototype.hasOwnProperty.call(
                    state.modules,
                    moduleName
                )
            ) {
                state.modules[moduleName] = checkbox.checked;
            }

            selectProfile("custom");
            updateModuleSelection();
        });
    });

    elements.severityFilter?.addEventListener(
        "change",
        applyFindingsFilters
    );

    elements.moduleFilter?.addEventListener(
        "change",
        applyFindingsFilters
    );

    elements.clearConsoleButton?.addEventListener("click", event => {
        event.preventDefault();
        clearConsole();
    });

    elements.refreshResultsButton?.addEventListener("click", event => {
        event.preventDefault();
        refreshResults();
    });

    elements.closeFindingDetails?.addEventListener("click", event => {
        event.preventDefault();
        closeFindingDetails();
    });

    elements.jsonReportButton?.addEventListener("click", event => {
        event.preventDefault();
        exportJSONReport();
    });

    elements.pdfReportButton?.addEventListener("click", event => {
        event.preventDefault();
        generatePDFReport();
    });

    elements.targetUrl?.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            event.preventDefault();
            startScan();
        }
    });

    elements.settingsButton?.addEventListener("click", event => {
        event.preventDefault();
        showSettings();
    });

    const targetForm = elements.targetUrl?.closest("form");

    targetForm?.addEventListener("submit", event => {
        event.preventDefault();
    });
}

/* =========================================================
   PROFILES
========================================================= */

function initializeProfiles() {
    selectProfile("full");
}

function selectProfile(profile) {
    state.selectedProfile = profile;

    elements.profileOptions.forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.profile === profile
        );
    });

    if (profile === "full") {
        state.modules = {
            crawler: true,
            sqli: true,
            xss: true,
            csrf: true,
            ports: true
        };
    } else if (profile === "quick") {
        state.modules = {
            crawler: true,
            sqli: true,
            xss: true,
            csrf: true,
            ports: false
        };
    } else if (profile === "custom") {
        // Preserve the user's custom module selection.
    }

    updateModuleCheckboxes();
    updateModuleSelection();

    addConsoleMessage(
        "SYSTEM",
        `${profile.toUpperCase()} profile selected.`
    );
}

/* =========================================================
   MODULE SELECTION
========================================================= */

function updateModuleCheckboxes() {
    elements.moduleCheckboxes.forEach(checkbox => {
        const moduleName = checkbox.value;

        if (
            Object.prototype.hasOwnProperty.call(
                state.modules,
                moduleName
            )
        ) {
            checkbox.checked = state.modules[moduleName];
        }
    });
}

function updateModuleSelection() {
    elements.moduleCheckboxes.forEach(checkbox => {
        const parent = checkbox.closest(".module-item");

        parent?.classList.toggle(
            "module-disabled",
            !checkbox.checked
        );
    });
}

/* =========================================================
   BUILD SCAN PAYLOAD
========================================================= */

function buildScanPayload(target) {
    return {
        target,
        max_pages: CONFIG.maxPages,

        modules: {
            crawler: Boolean(state.modules.crawler),
            sqli: Boolean(state.modules.sqli),
            xss: Boolean(state.modules.xss),
            csrf: Boolean(state.modules.csrf),
            ports: Boolean(state.modules.ports)
        },

        port_scan: Boolean(state.modules.ports),

        ports: state.modules.ports
            ? CONFIG.defaultPorts
            : []
    };
}

/* =========================================================
   TARGET VALIDATION
========================================================= */

function isValidTarget(target) {
    try {
        const url = new URL(target);

        return (
            (url.protocol === "http:" ||
                url.protocol === "https:") &&
            Boolean(url.hostname)
        );
    } catch {
        return false;
    }
}

/* =========================================================
   BACKEND HEALTH CHECK
========================================================= */

async function checkBackendHealth() {
    try {
        const response = await fetch(
            `${API_BASE_URL}/health`,
            {
                method: "GET",
                headers: {
                    Accept: "application/json"
                }
            }
        );

        if (!response.ok) {
            throw new Error(
                `Backend returned HTTP ${response.status}`
            );
        }

        const data = await response.json();

        if (
            data.success === true ||
            data.status === "ok" ||
            data.status === "healthy"
        ) {
            addConsoleMessage(
                "SUCCESS",
                "Flask backend connection established."
            );

            updateSystemStatus(true);
        } else {
            updateSystemStatus(false);

            addConsoleMessage(
                "WARNING",
                "Backend is reachable but health status is not confirmed."
            );
        }
    } catch (error) {
        console.error("Backend health check:", error);

        addConsoleMessage(
            "ERROR",
            "Cannot connect to Flask backend."
        );

        addConsoleMessage(
            "ERROR",
            "Ensure app.py is running at http://127.0.0.1:5000."
        );

        updateSystemStatus(false);
    }
}

/* =========================================================
   SYSTEM STATUS
========================================================= */

function updateSystemStatus(isOnline) {
    const statusElements = document.querySelectorAll(
        ".system-status, .footer-left"
    );

    statusElements.forEach(element => {
        const dot = element.querySelector(".status-dot");

        if (dot) {
            dot.classList.toggle("online", isOnline);
            dot.classList.toggle("offline", !isOnline);
        }
    });
}

/* =========================================================
   START SCAN
========================================================= */

async function startScan() {
    if (state.isScanning) {
        showNotification(
            "A scan is already running.",
            "warning"
        );
        return;
    }

    const target = elements.targetUrl?.value.trim() || "";

    if (!target) {
        showNotification(
            "Please enter a target URL.",
            "error"
        );
        elements.targetUrl?.focus();
        return;
    }

    if (!isValidTarget(target)) {
        showNotification(
            "Enter a valid HTTP or HTTPS URL.",
            "error"
        );
        elements.targetUrl?.focus();
        return;
    }

    if (!Object.values(state.modules).some(Boolean)) {
        showNotification(
            "Please select at least one scanner module.",
            "warning"
        );
        return;
    }

    state.isScanning = true;
    state.stopRequested = false;
    state.scanStartTime = Date.now();
    state.scanEndTime = null;
    state.currentScan = null;
    state.currentScanId = null;
    state.findings = [];
    state.filteredFindings = [];

    resetDashboard();
    setScanControls(true);

    if (elements.scanTargetDisplay) {
        elements.scanTargetDisplay.textContent = target;
    }

    updateScanStatus("SCANNING");

    updateProgress(
        5,
        "Initializing scanner engine...",
        "SYSTEM"
    );

    addConsoleMessage("INFO", `Scan initiated for ${target}`);
    addConsoleMessage(
        "INFO",
        `Profile: ${state.selectedProfile.toUpperCase()}`
    );

    addConsoleMessage(
        "INFO",
        `Selected modules: ${
            Object.keys(state.modules)
                .filter(module => state.modules[module])
                .join(", ")
                .toUpperCase()
        }`
    );

    const controller = new AbortController();
    state.abortController = controller;

    const timeoutId = setTimeout(
        () => controller.abort(),
        CONFIG.requestTimeout
    );

    try {
        const payload = buildScanPayload(target);

        addConsoleMessage(
            "INFO",
            "Sending scan request to Flask backend..."
        );

        updateProgress(
            15,
            "Waiting for backend scanner...",
            "BACKEND"
        );

        const response = await fetch(
            `${API_BASE_URL}/scan`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Accept: "application/json"
                },
                body: JSON.stringify(payload),
                signal: controller.signal
            }
        );

        addConsoleMessage(
            "INFO",
            `Backend responded with HTTP ${response.status}.`
        );

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error(
                `Backend returned invalid JSON (HTTP ${response.status}).`
            );
        }

        if (!response.ok) {
            throw new Error(
                data.error ||
                data.message ||
                `Scan request failed with HTTP ${response.status}.`
            );
        }

        if (data.success === false) {
            throw new Error(
                data.error ||
                data.message ||
                "The backend reported that the scan failed."
            );
        }

        const scan =
            data.scan ||
            data.result ||
            data.data ||
            data;

        if (!scan || typeof scan !== "object") {
            throw new Error(
                "Backend response does not contain valid scan results."
            );
        }

        const scanId =
            scan.id ??
            scan.scan_id ??
            data.scan_id ??
            data.id ??
            null;

        if (scanId !== null) {
            scan.id = scanId;
        }

        const findings =
            scan.findings ||
            scan.vulnerabilities ||
            data.findings ||
            data.vulnerabilities ||
            [];

        scan.findings = Array.isArray(findings)
            ? findings
            : [];

        scan.pages_scanned ??=
            scan.visited_count ??
            scan.pages ??
            scan.total_pages ??
            0;

        scan.forms_found ??=
            scan.forms_count ??
            scan.total_forms ??
            0;

        state.currentScan = scan;
        state.currentScanId = scanId;
        state.findings = scan.findings;
        state.scanEndTime = Date.now();

        updateProgress(
            100,
            "Scan completed successfully.",
            "COMPLETE"
        );

        updateScanStatus("COMPLETED");

        addConsoleMessage(
            "SUCCESS",
            `Scan #${scanId ?? "N/A"} completed successfully.`
        );

        addConsoleMessage(
            "SUCCESS",
            `Pages scanned: ${scan.pages_scanned}`
        );

        addConsoleMessage(
            "SUCCESS",
            `Forms discovered: ${scan.forms_found}`
        );

        addConsoleMessage(
            "SUCCESS",
            `Findings detected: ${state.findings.length}`
        );

        renderScanResults(scan);

        showNotification(
            "Scan completed successfully!",
            "success"
        );

        await loadScanHistory();

    } catch (error) {
        console.error("Scan error:", error);
        state.scanEndTime = Date.now();

        if (error.name === "AbortError") {
            updateScanStatus(
                state.stopRequested ? "STOPPED" : "TIMEOUT"
            );

            addConsoleMessage(
                "WARNING",
                state.stopRequested
                    ? "Scan was cancelled."
                    : "Scan request timed out."
            );

            showNotification(
                state.stopRequested
                    ? "Scan cancelled."
                    : "The scan timed out. Check the target or backend.",
                state.stopRequested ? "warning" : "error"
            );
        } else {
            updateScanStatus("ERROR");

            addConsoleMessage(
                "ERROR",
                error.message || "An unexpected error occurred."
            );

            showNotification(
                error.message || "Scan failed.",
                "error"
            );
        }
    } finally {
        clearTimeout(timeoutId);

        state.isScanning = false;
        state.abortController = null;

        setScanControls(false);
        updateScanDuration();
    }
}

/* =========================================================
   STOP SCAN
========================================================= */

function stopScan() {
    if (!state.isScanning) {
        showNotification(
            "No scan is currently running.",
            "info"
        );
        return;
    }

    state.stopRequested = true;

    addConsoleMessage(
        "WARNING",
        "Stop requested by user."
    );

    if (state.abortController) {
        state.abortController.abort();

        addConsoleMessage(
            "WARNING",
            "Cancellation signal sent to the active scan request."
        );
    }

    updateScanStatus("STOPPING");

    showNotification(
        "Scan cancellation requested.",
        "warning"
    );
}

/* =========================================================
   SCAN CONTROLS
========================================================= */

function setScanControls(scanning) {
    if (elements.startScanButton) {
        elements.startScanButton.disabled = scanning;

        elements.startScanButton.classList.toggle(
            "scanning",
            scanning
        );

        elements.startScanButton.innerHTML = scanning
            ? `
                <span class="button-icon">◌</span>
                <span>SCANNING...</span>
              `
            : `
                <span class="button-icon">▶</span>
                <span>START SCAN</span>
              `;
    }

    if (elements.stopScanButton) {
        elements.stopScanButton.disabled = !scanning;
    }

    if (elements.targetUrl) {
        elements.targetUrl.disabled = scanning;
    }

    elements.profileOptions.forEach(button => {
        button.disabled = scanning;
    });

    elements.moduleCheckboxes.forEach(checkbox => {
        checkbox.disabled = scanning;
    });
}

/* =========================================================
   RESET DASHBOARD
========================================================= */

function resetDashboard() {
    updateProgress(
        0,
        "Waiting for scan...",
        "--"
    );

    updateScanStatus("IDLE");
    updateSeverityCounts([]);

    // No misleading score before scan results exist.
    if (elements.securityScore) {
        elements.securityScore.textContent = "--";
    }

    if (elements.scoreStatus) {
        elements.scoreStatus.textContent = "AWAITING SCAN";
    }

    if (elements.securityScoreRing) {
        elements.securityScoreRing.style.setProperty(
            "--score",
            0
        );

        elements.securityScoreRing.style.setProperty(
            "--percentage",
            "0%"
        );
    }

    if (elements.scoreStatusIndicator) {
        elements.scoreStatusIndicator.className =
            "severity-indicator";
    }

    updateModuleStatuses("Waiting");

    updateTelemetry({
        requests: "--",
        endpoints: 0,
        parameters: 0,
        ports: 0,
        errors: 0
    });

    if (elements.endpointCount) {
        elements.endpointCount.textContent = "00";
    }

    if (elements.requestCount) {
        elements.requestCount.textContent = "--";
    }

    if (elements.scanTime) {
        elements.scanTime.textContent = "00:00";
    }

    if (elements.findingsTableBody) {
        elements.findingsTableBody.innerHTML = `
            <tr class="empty-findings-row">
                <td colspan="6">
                    <div class="empty-state">
                        <span class="empty-icon">◇</span>
                        <strong>NO FINDINGS</strong>
                        <span>Start a scan to analyze the target.</span>
                    </div>
                </td>
            </tr>
        `;
    }

    closeFindingDetails();
}

/* =========================================================
   RENDER SCAN RESULTS
========================================================= */

function renderScanResults(scan) {
    const findings = Array.isArray(scan.findings)
        ? scan.findings
        : [];

    state.findings = findings;

    renderFindings(findings);
    updateSeverityCounts(findings);
    updateSecurityScore(findings);
    updateModuleStatusesFromFindings(findings);
    updateScanStats(scan);
    updateTelemetryFromScan(scan);

    if (elements.scanTargetDisplay) {
        elements.scanTargetDisplay.textContent =
            scan.target || "Target scanned";
    }
}

/* =========================================================
   FINDINGS FILTERS
========================================================= */

function renderFindings(findings) {
    state.findings = findings;
    applyFindingsFilters();
}

function applyFindingsFilters() {
    const severity = elements.severityFilter?.value || "all";
    const module = elements.moduleFilter?.value || "all";

    state.filteredFindings = state.findings.filter(finding => {
        const findingSeverity = normalizeSeverity(
            getFindingSeverity(finding)
        );

        const findingModule = normalizeModule(
            finding.module ||
            finding.type ||
            finding.category ||
            finding.scanner
        );

        const severityMatches =
            severity === "all" ||
            findingSeverity === severity;

        const moduleMatches =
            module === "all" ||
            findingModule === module;

        return severityMatches && moduleMatches;
    });

    renderFindingsTable(state.filteredFindings);
}

/* =========================================================
   FINDINGS TABLE
========================================================= */

function renderFindingsTable(findings) {
    if (!elements.findingsTableBody) {
        return;
    }

    if (!findings.length) {
        elements.findingsTableBody.innerHTML = `
            <tr class="empty-findings-row">
                <td colspan="6">
                    <div class="empty-state">
                        <span class="empty-icon">◇</span>
                        <strong>NO FINDINGS</strong>
                        <span>No vulnerabilities match the selected filters.</span>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    elements.findingsTableBody.innerHTML = "";

    findings.forEach(finding => {
        const severity = normalizeSeverity(
            getFindingSeverity(finding)
        );

        const title = getFindingTitle(finding);

        const url =
            finding.url ||
            finding.target ||
            finding.endpoint ||
            state.currentScan?.target ||
            "--";

        const module = normalizeModule(
            finding.module ||
            finding.type ||
            finding.category ||
            finding.scanner
        );

        const detected = formatDate(
            finding.detected_at ||
            finding.timestamp ||
            state.scanEndTime
        );

        const row = document.createElement("tr");
        row.className = "finding-row";

        row.innerHTML = `
            <td>
                <span class="severity-badge ${severity}">
                    ${escapeHTML(severity.toUpperCase())}
                </span>
            </td>

            <td class="finding-title-cell">
                <strong>${escapeHTML(title)}</strong>
            </td>

            <td class="finding-url-cell">
                <span title="${escapeHTML(url)}">
                    ${escapeHTML(truncateText(url, 55))}
                </span>
            </td>

            <td>
                <span class="module-badge ${module}">
                    ${escapeHTML(module.toUpperCase())}
                </span>
            </td>

            <td>${escapeHTML(detected)}</td>

            <td>
                <button class="view-finding-button" type="button">
                    VIEW
                </button>
            </td>
        `;

        row.querySelector(".view-finding-button")
            ?.addEventListener("click", event => {
                event.preventDefault();
                event.stopPropagation();
                showFindingDetails(finding);
            });

        row.addEventListener("click", () => {
            showFindingDetails(finding);
        });

        elements.findingsTableBody.appendChild(row);
    });
}

/* =========================================================
   FINDING DETAILS
========================================================= */

function showFindingDetails(finding) {
    state.selectedFinding = finding;

    const severity = normalizeSeverity(
        getFindingSeverity(finding)
    );

    const module = normalizeModule(
        finding.module ||
        finding.type ||
        finding.category ||
        finding.scanner
    );

    const title = getFindingTitle(finding);

    const url =
        finding.url ||
        finding.target ||
        finding.endpoint ||
        state.currentScan?.target ||
        "--";

    const parameter =
        finding.parameter ||
        finding.param ||
        finding.input ||
        finding.field ||
        "--";

    const detected = formatDate(
        finding.detected_at ||
        finding.timestamp ||
        state.scanEndTime
    );

    if (elements.detailSeverity) {
        elements.detailSeverity.textContent =
            severity.toUpperCase();

        elements.detailSeverity.className =
            `severity-badge ${severity}`;
    }

    if (elements.detailTitle) {
        elements.detailTitle.textContent = title;
    }

    if (elements.detailUrl) {
        elements.detailUrl.textContent = url;
    }

    if (elements.detailModule) {
        elements.detailModule.textContent =
            module.toUpperCase();
    }

    if (elements.detailParameter) {
        elements.detailParameter.textContent = parameter;
    }

    if (elements.detailDetected) {
        elements.detailDetected.textContent = detected;
    }

    if (elements.detailDescription) {
        elements.detailDescription.textContent =
            finding.description ||
            "No detailed description was provided by the scanner.";
    }

    if (elements.detailImpact) {
        elements.detailImpact.textContent =
            finding.impact ||
            finding.risk_description ||
            "Potential security impact depends on the affected application.";
    }

    if (elements.detailEvidence) {
        elements.detailEvidence.textContent =
            finding.evidence ||
            finding.payload ||
            finding.proof ||
            finding.response ||
            "No evidence recorded.";
    }

    if (elements.detailRemediation) {
        elements.detailRemediation.textContent =
            finding.remediation ||
            finding.recommendation ||
            finding.solution ||
            "Review the affected code and apply appropriate security controls.";
    }

    if (elements.findingDetails) {
        elements.findingDetails.classList.add("active");
        elements.findingDetails.style.display = "block";

        elements.findingDetails.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}

function closeFindingDetails() {
    state.selectedFinding = null;

    if (elements.findingDetails) {
        elements.findingDetails.classList.remove("active");
        elements.findingDetails.style.display = "none";
    }
}

/* =========================================================
   SEVERITY COUNTS
========================================================= */

function updateSeverityCounts(findings = []) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    };

    if (!Array.isArray(findings)) {
        findings = [];
    }

    findings.forEach(finding => {
        const severity = normalizeSeverity(
            getFindingSeverity(finding)
        );

        if (
            Object.prototype.hasOwnProperty.call(
                counts,
                severity
            )
        ) {
            counts[severity]++;
        }
    });

    if (elements.criticalCount) {
        elements.criticalCount.textContent =
            formatNumber(counts.critical, 2);
    }

    if (elements.highCount) {
        elements.highCount.textContent =
            formatNumber(counts.high, 2);
    }

    if (elements.mediumCount) {
        elements.mediumCount.textContent =
            formatNumber(counts.medium, 2);
    }

    if (elements.lowCount) {
        elements.lowCount.textContent =
            formatNumber(counts.low, 2);
    }

    if (elements.findingCount) {
        elements.findingCount.textContent =
            formatNumber(findings.length, 2);
    }
}

/* =========================================================
   SEVERITY EXTRACTION
========================================================= */

/**
 * Extract severity from different backend naming conventions.
 *
 * Supports:
 * severity, risk_level, risk, priority, level,
 * cvss_severity, severity_level, impact_level.
 */
function getFindingSeverity(finding = {}) {
    if (!finding || typeof finding !== "object") {
        return "info";
    }

    const candidates = [
        finding.severity,
        finding.risk_level,
        finding.severity_level,
        finding.cvss_severity,
        finding.impact_level,
        finding.priority,
        finding.level,
        finding.risk
    ];

    for (const candidate of candidates) {
        if (
            candidate !== null &&
            candidate !== undefined &&
            String(candidate).trim() !== ""
        ) {
            return candidate;
        }
    }

    // Some scanner results use CVSS numeric scores.
    const cvssScore =
        finding.cvss_score ??
        finding.cvss ??
        finding.score;

    if (
        cvssScore !== null &&
        cvssScore !== undefined &&
        Number.isFinite(Number(cvssScore))
    ) {
        return Number(cvssScore);
    }

    return "info";
}

/* =========================================================
   SECURITY SCORE
========================================================= */

/**
 * Count findings by normalized severity.
 */
function calculateSeverityCounts(findings = []) {
    const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    };

    if (!Array.isArray(findings)) {
        return counts;
    }

    findings.forEach(finding => {
        const severity = normalizeSeverity(
            getFindingSeverity(finding)
        );

        if (
            Object.prototype.hasOwnProperty.call(
                counts,
                severity
            )
        ) {
            counts[severity]++;
        }
    });

    return counts;
}

/**
 * Heuristic security score.
 *
 * Critical: -25
 * High:    -15
 * Medium:   -8
 * Low:     -3
 * Info:     0
 *
 * This is NOT a CVSS score.
 */
function calculateSecurityScore(findings = []) {
    if (!Array.isArray(findings)) {
        return null;
    }

    const counts = calculateSeverityCounts(findings);

    const deductions =
        counts.critical * 25 +
        counts.high * 15 +
        counts.medium * 8 +
        counts.low * 3;

    return Math.max(
        0,
        Math.min(100, 100 - deductions)
    );
}

/**
 * Update security score and dashboard indicators.
 */
function updateSecurityScore(findings = []) {
    const score = calculateSecurityScore(findings);

    if (score === null) {
        if (elements.securityScore) {
            elements.securityScore.textContent = "--";
        }

        if (elements.scoreStatus) {
            elements.scoreStatus.textContent = "NOT ANALYZED";
        }

        return;
    }

    if (elements.securityScore) {
        elements.securityScore.textContent = String(score);
    }

    if (elements.securityScoreRing) {
        elements.securityScoreRing.style.setProperty(
            "--score",
            score
        );

        elements.securityScoreRing.style.setProperty(
            "--percentage",
            `${score}%`
        );
    }

    let status;
    let color;

    if (score >= 95) {
        status = "SECURE";
        color = "green";
    } else if (score >= 80) {
        status = "LOW RISK";
        color = "yellow";
    } else if (score >= 60) {
        status = "MODERATE RISK";
        color = "orange";
    } else if (score >= 40) {
        status = "HIGH RISK";
        color = "red";
    } else {
        status = "CRITICAL RISK";
        color = "red";
    }

    if (elements.scoreStatus) {
        elements.scoreStatus.textContent = status;
    }

    if (elements.scoreStatusIndicator) {
        elements.scoreStatusIndicator.className =
            `severity-indicator ${color}`;
    }
}

/* =========================================================
   MODULE STATUS
========================================================= */

function updateModuleStatuses(status) {
    const modules = [
        "crawler",
        "sqli",
        "xss",
        "csrf",
        "ports"
    ];

    modules.forEach(module => {
        const statusElement = document.getElementById(
            `${module}Status`
        );

        if (statusElement) {
            statusElement.textContent = status;
        }
    });
}

function updateModuleStatusesFromFindings(findings) {
    const moduleCounts = {
        crawler: 0,
        sqli: 0,
        xss: 0,
        csrf: 0,
        ports: 0
    };

    findings.forEach(finding => {
        const module = normalizeModule(
            finding.module ||
            finding.type ||
            finding.category ||
            finding.scanner
        );

        if (
            Object.prototype.hasOwnProperty.call(
                moduleCounts,
                module
            )
        ) {
            moduleCounts[module]++;
        }
    });

    const moduleElements = {
        crawler: elements.crawlerCount,
        sqli: elements.sqliCount,
        xss: elements.xssCount,
        csrf: elements.csrfCount,
        ports: elements.portsCount
    };

    Object.entries(moduleElements).forEach(
        ([module, element]) => {
            if (element) {
                element.textContent =
                    formatNumber(moduleCounts[module], 2);
            }
        }
    );

    const statusElements = {
        crawler: elements.crawlerStatus,
        sqli: elements.sqliStatus,
        xss: elements.xssStatus,
        csrf: elements.csrfStatus,
        ports: elements.portsStatus
    };

    Object.entries(statusElements).forEach(
        ([module, element]) => {
            if (element) {
                element.textContent =
                    state.modules[module]
                        ? "Completed"
                        : "Disabled";
            }
        }
    );

    elements.moduleStatusCards.forEach(card => {
        card.classList.remove(
            "module-active",
            "module-error"
        );

        card.classList.add("module-completed");
    });
}

/* =========================================================
   SCAN STATISTICS
========================================================= */

function updateScanStats(scan) {
    const endpoints =
        scan.pages_scanned ??
        scan.visited_count ??
        scan.pages ??
        0;

    const requests =
        scan.requests_sent ??
        scan.request_count ??
        scan.total_requests ??
        null;

    if (elements.endpointCount) {
        elements.endpointCount.textContent =
            formatNumber(endpoints, 2);
    }

    if (elements.requestCount) {
        elements.requestCount.textContent =
            requests !== null
                ? formatNumber(requests, 3)
                : "--";
    }

    if (elements.telemetryEndpoints) {
        elements.telemetryEndpoints.textContent =
            formatNumber(endpoints, 2);
    }

    if (elements.telemetryRequests) {
        elements.telemetryRequests.textContent =
            requests !== null
                ? formatNumber(requests, 3)
                : "--";
    }
}

/* =========================================================
   TELEMETRY
========================================================= */

function updateTelemetry(data = {}) {
    const fields = {
        telemetryRequests: data.requests ?? "--",
        telemetryEndpoints: data.endpoints ?? 0,
        telemetryParameters: data.parameters ?? 0,
        telemetryPorts: data.ports ?? 0,
        telemetryErrors: data.errors ?? 0
    };

    Object.entries(fields).forEach(([key, value]) => {
        const element = elements[key];

        if (element) {
            element.textContent =
                typeof value === "number"
                    ? formatNumber(value, 3)
                    : String(value);
        }
    });
}

function updateTelemetryFromScan(scan) {
    const findings = Array.isArray(scan.findings)
        ? scan.findings
        : [];

    const endpoints =
        scan.pages_scanned ??
        scan.visited_count ??
        scan.pages ??
        0;

    const parameters = new Set(
        findings
            .map(finding =>
                finding.parameter ||
                finding.param ||
                finding.input
            )
            .filter(Boolean)
    ).size;

    const ports = Array.isArray(scan.ports)
        ? scan.ports.length
        : Array.isArray(scan.open_ports)
            ? scan.open_ports.length
            : 0;

    const requests =
        scan.requests_sent ??
        scan.request_count ??
        scan.total_requests ??
        null;

    updateTelemetry({
        requests,
        endpoints,
        parameters,
        ports,
        errors: scan.errors_count ?? scan.error_count ?? 0
    });
}

/* =========================================================
   SCAN TIMER
========================================================= */

function updateScanDuration() {
    if (!state.scanStartTime) {
        return;
    }

    const endTime =
        state.scanEndTime ??
        Date.now();

    const duration = Math.floor(
        (endTime - state.scanStartTime) / 1000
    );

    if (elements.scanTime) {
        elements.scanTime.textContent =
            formatDuration(duration);
    }
}

function formatDuration(seconds) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;

    return (
        String(minutes).padStart(2, "0") +
        ":" +
        String(remainingSeconds).padStart(2, "0")
    );
}

/* =========================================================
   PROGRESS BAR
========================================================= */

function updateProgress(
    percentage,
    message,
    module = "--"
) {
    const value = Math.max(
        0,
        Math.min(100, percentage)
    );

    if (elements.scanProgressValue) {
        elements.scanProgressValue.textContent =
            Math.round(value);
    }

    if (elements.scanProgressBar) {
        elements.scanProgressBar.style.width =
            `${value}%`;
    }

    if (elements.currentScanStage) {
        elements.currentScanStage.textContent = message;
    }

    if (elements.activeModule) {
        elements.activeModule.textContent = module;
    }

    if (elements.progressTarget) {
        elements.progressTarget.textContent =
            state.currentScan?.target ||
            elements.targetUrl?.value ||
            "--";
    }

    if (elements.scanEta) {
        elements.scanEta.textContent =
            value >= 100
                ? "00:00"
                : "--";
    }
}

/* =========================================================
   SCAN STATUS BADGE
========================================================= */

function updateScanStatus(status) {
    if (!elements.scanStatusBadge) {
        return;
    }

    elements.scanStatusBadge.textContent = status;

    elements.scanStatusBadge.className =
        "scan-status-badge";

    elements.scanStatusBadge.classList.add(
        status.toLowerCase()
    );
}

/* =========================================================
   CONSOLE LOGGER
========================================================= */

function addConsoleMessage(type, message) {
    const now = new Date();

    const time = now.toLocaleTimeString(
        "en-US",
        {
            hour12: false
        }
    );

    const entry = {
        time,
        type,
        message
    };

    state.consoleMessages.push(entry);

    if (!elements.consoleOutput) {
        console.log(`[${time}] [${type}] ${message}`);
        return;
    }

    const line = document.createElement("div");

    line.className =
        `console-line ${type.toLowerCase()}-line`;

    const timeElement = document.createElement("span");
    timeElement.className = "console-time";
    timeElement.textContent = `[${time}]`;

    const typeElement = document.createElement("span");
    typeElement.className = "console-type";
    typeElement.textContent = type;

    const messageElement = document.createElement("span");
    messageElement.className = "console-message";
    messageElement.textContent = message;

    line.appendChild(timeElement);
    line.appendChild(typeElement);
    line.appendChild(messageElement);

    elements.consoleOutput.appendChild(line);

    elements.consoleOutput.scrollTop =
        elements.consoleOutput.scrollHeight;
}

function clearConsole() {
    state.consoleMessages = [];

    if (elements.consoleOutput) {
        elements.consoleOutput.innerHTML = "";
    }

    addConsoleMessage(
        "SYSTEM",
        "Console cleared."
    );
}

/* =========================================================
   SCAN HISTORY
========================================================= */

async function loadScanHistory() {
    try {
        const response = await fetch(
            `${API_BASE_URL}/scans?limit=20`,
            {
                headers: {
                    Accept: "application/json"
                }
            }
        );

        if (!response.ok) {
            throw new Error(
                `Could not fetch scan history (HTTP ${response.status}).`
            );
        }

        const data = await response.json();

        state.scanHistory = Array.isArray(data.scans)
            ? data.scans
            : Array.isArray(data.history)
                ? data.history
                : [];

        addConsoleMessage(
            "INFO",
            `Scan history synchronized: ${state.scanHistory.length} record(s).`
        );
    } catch (error) {
        console.error("Scan history error:", error);

        addConsoleMessage(
            "WARNING",
            "Unable to synchronize scan history."
        );
    }
}

/* =========================================================
   REFRESH RESULTS
========================================================= */

async function refreshResults() {
    if (state.isScanning) {
        showNotification(
            "Wait until the current scan finishes.",
            "warning"
        );
        return;
    }

    addConsoleMessage(
        "INFO",
        "Refreshing dashboard data..."
    );

    await checkBackendHealth();
    await loadScanHistory();

    if (!state.currentScanId) {
        showNotification(
            "No scan results available yet.",
            "warning"
        );
        return;
    }

    try {
        const response = await fetch(
            `${API_BASE_URL}/scans/${encodeURIComponent(state.currentScanId)}`
        );

        if (!response.ok) {
            throw new Error(
                `Could not retrieve scan details (HTTP ${response.status}).`
            );
        }

        const data = await response.json();
        const scan = data.scan || data.result || data.data || data;

        if (data.success === false || !scan) {
            throw new Error(
                data.error ||
                "Backend returned unsuccessful scan details."
            );
        }

        state.currentScan = scan;

        state.findings = Array.isArray(scan.findings)
            ? scan.findings
            : Array.isArray(scan.vulnerabilities)
                ? scan.vulnerabilities
                : [];

        scan.findings = state.findings;

        renderScanResults(scan);

        addConsoleMessage(
            "SUCCESS",
            "Dashboard results refreshed."
        );

        showNotification(
            "Results refreshed.",
            "success"
        );
    } catch (error) {
        console.error("Refresh error:", error);

        addConsoleMessage(
            "ERROR",
            error.message || "Failed to refresh scan results."
        );

        showNotification(
            error.message || "Failed to refresh scan results.",
            "error"
        );
    }
}

/* =========================================================
   JSON REPORT EXPORT
========================================================= */

function exportJSONReport() {
    if (!state.currentScan) {
        showNotification(
            "Run a scan before exporting a report.",
            "warning"
        );
        return;
    }

    const report = {
        application: "WAVS",
        version: "1.0",
        generated_at: new Date().toISOString(),

        scan: state.currentScan,

        security_score: calculateSecurityScore(
            state.findings
        ),

        severity_counts: calculateSeverityCounts(
            state.findings
        ),

        findings: state.findings
    };

    const blob = new Blob(
        [
            JSON.stringify(
                report,
                null,
                4
            )
        ],
        {
            type: "application/json"
        }
    );

    const filename =
        `WAVS_report_${state.currentScanId || "latest"}.json`;

    downloadBlob(blob, filename);

    addConsoleMessage(
        "SUCCESS",
        "JSON report exported successfully."
    );

    showNotification(
        "JSON report downloaded.",
        "success"
    );
}

/* =========================================================
   HTML REPORT DOWNLOAD
========================================================= */

async function downloadHTMLReport() {
    if (!state.currentScanId) {
        showNotification(
            "Run a scan before generating a report.",
            "warning"
        );
        return;
    }

    try {
        const response = await fetch(
            `${API_BASE_URL}/scans/${encodeURIComponent(state.currentScanId)}/report`
        );

        if (!response.ok) {
            let message = "Could not generate HTML report.";

            try {
                const data = await response.json();
                message = data.error || message;
            } catch {
                // Response may not contain JSON.
            }

            throw new Error(message);
        }

        const blob = await response.blob();

        downloadBlob(
            blob,
            `WAVS_report_${state.currentScanId}.html`
        );

        addConsoleMessage(
            "SUCCESS",
            "HTML security report downloaded."
        );

        showNotification(
            "HTML report downloaded successfully.",
            "success"
        );
    } catch (error) {
        console.error("HTML report error:", error);

        showNotification(
            error.message || "Could not generate a report.",
            "error"
        );
    }
}

/* =========================================================
   PDF REPORT GENERATION
========================================================= */

function generatePDFReport() {
    if (!state.currentScan) {
        showNotification(
            "Run a scan before generating a PDF.",
            "warning"
        );
        return;
    }

    const printWindow = window.open("", "_blank");

    if (!printWindow) {
        showNotification(
            "Please allow pop-ups to generate the report.",
            "warning"
        );
        return;
    }

    printWindow.document.open();

    printWindow.document.write(
        generatePrintableReportHTML(state.currentScan)
    );

    printWindow.document.close();

    printWindow.onload = function () {
        printWindow.focus();
        printWindow.print();
    };

    addConsoleMessage(
        "SUCCESS",
        "Printable security report prepared."
    );

    showNotification(
        "Choose 'Save as PDF' in the print dialog.",
        "success"
    );
}

/* =========================================================
   PRINTABLE REPORT HTML
========================================================= */

function generatePrintableReportHTML(scan) {
    const findings = Array.isArray(scan.findings)
        ? scan.findings
        : [];

    const counts = calculateSeverityCounts(findings);
    const score = calculateSecurityScore(findings);

    const rows = findings.map(finding => {
        const severity = normalizeSeverity(
            getFindingSeverity(finding)
        );

        const module = normalizeModule(
            finding.module ||
            finding.type ||
            finding.category ||
            finding.scanner
        );

        return `
            <tr>
                <td class="${escapeHTML(severity)}">
                    ${escapeHTML(severity.toUpperCase())}
                </td>

                <td>${escapeHTML(getFindingTitle(finding))}</td>

                <td>
                    ${escapeHTML(
                        finding.url ||
                        finding.target ||
                        scan.target ||
                        "--"
                    )}
                </td>

                <td>${escapeHTML(module.toUpperCase())}</td>

                <td>${escapeHTML(finding.description || "--")}</td>

                <td>
                    ${escapeHTML(
                        finding.remediation ||
                        finding.recommendation ||
                        finding.solution ||
                        "--"
                    )}
                </td>
            </tr>
        `;
    }).join("");

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>WAVS Security Report</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, Helvetica, sans-serif;
            color: #172033;
            padding: 35px;
            background: #ffffff;
            line-height: 1.6;
        }

        header {
            border-bottom: 3px solid #4f8cff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 30px;
            margin-bottom: 5px;
        }

        h2 {
            margin-top: 30px;
            font-size: 20px;
        }

        .subtitle {
            color: #64748b;
            font-size: 13px;
        }

        .metadata {
            background: #f4f7fb;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
            overflow-wrap: anywhere;
        }

        .summary {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 25px;
        }

        .summary-item {
            padding: 15px;
            border: 1px solid #dce3ed;
            border-radius: 8px;
            min-width: 100px;
            flex: 1;
        }

        .summary-item strong {
            display: block;
            font-size: 23px;
        }

        .critical {
            color: #dc2626;
        }

        .high {
            color: #ea580c;
        }

        .medium {
            color: #ca8a04;
        }

        .low {
            color: #2563eb;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 12px;
            table-layout: fixed;
        }

        th {
            background: #172033;
            color: #ffffff;
            text-align: left;
        }

        th, td {
            border: 1px solid #dce3ed;
            padding: 10px;
            vertical-align: top;
            overflow-wrap: anywhere;
        }

        tr:nth-child(even) {
            background: #f8fafc;
        }

        footer {
            margin-top: 40px;
            padding-top: 15px;
            border-top: 1px solid #dce3ed;
            font-size: 11px;
            color: #64748b;
        }

        @media print {
            body {
                padding: 0;
            }

            button {
                display: none;
            }

            tr {
                page-break-inside: avoid;
            }
        }
    </style>
</head>

<body>
    <header>
        <h1>WAVS Security Assessment</h1>

        <div class="subtitle">
            Web Application Vulnerability Scanner | Version 1.0
        </div>
    </header>

    <div class="metadata">
        <strong>Target:</strong>
        ${escapeHTML(scan.target || "--")}
        <br>

        <strong>Scan ID:</strong>
        ${escapeHTML(String(scan.id ?? "--"))}
        <br>

        <strong>Generated:</strong>
        ${escapeHTML(new Date().toLocaleString())}
        <br>

        <strong>Pages Scanned:</strong>
        ${escapeHTML(String(scan.pages_scanned ?? 0))}
        <br>

        <strong>Forms Found:</strong>
        ${escapeHTML(String(scan.forms_found ?? 0))}
    </div>

    <h2>Executive Summary</h2>

    <div class="summary">
        <div class="summary-item">
            <span>Security Score</span>
            <strong>${score}/100</strong>
        </div>

        <div class="summary-item">
            <span>Total Findings</span>
            <strong>${findings.length}</strong>
        </div>

        <div class="summary-item critical">
            <span>Critical</span>
            <strong>${counts.critical}</strong>
        </div>

        <div class="summary-item high">
            <span>High</span>
            <strong>${counts.high}</strong>
        </div>

        <div class="summary-item medium">
            <span>Medium</span>
            <strong>${counts.medium}</strong>
        </div>

        <div class="summary-item low">
            <span>Low</span>
            <strong>${counts.low}</strong>
        </div>
    </div>

    <p>
        The WAVS security score is a heuristic assessment based on detected
        findings. It is not a CVSS score or a guarantee of security.
    </p>

    <h2>Vulnerability Findings</h2>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>Affected Target</th>
                <th>Module</th>
                <th>Description</th>
                <th>Remediation</th>
            </tr>
        </thead>

        <tbody>
            ${
                rows ||
                `
                    <tr>
                        <td colspan="6">No findings detected.</td>
                    </tr>
                `
            }
        </tbody>
    </table>

    <footer>
        Generated by WAVS — Web Application Vulnerability Scanner.
        <br>
        Intended for authorized security assessments and educational use.
    </footer>
</body>
</html>
`;
}

/* =========================================================
   DOWNLOAD HELPER
========================================================= */

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);

    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    setTimeout(() => {
        URL.revokeObjectURL(url);
    }, 1000);
}

/* =========================================================
   NOTIFICATIONS
========================================================= */

function showNotification(message, type = "info") {
    let container = document.getElementById(
        "notificationContainer"
    );

    if (!container) {
        container = document.createElement("div");
        container.id = "notificationContainer";
        container.className = "notification-container";

        document.body.appendChild(container);
    }

    const notification = document.createElement("div");

    notification.className =
        `notification notification-${type}`;

    notification.textContent = message;

    container.appendChild(notification);

    requestAnimationFrame(() => {
        notification.classList.add("notification-visible");
    });

    setTimeout(() => {
        notification.classList.remove("notification-visible");

        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3500);
}

/* =========================================================
   SETTINGS
========================================================= */

function showSettings() {
    showNotification(
        "WAVS Scanner v1.0 | Flask Backend | API Port 5000",
        "info"
    );
}

/* =========================================================
   NORMALIZE SEVERITY
========================================================= */

/**
 * Converts backend severity values to:
 * critical | high | medium | low | info
 *
 * Supports textual severities and numeric CVSS values.
 */
function normalizeSeverity(severity) {
    if (
        severity === null ||
        severity === undefined ||
        severity === ""
    ) {
        return "info";
    }

    const value = String(severity)
        .trim()
        .toLowerCase()
        .replace(/[_-]/g, " ")
        .replace(/\s+/g, " ");

    // Numeric CVSS-like severity.
    const numericValue = Number(value);

    if (value !== "" && Number.isFinite(numericValue)) {
        if (numericValue >= 9) return "critical";
        if (numericValue >= 7) return "high";
        if (numericValue >= 4) return "medium";
        if (numericValue > 0) return "low";

        return "info";
    }

    if (
        value.includes("critical") ||
        value.includes("severe") ||
        value.includes("very high")
    ) {
        return "critical";
    }

    if (
        value.includes("high") ||
        value.includes("major")
    ) {
        return "high";
    }

    if (
        value.includes("medium") ||
        value.includes("moderate") ||
        value.includes("warning")
    ) {
        return "medium";
    }

    if (
        value.includes("low") ||
        value.includes("minor")
    ) {
        return "low";
    }

    if (
        value.includes("info") ||
        value.includes("informational") ||
        value.includes("note") ||
        value.includes("unknown") ||
        value.includes("none")
    ) {
        return "info";
    }

    return "info";
}

/* =========================================================
   NORMALIZE MODULE
========================================================= */

function normalizeModule(module) {
    const value = String(module || "")
        .toLowerCase()
        .replace(/[_-]/g, " ");

    if (
        value.includes("sql") ||
        value.includes("sqli") ||
        value.includes("injection")
    ) {
        return "sqli";
    }

    if (
        value.includes("xss") ||
        value.includes("cross site")
    ) {
        return "xss";
    }

    if (
        value.includes("csrf") ||
        value.includes("forgery")
    ) {
        return "csrf";
    }

    if (
        value.includes("port") ||
        value.includes("network")
    ) {
        return "ports";
    }

    if (
        value.includes("crawl") ||
        value.includes("endpoint") ||
        value.includes("discovery")
    ) {
        return "crawler";
    }

    return "crawler";
}

/* =========================================================
   GET FINDING TITLE
========================================================= */

function getFindingTitle(finding = {}) {
    return (
        finding.title ||
        finding.name ||
        finding.vulnerability ||
        finding.issue ||
        finding.type ||
        "Security Finding"
    );
}

/* =========================================================
   FORMAT DATE
========================================================= */

function formatDate(value) {
    if (!value) {
        return "--";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

/* =========================================================
   FORMAT NUMBER
========================================================= */

function formatNumber(number, digits = 2) {
    if (
        number === null ||
        number === undefined ||
        number === "--"
    ) {
        return "--";
    }

    const numericValue = Number(number);

    if (!Number.isFinite(numericValue)) {
        return String(number);
    }

    return String(numericValue).padStart(digits, "0");
}

/* =========================================================
   TRUNCATE TEXT
========================================================= */

function truncateText(text, maxLength = 50) {
    const value = String(text || "");

    if (value.length <= maxLength) {
        return value;
    }

    return value.substring(0, maxLength) + "...";
}

/* =========================================================
   HTML ESCAPE
========================================================= */

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* =========================================================
   SLEEP UTILITY
========================================================= */

function sleep(milliseconds) {
    return new Promise(resolve => {
        setTimeout(resolve, milliseconds);
    });
}

/* =========================================================
   WAVS READY
========================================================= */

console.log(
    "%c WAVS — Web Application Vulnerability Scanner ",
    "background: #101827; color: #5fa8ff; font-size: 14px; font-weight: bold;"
);

console.log(
    "Dashboard JavaScript loaded successfully."
);
