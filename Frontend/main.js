"use strict";


/* ============================================================
   CONFIGURATION
   ============================================================ */

const API = {
    scan: "/scan",
    results: "/results",
    reportPdf: "/report/pdf"
};


/* ============================================================
   APPLICATION STATE
   ============================================================ */

const state = {

    scanning: false,

    scanStartedAt: null,

    scanTimer: null,

    progress: 0,

    target: "",

    profile: "full",

    modules: [
        "crawler",
        "sqli",
        "xss",
        "csrf",
        "ports"
    ],

    findings: [],

    filteredFindings: [],

    selectedFinding: null,

    lastResults: null

};


/* ============================================================
   DOM REFERENCES
   ============================================================ */

const elements = {

    targetUrl:
        document.getElementById("targetUrl"),

    startScanButton:
        document.getElementById("startScanButton"),

    stopScanButton:
        document.getElementById("stopScanButton"),

    refreshResultsButton:
        document.getElementById("refreshResultsButton"),

    clearConsoleButton:
        document.getElementById("clearConsoleButton"),

    jsonReportButton:
        document.getElementById("jsonReportButton"),

    pdfReportButton:
        document.getElementById("pdfReportButton"),

    scanTargetDisplay:
        document.getElementById("scanTargetDisplay"),

    scanStatusBadge:
        document.getElementById("scanStatusBadge"),

    scanProgressValue:
        document.getElementById("scanProgressValue"),

    scanProgressBar:
        document.getElementById("scanProgressBar"),

    currentScanStage:
        document.getElementById("currentScanStage"),

    progressTarget:
        document.getElementById("progressTarget"),

    activeModule:
        document.getElementById("activeModule"),

    scanEta:
        document.getElementById("scanEta"),

    securityScore:
        document.getElementById("securityScore"),

    scoreStatus:
        document.getElementById("scoreStatus"),

    securityScoreRing:
        document.getElementById("securityScoreRing"),

    criticalCount:
        document.getElementById("criticalCount"),

    highCount:
        document.getElementById("highCount"),

    mediumCount:
        document.getElementById("mediumCount"),

    lowCount:
        document.getElementById("lowCount"),

    endpointCount:
        document.getElementById("endpointCount"),

    requestCount:
        document.getElementById("requestCount"),

    findingCount:
        document.getElementById("findingCount"),

    scanTime:
        document.getElementById("scanTime"),

    consoleOutput:
        document.getElementById("consoleOutput"),

    findingsTableBody:
        document.getElementById("findingsTableBody"),

    severityFilter:
        document.getElementById("severityFilter"),

    moduleFilter:
        document.getElementById("moduleFilter"),

    findingDetails:
        document.getElementById("findingDetails"),

    closeFindingDetails:
        document.getElementById("closeFindingDetails"),

    detailSeverity:
        document.getElementById("detailSeverity"),

    detailTitle:
        document.getElementById("detailTitle"),

    detailUrl:
        document.getElementById("detailUrl"),

    detailModule:
        document.getElementById("detailModule"),

    detailParameter:
        document.getElementById("detailParameter"),

    detailDetected:
        document.getElementById("detailDetected"),

    detailDescription:
        document.getElementById("detailDescription"),

    detailImpact:
        document.getElementById("detailImpact"),

    detailEvidence:
        document.getElementById("detailEvidence"),

    detailRemediation:
        document.getElementById("detailRemediation"),

    telemetryRequests:
        document.getElementById("telemetryRequests"),

    telemetryEndpoints:
        document.getElementById("telemetryEndpoints"),

    telemetryParameters:
        document.getElementById("telemetryParameters"),

    telemetryPorts:
        document.getElementById("telemetryPorts"),

    telemetryErrors:
        document.getElementById("telemetryErrors")

};


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {

    initializeProfileSelector();

    initializeModules();

    initializeEventListeners();

    initializeDashboard();

    addConsoleMessage(
        "SYSTEM",
        "WAVS engine initialized. Awaiting target configuration."
    );

});


/* ============================================================
   EVENT LISTENERS
   ============================================================ */

function initializeEventListeners() {

    elements.startScanButton?.addEventListener(
        "click",
        startScan
    );


    elements.stopScanButton?.addEventListener(
        "click",
        stopScan
    );


    elements.refreshResultsButton?.addEventListener(
        "click",
        loadResults
    );


    elements.clearConsoleButton?.addEventListener(
        "click",
        clearConsole
    );


    elements.pdfReportButton?.addEventListener(
        "click",
        downloadPdfReport
    );


    elements.jsonReportButton?.addEventListener(
        "click",
        exportJsonReport
    );


    elements.severityFilter?.addEventListener(
        "change",
        applyFilters
    );


    elements.moduleFilter?.addEventListener(
        "change",
        applyFilters
    );


    elements.closeFindingDetails?.addEventListener(
        "click",
        closeFindingDetails
    );


    elements.targetUrl?.addEventListener(
        "input",
        updateTargetPreview
    );

}


/* ============================================================
   DASHBOARD INITIALIZATION
   ============================================================ */

function initializeDashboard() {

    updateScanStatus("IDLE");

    updateProgress(0);

    updateTargetPreview();

    updateStatistics({
        endpoints: 0,
        requests: 0,
        findings: 0
    });

    resetSeverityCounters();

}


/* ============================================================
   TARGET
   ============================================================ */

function updateTargetPreview() {

    const target =
        elements.targetUrl?.value.trim() || "";

    if (!target) {

        if (elements.scanTargetDisplay) {
            elements.scanTargetDisplay.textContent =
                "Awaiting target configuration...";
        }

        return;
    }

    if (elements.scanTargetDisplay) {
        elements.scanTargetDisplay.textContent = target;
    }

}


/* ============================================================
   PROFILE SELECTION
   ============================================================ */

function initializeProfileSelector() {

    const profileButtons =
        document.querySelectorAll(".profile-option");

    profileButtons.forEach(button => {

        button.addEventListener("click", () => {

            profileButtons.forEach(item => {
                item.classList.remove("active");
            });

            button.classList.add("active");

            state.profile =
                button.dataset.profile || "full";

            applyProfile(state.profile);

        });

    });

}


/* ============================================================
   APPLY SCAN PROFILE
   ============================================================ */

function applyProfile(profile) {

    const checkboxes =
        document.querySelectorAll(
            'input[name="module"]'
        );

    if (profile === "full") {

        checkboxes.forEach(checkbox => {
            checkbox.checked = true;
        });

        state.modules = [
            "crawler",
            "sqli",
            "xss",
            "csrf",
            "ports"
        ];

    }


    if (profile === "quick") {

        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
        });

        const quickModules = [
            "crawler",
            "sqli",
            "xss"
        ];

        quickModules.forEach(module => {

            const checkbox =
                document.querySelector(
                    `input[value="${module}"]`
                );

            if (checkbox) {
                checkbox.checked = true;
            }

        });

        state.modules = quickModules;

    }


    if (profile === "custom") {

        state.modules =
            getSelectedModules();

    }

}


/* ============================================================
   MODULE SELECTION
   ============================================================ */

function initializeModules() {

    const checkboxes =
        document.querySelectorAll(
            'input[name="module"]'
        );

    checkboxes.forEach(checkbox => {

        checkbox.addEventListener(
            "change",
            () => {

                state.modules =
                    getSelectedModules();

                updateCustomProfile();

            }
        );

    });

}


/* ============================================================
   GET SELECTED MODULES
   ============================================================ */

function getSelectedModules() {

    return Array.from(
        document.querySelectorAll(
            'input[name="module"]:checked'
        )
    ).map(
        checkbox => checkbox.value
    );

}


/* ============================================================
   UPDATE PROFILE TO CUSTOM
   ============================================================ */

function updateCustomProfile() {

    const profileButtons =
        document.querySelectorAll(".profile-option");

    const customButton =
        document.querySelector(
            '[data-profile="custom"]'
        );

    if (!customButton) {
        return;
    }

    profileButtons.forEach(button => {
        button.classList.remove("active");
    });

    customButton.classList.add("active");

    state.profile = "custom";

}


/* ============================================================
   START SCAN
   ============================================================ */

async function startScan() {

    if (state.scanning) {
        return;
    }


    const target =
        elements.targetUrl?.value.trim();


    if (!target) {

        showNotification(
            "Enter a target URL before starting the scan.",
            "warning"
        );

        elements.targetUrl?.focus();

        return;
    }


    if (!isValidUrl(target)) {

        showNotification(
            "Please enter a valid HTTP or HTTPS URL.",
            "warning"
        );

        elements.targetUrl?.focus();

        return;
    }


    state.modules =
        getSelectedModules();


    if (state.modules.length === 0) {

        showNotification(
            "Select at least one scanner module.",
            "warning"
        );

        return;
    }


    state.target = target;

    state.scanning = true;

    state.progress = 0;

    state.scanStartedAt =
        Date.now();


    setScanControls(true);

    updateTargetPreview();

    updateScanStatus("SCANNING");

    updateProgress(0);

    resetSeverityCounters();

    resetModuleStatuses();

    clearConsole();


    addConsoleMessage(
        "SYSTEM",
        `Starting scan against ${target}`
    );


    addConsoleMessage(
        "CONFIG",
        `Profile: ${state.profile.toUpperCase()}`
    );


    addConsoleMessage(
        "CONFIG",
        `Modules: ${state.modules.join(", ").toUpperCase()}`
    );


    startScanTimer();


    try {

        const response =
            await fetch(API.scan, {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    target: target,

                    url: target,

                    profile: state.profile,

                    modules: state.modules

                })

            });


        const data =
            await parseResponse(response);


        if (!response.ok) {

            throw new Error(
                data?.message ||
                data?.error ||
                `Scan request failed (${response.status})`
            );

        }


        addConsoleMessage(
            "SCAN",
            "Scan request accepted by backend."
        );


        handleScanResponse(data);


        /*
         * The current backend specification only exposes
         * /scan and /results. Therefore we poll /results
         * while the scan is active.
         */
        await monitorScan();


    } catch (error) {

        console.error(error);

        addConsoleMessage(
            "ERROR",
            error.message
        );

        updateScanStatus("ERROR");

        showNotification(
            error.message,
            "error"
        );

        state.scanning = false;

        stopScanTimer();

        setScanControls(false);

    }

}


/* ============================================================
   MONITOR SCAN
   ============================================================ */

async function monitorScan() {

    /*
     * Poll results while scanning.
     *
     * If your Flask backend later exposes:
     * GET /scan/status
     *
     * this function can be upgraded to use it directly.
     */

    const maxAttempts = 360;

    let attempts = 0;


    while (state.scanning && attempts < maxAttempts) {

        await sleep(2000);

        if (!state.scanning) {
            break;
        }

        attempts++;


        try {

            const response =
                await fetch(API.results, {
                    cache: "no-store"
                });


            const data =
                await parseResponse(response);


            if (!response.ok) {
                throw new Error(
                    data?.message ||
                    data?.error ||
                    "Unable to retrieve scan results."
                );
            }


            handleResultsResponse(data);


            /*
             * If the backend gives us an explicit scan status,
             * respect it.
             */

            const backendStatus =
                extractScanStatus(data);


            if (
                backendStatus === "completed" ||
                backendStatus === "complete" ||
                backendStatus === "finished" ||
                backendStatus === "done"
            ) {

                await finishScan();

                break;

            }


            if (
                backendStatus === "failed" ||
                backendStatus === "error"
            ) {

                throw new Error(
                    "Scanner reported an error."
                );

            }


            /*
             * If there is no explicit backend status,
             * keep the UI moving based on scan activity.
             */
            if (!backendStatus) {

                const calculatedProgress =
                    calculateProgress(
                        attempts,
                        data
                    );

                updateProgress(
                    calculatedProgress
                );

            }

        } catch (error) {

            console.error(
                "Result polling error:",
                error
            );

            /*
             * Don't immediately kill the scan because
             * one polling request failed.
             */
            addConsoleMessage(
                "WARNING",
                `Result polling failed: ${error.message}`
            );

        }

    }


    if (
        state.scanning &&
        attempts >= maxAttempts
    ) {

        addConsoleMessage(
            "WARNING",
            "Monitoring timeout reached."
        );

        await finishScan();

    }

}


/* ============================================================
   HANDLE /SCAN RESPONSE
   ============================================================ */

function handleScanResponse(data) {

    if (!data) {
        return;
    }


    /*
     * Some Flask APIs return:
     *
     * {
     *   status: "started",
     *   message: "...",
     *   scan_id: 123
     * }
     */

    const status =
        extractScanStatus(data);


    if (status) {

        updateBackendStatus(
            status
        );

    }


    if (data.message) {

        addConsoleMessage(
            "BACKEND",
            data.message
        );

    }


    if (data.scan_id) {

        addConsoleMessage(
            "SCAN",
            `Scan ID: ${data.scan_id}`
        );

    }

}


/* ============================================================
   HANDLE RESULTS
   ============================================================ */

function handleResultsResponse(data) {

    state.lastResults = data;


    const findings =
        normalizeFindings(data);


    if (findings.length > 0) {

        state.findings =
            findings;

        applyFilters();

        updateSeverityCounters();

        updateFindingStatistics();

    }


    updateStatistics(
        extractStatistics(data)
    );


    updateTelemetry(
        data
    );


    updateModuleStatuses(
        data,
        findings
    );


    updateSecurityScore(
        data,
        findings
    );


    updateProgressFromResults(
        data
    );

}


/* ============================================================
   LOAD RESULTS MANUALLY
   ============================================================ */

async function loadResults() {

    addConsoleMessage(
        "SYSTEM",
        "Refreshing scan results..."
    );


    try {

        const response =
            await fetch(API.results, {
                cache: "no-store"
            });


        const data =
            await parseResponse(response);


        if (!response.ok) {

            throw new Error(
                data?.message ||
                data?.error ||
                "Failed to load results."
            );

        }


        handleResultsResponse(data);


        addConsoleMessage(
            "RESULTS",
            "Results refreshed successfully."
        );


    } catch (error) {

        console.error(error);

        addConsoleMessage(
            "ERROR",
            error.message
        );

        showNotification(
            error.message,
            "error"
        );

    }

}


/* ============================================================
   FINISH SCAN
   ============================================================ */

async function finishScan() {

    if (!state.scanning) {
        return;
    }


    state.scanning = false;


    stopScanTimer();


    updateProgress(100);


    updateScanStatus("COMPLETE");


    setScanControls(false);


    addConsoleMessage(
        "SYSTEM",
        "Scan completed."
    );


    await loadResults();


    showNotification(
        "Scan completed successfully.",
        "success"
    );

}


/* ============================================================
   STOP SCAN
   ============================================================ */

function stopScan() {

    if (!state.scanning) {
        return;
    }


    state.scanning = false;


    stopScanTimer();


    updateScanStatus("STOPPED");


    setScanControls(false);


    addConsoleMessage(
        "SYSTEM",
        "Scan stopped by user."
    );


    showNotification(
        "Scan stopped.",
        "warning"
    );

}


/* ============================================================
   SCAN CONTROLS
   ============================================================ */

function setScanControls(scanning) {

    if (elements.startScanButton) {

        elements.startScanButton.disabled =
            scanning;

    }


    if (elements.stopScanButton) {

        elements.stopScanButton.disabled =
            !scanning;

    }


    if (elements.targetUrl) {

        elements.targetUrl.disabled =
            scanning;

    }

}


/* ============================================================
   SCAN STATUS
   ============================================================ */

function updateScanStatus(status) {

    if (!elements.scanStatusBadge) {
        return;
    }


    elements.scanStatusBadge.textContent =
        status.toUpperCase();


    elements.scanStatusBadge.dataset.status =
        status.toLowerCase();

}


/* ============================================================
   BACKEND STATUS
   ============================================================ */

function updateBackendStatus(status) {

    const normalized =
        String(status).toLowerCase();


    const statusMap = {

        queued: "QUEUED",

        pending: "QUEUED",

        started: "SCANNING",

        running: "SCANNING",

        scanning: "SCANNING",

        complete: "COMPLETE",

        completed: "COMPLETE",

        finished: "COMPLETE",

        done: "COMPLETE",

        failed: "ERROR",

        error: "ERROR"

    };


    updateScanStatus(
        statusMap[normalized] ||
        normalized.toUpperCase()
    );

}


/* ============================================================
   PROGRESS
   ============================================================ */

function updateProgress(value) {

    const progress =
        Math.max(
            0,
            Math.min(
                100,
                Number(value) || 0
            )
        );


    state.progress = progress;


    if (elements.scanProgressValue) {

        elements.scanProgressValue.textContent =
            Math.round(progress);

    }


    if (elements.scanProgressBar) {

        elements.scanProgressBar.style.width =
            `${progress}%`;

    }

}


/* ============================================================
   PROGRESS FROM RESULTS
   ============================================================ */

function updateProgressFromResults(data) {

    if (!data) {
        return;
    }


    const progress =
        data.progress ??
        data.percentage ??
        data.scan_progress ??
        data.percent;


    if (
        progress !== undefined &&
        progress !== null
    ) {

        updateProgress(progress);

    }


    if (data.current_stage) {

        elements.currentScanStage.textContent =
            data.current_stage;

    }


    if (data.stage) {

        elements.currentScanStage.textContent =
            data.stage;

    }


    if (data.current_module) {

        elements.activeModule.textContent =
            String(
                data.current_module
            ).toUpperCase();

    }

}


/* ============================================================
   CALCULATE FALLBACK PROGRESS
   ============================================================ */

function calculateProgress(
    attempts,
    data
) {

    const explicitProgress =
        data?.progress ??
        data?.percentage ??
        data?.scan_progress;


    if (
        explicitProgress !== undefined &&
        explicitProgress !== null
    ) {

        return Number(
            explicitProgress
        );

    }


    /*
     * Conservative fallback.
     * We don't want to pretend the scan is complete
     * when the backend hasn't told us that.
     */

    return Math.min(
        95,
        attempts * 2
    );

}


/* ============================================================
   SCAN TIMER
   ============================================================ */

function startScanTimer() {

    stopScanTimer();


    state.scanTimer =
        setInterval(
            updateScanTimer,
            1000
        );


    updateScanTimer();

}


function stopScanTimer() {

    if (state.scanTimer) {

        clearInterval(
            state.scanTimer
        );

        state.scanTimer = null;

    }

}


function updateScanTimer() {

    if (!state.scanStartedAt) {
        return;
    }


    const elapsed =
        Date.now() -
        state.scanStartedAt;


    elements.scanTime.textContent =
        formatDuration(elapsed);

}


/* ============================================================
   STATISTICS
   ============================================================ */

function updateStatistics(stats = {}) {

    const endpoints =
        Number(
            stats.endpoints ?? 0
        );


    const requests =
        Number(
            stats.requests ?? 0
        );


    const findings =
        Number(
            stats.findings ?? state.findings.length
        );


    elements.endpointCount.textContent =
        formatNumber(endpoints);


    elements.requestCount.textContent =
        formatNumber(requests);


    elements.findingCount.textContent =
        formatNumber(findings);


    elements.telemetryEndpoints.textContent =
        formatNumber(endpoints);


    elements.telemetryRequests.textContent =
        formatNumber(requests);

}


/* ============================================================
   FINDING STATISTICS
   ============================================================ */

function updateFindingStatistics() {

    const findings =
        state.findings || [];


    updateStatistics({

        endpoints:
            extractNumber(
                state.lastResults,
                [
                    "endpoints",
                    "endpoint_count",
                    "total_endpoints"
                ]
            ),

        requests:
            extractNumber(
                state.lastResults,
                [
                    "requests",
                    "request_count",
                    "total_requests"
                ]
            ),

        findings:
            findings.length

    });

}


/* ============================================================
   SEVERITY COUNTERS
   ============================================================ */

function resetSeverityCounters() {

    elements.criticalCount.textContent = "00";

    elements.highCount.textContent = "00";

    elements.mediumCount.textContent = "00";

    elements.lowCount.textContent = "00";

}


function updateSeverityCounters() {

    const counts = {

        critical: 0,

        high: 0,

        medium: 0,

        low: 0

    };


    state.findings.forEach(
        finding => {

            const severity =
                normalizeSeverity(
                    finding.severity
                );

            if (
                counts[severity] !== undefined
            ) {

                counts[severity]++;

            }

        }
    );


    elements.criticalCount.textContent =
        padNumber(counts.critical);


    elements.highCount.textContent =
        padNumber(counts.high);


    elements.mediumCount.textContent =
        padNumber(counts.medium);


    elements.lowCount.textContent =
        padNumber(counts.low);

}


/* ============================================================
   SECURITY SCORE
   ============================================================ */

function updateSecurityScore(
    data,
    findings
) {

    let score =
        data?.security_score ??
        data?.securityScore ??
        data?.score;


    if (
        score === undefined ||
        score === null
    ) {

        score =
            calculateSecurityScore(
                findings
            );

    }


    score =
        Math.max(
            0,
            Math.min(
                100,
                Number(score)
            )
        );


    elements.securityScore.textContent =
        Math.round(score);


    const status =
        getScoreStatus(score);


    elements.scoreStatus.textContent =
        status;


    if (elements.securityScoreRing) {

        elements.securityScoreRing.style
            .setProperty(
                "--score",
                `${score}`
            );

    }

}


/* ============================================================
   FALLBACK SECURITY SCORE
   ============================================================ */

function calculateSecurityScore(
    findings
) {

    let score = 100;


    const weights = {

        critical: 25,

        high: 15,

        medium: 8,

        low: 3

    };


    findings.forEach(
        finding => {

            const severity =
                normalizeSeverity(
                    finding.severity
                );


            score -=
                weights[severity] || 0;

        }
    );


    return Math.max(
        0,
        score
    );

}


/* ============================================================
   SCORE STATUS
   ============================================================ */

function getScoreStatus(score) {

    if (score >= 90) {
        return "EXCELLENT";
    }

    if (score >= 75) {
        return "GOOD";
    }

    if (score >= 50) {
        return "NEEDS REVIEW";
    }

    if (score >= 25) {
        return "AT RISK";
    }

    return "CRITICAL RISK";

}


/* ============================================================
   TELEMETRY
   ============================================================ */

function updateTelemetry(data) {

    if (!data) {
        return;
    }


    const telemetry =
        data.telemetry ||
        data.metrics ||
        data.statistics ||
        data.stats ||
        data;


    const parameters =
        telemetry.parameters ??
        telemetry.parameter_count ??
        telemetry.total_parameters ??
        0;


    const ports =
        telemetry.ports_checked ??
        telemetry.ports ??
        telemetry.total_ports ??
        0;


    const errors =
        telemetry.errors ??
        telemetry.response_errors ??
        telemetry.error_count ??
        0;


    elements.telemetryParameters.textContent =
        formatNumber(parameters);


    elements.telemetryPorts.textContent =
        formatNumber(ports);


    elements.telemetryErrors.textContent =
        formatNumber(errors);

}


/* ============================================================
   MODULE STATUS
   ============================================================ */

function resetModuleStatuses() {

    const modules = [
        "crawler",
        "sqli",
        "xss",
        "csrf",
        "ports"
    ];


    modules.forEach(module => {

        updateModuleStatus(
            module,
            "Waiting",
            "--"
        );

    });

}


/* ============================================================
   UPDATE MODULE STATUSES
   ============================================================ */

function updateModuleStatuses(
    data,
    findings
) {

    const moduleData =
        data?.modules ||
        data?.module_results ||
        data?.results ||
        {};


    const moduleNames = [
        "crawler",
        "sqli",
        "xss",
        "csrf",
        "ports"
    ];


    moduleNames.forEach(module => {

        const matchingFindings =
            findings.filter(
                finding =>
                    normalizeModule(
                        finding.module ||
                        finding.type ||
                        finding.scanner
                    ) === module
            );


        let moduleResult =
            moduleData[module];


        if (
            typeof moduleResult === "object" &&
            moduleResult !== null
        ) {

            const status =
                moduleResult.status ||
                "Complete";


            const count =
                moduleResult.count ??
                moduleResult.findings ??
                matchingFindings.length;


            updateModuleStatus(
                module,
                status,
                count
            );

            return;
        }


        if (matchingFindings.length > 0) {

            updateModuleStatus(
                module,
                "Findings detected",
                matchingFindings.length
            );

        } else if (
            state.scanning &&
            state.modules.includes(module)
        ) {

            updateModuleStatus(
                module,
                "Analyzed",
                0
            );

        }

    });

}


/* ============================================================
   UPDATE SINGLE MODULE
   ============================================================ */

function updateModuleStatus(
    module,
    status,
    count
) {

    const statusElement =
        document.getElementById(
            `${module}Status`
        );


    const countElement =
        document.getElementById(
            `${module}Count`
        );


    if (statusElement) {

        statusElement.textContent =
            formatModuleStatus(status);

    }


    if (countElement) {

        if (
            count === "--" ||
            count === undefined
        ) {

            countElement.textContent =
                "--";

        } else {

            countElement.textContent =
                padNumber(count);

        }

    }


    const card =
        document.querySelector(
            `[data-module="${module}"]`
        );


    if (card) {

        card.dataset.status =
            String(status)
                .toLowerCase()
                .replace(/\s+/g, "-");

    }

}


/* ============================================================
   FINDINGS NORMALIZATION
   ============================================================ */

function normalizeFindings(data) {

    if (!data) {
        return [];
    }


    let rawFindings = [];


    if (Array.isArray(data)) {

        rawFindings = data;

    } else if (Array.isArray(data.findings)) {

        rawFindings =
            data.findings;

    } else if (Array.isArray(data.vulnerabilities)) {

        rawFindings =
            data.vulnerabilities;

    } else if (Array.isArray(data.results)) {

        rawFindings =
            data.results;

    } else if (Array.isArray(data.data)) {

        rawFindings =
            data.data;

    }


    return rawFindings.map(
        normalizeFinding
    );

}


/* ============================================================
   NORMALIZE SINGLE FINDING
   ============================================================ */

function normalizeFinding(
    finding,
    index
) {

    const item =
        finding || {};


    return {

        id:
            item.id ??
            item.finding_id ??
            item.vulnerability_id ??
            index + 1,


        title:
            item.title ??
            item.name ??
            item.vulnerability ??
            item.type ??
            "Unknown Vulnerability",


        severity:
            normalizeSeverity(
                item.severity ??
                item.risk ??
                item.level ??
                "low"
            ),


        url:
            item.url ??
            item.target ??
            item.endpoint ??
            item.affected_url ??
            "--",


        module:
            normalizeModule(
                item.module ??
                item.scanner ??
                item.type ??
                ""
            ),


        parameter:
            item.parameter ??
            item.param ??
            item.parameter_name ??
            "--",


        detected:
            item.detected_at ??
            item.timestamp ??
            item.date ??
            item.detected ??
            "--",


        description:
            item.description ??
            item.details ??
            item.explanation ??
            "No description available.",


        impact:
            item.impact ??
            item.risk_description ??
            "Impact information unavailable.",


        evidence:
            item.evidence ??
            item.payload ??
            item.response ??
            item.proof ??
            "--",


        remediation:
            item.remediation ??
            item.recommendation ??
            item.fix ??
            "No remediation information available.",


        raw:
            item

    };

}


/* ============================================================
   FILTER FINDINGS
   ============================================================ */

function applyFilters() {

    const severity =
        elements.severityFilter?.value ||
        "all";


    const module =
        elements.moduleFilter?.value ||
        "all";


    state.filteredFindings =
        state.findings.filter(
            finding => {

                const severityMatch =
                    severity === "all" ||
                    normalizeSeverity(
                        finding.severity
                    ) === severity;


                const moduleMatch =
                    module === "all" ||
                    normalizeModule(
                        finding.module
                    ) === module;


                return (
                    severityMatch &&
                    moduleMatch
                );

            }
        );


    renderFindings(
        state.filteredFindings
    );

}


/* ============================================================
   RENDER FINDINGS
   ============================================================ */

function renderFindings(
    findings
) {

    if (!elements.findingsTableBody) {
        return;
    }


    if (
        !findings ||
        findings.length === 0
    ) {

        elements.findingsTableBody.innerHTML = `

            <tr class="empty-findings-row">

                <td colspan="6">

                    <div class="empty-state">

                        <span class="empty-icon">
                            ◇
                        </span>

                        <strong>
                            NO FINDINGS
                        </strong>

                        <span>
                            No vulnerabilities match
                            the current filters.
                        </span>

                    </div>

                </td>

            </tr>

        `;

        return;
    }


    elements.findingsTableBody.innerHTML =
        findings.map(
            createFindingRow
        ).join("");


    attachFindingRowListeners();

}


/* ============================================================
   CREATE FINDING ROW
   ============================================================ */

function createFindingRow(
    finding
) {

    const severity =
        normalizeSeverity(
            finding.severity
        );


    return `

        <tr
            class="finding-row"
            data-finding-id="${escapeHtml(
                finding.id
            )}"
        >

            <td>

                <span
                    class="severity-badge severity-${severity}"
                >
                    ${escapeHtml(
                        severity.toUpperCase()
                    )}
                </span>

            </td>


            <td>

                <div class="finding-name">

                    <strong>
                        ${escapeHtml(
                            finding.title
                        )}
                    </strong>

                </div>

            </td>


            <td>

                <code class="finding-url">
                    ${escapeHtml(
                        truncate(
                            finding.url,
                            55
                        )
                    )}
                </code>

            </td>


            <td>

                <span class="module-badge">
                    ${escapeHtml(
                        formatModule(
                            finding.module
                        )
                    )}
                </span>

            </td>


            <td>

                <span class="detected-time">
                    ${escapeHtml(
                        formatDate(
                            finding.detected
                        )
                    )}
                </span>

            </td>


            <td>

                <button
                    type="button"
                    class="finding-view-button"
                    data-finding-id="${escapeHtml(
                        finding.id
                    )}"
                >
                    VIEW
                </button>

            </td>

        </tr>

    `;

}


/* ============================================================
   FINDING ROW EVENTS
   ============================================================ */

function attachFindingRowListeners() {

    const buttons =
        document.querySelectorAll(
            ".finding-view-button"
        );


    buttons.forEach(button => {

        button.addEventListener(
            "click",
            event => {

                event.stopPropagation();

                const id =
                    button.dataset.findingId;

                openFindingDetails(id);

            }
        );

    });


    const rows =
        document.querySelectorAll(
            ".finding-row"
        );


    rows.forEach(row => {

        row.addEventListener(
            "click",
            () => {

                openFindingDetails(
                    row.dataset.findingId
                );

            }
        );

    });

}


/* ============================================================
   OPEN FINDING DETAILS
   ============================================================ */

function openFindingDetails(
    id
) {

    const finding =
        state.findings.find(
            item =>
                String(item.id) ===
                String(id)
        );


    if (!finding) {
        return;
    }


    state.selectedFinding =
        finding;


    elements.detailSeverity.textContent =
        finding.severity.toUpperCase();


    elements.detailSeverity.className =
        `severity-badge severity-${finding.severity}`;


    elements.detailTitle.textContent =
        finding.title;


    elements.detailUrl.textContent =
        finding.url;


    elements.detailModule.textContent =
        formatModule(
            finding.module
        );


    elements.detailParameter.textContent =
        finding.parameter;


    elements.detailDetected.textContent =
        formatDate(
            finding.detected
        );


    elements.detailDescription.textContent =
        finding.description;


    elements.detailImpact.textContent =
        finding.impact;


    elements.detailEvidence.textContent =
        formatEvidence(
            finding.evidence
        );


    elements.detailRemediation.textContent =
        finding.remediation;


    elements.findingDetails.classList.add(
        "visible"
    );


    elements.findingDetails.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });

}


/* ============================================================
   CLOSE FINDING DETAILS
   ============================================================ */

function closeFindingDetails() {

    elements.findingDetails.classList.remove(
        "visible"
    );

    state.selectedFinding = null;

}


/* ============================================================
   LIVE CONSOLE
   ============================================================ */

function addConsoleMessage(
    type,
    message
) {

    if (!elements.consoleOutput) {
        return;
    }


    const time =
        new Date().toLocaleTimeString(
            "en-GB",
            {
                hour12: false
            }
        );


    const line =
        document.createElement("div");


    line.className =
        "console-line";


    line.innerHTML = `

        <span class="console-time">
            [${time}]
        </span>

        <span class="console-type">
            ${escapeHtml(
                String(type).toUpperCase()
            )}
        </span>

        <span class="console-message">
            ${escapeHtml(message)}
        </span>

    `;


    elements.consoleOutput.appendChild(
        line
    );


    elements.consoleOutput.scrollTop =
        elements.consoleOutput.scrollHeight;

}


/* ============================================================
   CLEAR CONSOLE
   ============================================================ */

function clearConsole() {

    if (!elements.consoleOutput) {
        return;
    }


    elements.consoleOutput.innerHTML = "";


    addConsoleMessage(
        "SYSTEM",
        "Console cleared."
    );

}


/* ============================================================
   REPORT — PDF
   ============================================================ */

function downloadPdfReport() {

    addConsoleMessage(
        "REPORT",
        "Preparing PDF report..."
    );


    /*
     * Browser navigation lets Flask return the
     * generated PDF directly.
     */

    window.open(
        API.reportPdf,
        "_blank"
    );

}


/* ============================================================
   REPORT — JSON
   ============================================================ */

function exportJsonReport() {

    const data =
        state.lastResults ||
        {
            target: state.target,
            findings: state.findings
        };


    const json =
        JSON.stringify(
            data,
            null,
            2
        );


    const blob =
        new Blob(
            [json],
            {
                type:
                    "application/json"
            }
        );


    const url =
        URL.createObjectURL(
            blob
        );


    const link =
        document.createElement("a");


    link.href = url;


    link.download =
        `wavs-scan-${getTimestamp()}.json`;


    document.body.appendChild(
        link
    );


    link.click();


    link.remove();


    URL.revokeObjectURL(
        url
    );


    addConsoleMessage(
        "REPORT",
        "JSON report exported."
    );

}


/* ============================================================
   RESPONSE PARSER
   ============================================================ */

async function parseResponse(
    response
) {

    const contentType =
        response.headers.get(
            "content-type"
        ) || "";


    if (
        contentType.includes(
            "application/json"
        )
    ) {

        return await response.json();

    }


    const text =
        await response.text();


    try {

        return JSON.parse(text);

    } catch {

        return {
            message: text
        };

    }

}


/* ============================================================
   EXTRACT SCAN STATUS
   ============================================================ */

function extractScanStatus(
    data
) {

    if (!data) {
        return null;
    }


    return (
        data.status ??
        data.scan_status ??
        data.state ??
        data.scan?.status ??
        null
    );

}


/* ============================================================
   EXTRACT STATISTICS
   ============================================================ */

function extractStatistics(
    data
) {

    if (!data) {

        return {
            endpoints: 0,
            requests: 0,
            findings: state.findings.length
        };

    }


    const stats =
        data.statistics ||
        data.stats ||
        data.metrics ||
        data;


    return {

        endpoints:
            stats.endpoints ??
            stats.endpoint_count ??
            stats.total_endpoints ??
            0,


        requests:
            stats.requests ??
            stats.request_count ??
            stats.total_requests ??
            0,


        findings:
            stats.findings ??
            stats.finding_count ??
            stats.total_findings ??
            state.findings.length

    };

}


/* ============================================================
   EXTRACT NUMBER
   ============================================================ */

function extractNumber(
    object,
    keys
) {

    if (!object) {
        return 0;
    }


    for (const key of keys) {

        if (
            object[key] !== undefined &&
            object[key] !== null
        ) {

            const value =
                Number(
                    object[key]
                );


            if (!Number.isNaN(value)) {
                return value;
            }

        }

    }


    return 0;

}


/* ============================================================
   NORMALIZE SEVERITY
   ============================================================ */

function normalizeSeverity(
    severity
) {

    const value =
        String(
            severity || "low"
        )
        .trim()
        .toLowerCase();


    if (
        value.includes("critical")
    ) {
        return "critical";
    }


    if (
        value.includes("high")
    ) {
        return "high";
    }


    if (
        value.includes("medium") ||
        value.includes("moderate")
    ) {
        return "medium";
    }


    return "low";

}


/* ============================================================
   NORMALIZE MODULE
   ============================================================ */

function normalizeModule(
    module
) {

    const value =
        String(
            module || ""
        )
        .trim()
        .toLowerCase();


    if (
        value.includes("sql") ||
        value.includes("injection")
    ) {
        return "sqli";
    }


    if (
        value.includes("xss") ||
        value.includes("cross-site")
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
        value.includes("port")
    ) {
        return "ports";
    }


    if (
        value.includes("crawl")
    ) {
        return "crawler";
    }


    return value || "unknown";

}


/* ============================================================
   FORMAT MODULE
   ============================================================ */

function formatModule(
    module
) {

    const labels = {

        crawler: "CRAWLER",

        sqli: "SQLi",

        xss: "XSS",

        csrf: "CSRF",

        ports: "PORT SCAN",

        unknown: "UNKNOWN"

    };


    return (
        labels[
            normalizeModule(module)
        ] ||
        String(module || "UNKNOWN")
            .toUpperCase()
    );

}


/* ============================================================
   FORMAT MODULE STATUS
   ============================================================ */

function formatModuleStatus(
    status
) {

    if (!status) {
        return "Waiting";
    }


    return String(status)
        .replaceAll("_", " ")
        .replace(/\b\w/g, char =>
            char.toUpperCase()
        );

}


/* ============================================================
   FORMAT EVIDENCE
   ============================================================ */

function formatEvidence(
    evidence
) {

    if (
        typeof evidence === "string"
    ) {

        return evidence;

    }


    try {

        return JSON.stringify(
            evidence,
            null,
            2
        );

    } catch {

        return String(
            evidence
        );

    }

}


/* ============================================================
   FORMAT DATE
   ============================================================ */

function formatDate(
    value
) {

    if (
        !value ||
        value === "--"
    ) {

        return "--";

    }


    const date =
        new Date(value);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return String(value);

    }


    return date.toLocaleString(
        "en-GB",
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );

}


/* ============================================================
   FORMAT DURATION
   ============================================================ */

function formatDuration(
    milliseconds
) {

    const totalSeconds =
        Math.floor(
            milliseconds / 1000
        );


    const hours =
        Math.floor(
            totalSeconds / 3600
        );


    const minutes =
        Math.floor(
            (totalSeconds % 3600) / 60
        );


    const seconds =
        totalSeconds % 60;


    if (hours > 0) {

        return [
            padNumber(hours),
            padNumber(minutes),
            padNumber(seconds)
        ].join(":");

    }


    return [
        padNumber(minutes),
        padNumber(seconds)
    ].join(":");

}


/* ============================================================
   FORMAT NUMBER
   ============================================================ */

function formatNumber(
    number
) {

    return Number(
        number || 0
    ).toLocaleString(
        "en-US"
    );

}


/* ============================================================
   PAD NUMBER
   ============================================================ */

function padNumber(
    number
) {

    return String(
        number ?? 0
    ).padStart(
        2,
        "0"
    );

}


/* ============================================================
   TIMESTAMP
   ============================================================ */

function getTimestamp() {

    const now =
        new Date();


    return now
        .toISOString()
        .replace(
            /[:.]/g,
            "-"
        );

}


/* ============================================================
   URL VALIDATION
   ============================================================ */

function isValidUrl(
    value
) {

    try {

        const url =
            new URL(value);


        return (
            url.protocol === "http:" ||
            url.protocol === "https:"
        );

    } catch {

        return false;

    }

}


/* ============================================================
   TRUNCATE
   ============================================================ */

function truncate(
    value,
    length
) {

    const string =
        String(
            value ?? ""
        );


    if (
        string.length <= length
    ) {

        return string;

    }


    return (
        string.slice(
            0,
            length - 3
        ) +
        "..."
    );

}


/* ============================================================
   ESCAPE HTML
   ============================================================ */

function escapeHtml(
    value
) {

    return String(
        value ?? ""
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /'/g,
        "&#039;"
    );

}


/* ============================================================
   NOTIFICATION
   ============================================================ */

function showNotification(
    message,
    type = "info"
) {

    /*
     * Uses an existing notification system if your CSS later
     * defines one. Otherwise this falls back to a browser alert.
     */

    let container =
        document.querySelector(
            ".notification-container"
        );


    if (!container) {

        container =
            document.createElement(
                "div"
            );

        container.className =
            "notification-container";

        document.body.appendChild(
            container
        );

    }


    const notification =
        document.createElement(
            "div"
        );


    notification.className =
        `notification notification-${type}`;


    notification.innerHTML = `

        <span class="notification-icon">
            ${getNotificationIcon(type)}
        </span>

        <span class="notification-message">
            ${escapeHtml(message)}
        </span>

    `;


    container.appendChild(
        notification
    );


    requestAnimationFrame(() => {

        notification.classList.add(
            "visible"
        );

    });


    setTimeout(() => {

        notification.classList.remove(
            "visible"
        );


        setTimeout(() => {

            notification.remove();

        }, 300);

    }, 4000);

}


/* ============================================================
   NOTIFICATION ICON
   ============================================================ */

function getNotificationIcon(
    type
) {

    const icons = {

        success: "✓",

        warning: "!",

        error: "×",

        info: "i"

    };


    return icons[type] || "i";

}


/* ============================================================
   SLEEP
   ============================================================ */

function sleep(
    milliseconds
) {

    return new Promise(
        resolve =>
            setTimeout(
                resolve,
                milliseconds
            )
    );

}


/* ============================================================
   GLOBAL KEYBOARD SHORTCUTS
   ============================================================ */

document.addEventListener(
    "keydown",
    event => {

        /*
         * Ctrl/Cmd + Enter
         * Start scan
         */

        if (
            (event.ctrlKey ||
             event.metaKey) &&
            event.key === "Enter"
        ) {

            event.preventDefault();

            if (!state.scanning) {
                startScan();
            }

        }


        /*
         * Escape
         * Close finding details
         */

        if (
            event.key === "Escape"
        ) {

            closeFindingDetails();

        }

    }
);


/* ============================================================
   EXPORT STATE FOR DEBUGGING
   ============================================================ */

window.WAVS = {

    state,

    API,

    startScan,

    stopScan,

    loadResults,

    openFindingDetails

};

