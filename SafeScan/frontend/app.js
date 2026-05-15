/**
 * SafeScan Frontend Application
 *
 * Handles tab switching, URL/file submission, loading states,
 * result rendering with confidence ring animation, and collapsible sections.
 */

/* ============================================================
   DOM Element References
   ============================================================ */

const elements = {
    /* Tab navigation */
    tabNav: document.getElementById("tab-nav"),
    tabUrl: document.getElementById("tab-url"),
    tabFile: document.getElementById("tab-file"),
    panelUrl: document.getElementById("panel-url"),
    panelFile: document.getElementById("panel-file"),

    /* URL scan */
    urlInput: document.getElementById("url-input"),
    btnScanUrl: document.getElementById("btn-scan-url"),
    urlError: document.getElementById("url-error"),

    /* File scan */
    dropZone: document.getElementById("drop-zone"),
    fileInput: document.getElementById("file-input"),
    fileSelected: document.getElementById("file-selected"),
    fileName: document.getElementById("file-name"),
    fileSize: document.getElementById("file-size"),
    fileActions: document.getElementById("file-actions"),
    btnScanFile: document.getElementById("btn-scan-file"),
    fileError: document.getElementById("file-error"),

    /* Loading */
    loadingOverlay: document.getElementById("loading-overlay"),
    loadingText: document.getElementById("loading-text"),
    loadingStep: document.getElementById("loading-step"),

    /* Results */
    resultsPanel: document.getElementById("results-panel"),
    threatHeader: document.getElementById("threat-header"),
    confidenceRing: document.getElementById("confidence-ring"),
    ringFill: document.getElementById("ring-fill"),
    confidenceValue: document.getElementById("confidence-value"),
    threatLevelText: document.getElementById("threat-level-text"),
    threatSummary: document.getElementById("threat-summary"),
    humanReviewBanner: document.getElementById("human-review-banner"),
    whatItDoesList: document.getElementById("what-it-does-list"),
    whoTargetsText: document.getElementById("who-targets-text"),
    whatHappensText: document.getElementById("what-happens-text"),
    recommendationText: document.getElementById("recommendation-text"),
    technicalContent: document.getElementById("technical-content"),
    intelSources: document.getElementById("intel-sources"),
    logEntries: document.getElementById("log-entries"),
    btnScanAnother: document.getElementById("btn-scan-another"),
};


/* ============================================================
   Tab Switching
   ============================================================ */

function switchTab(tabName) {
    /* Update button states */
    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.tab === tabName);
    });

    /* Show the correct panel */
    elements.panelUrl.classList.toggle("active", tabName === "url");
    elements.panelFile.classList.toggle("active", tabName === "file");

    /* Clear errors when switching */
    hideAllErrors();
}

elements.tabNav.addEventListener("click", (event) => {
    const btn = event.target.closest(".tab-btn");
    if (btn) switchTab(btn.dataset.tab);
});


/* ============================================================
   URL Scanning
   ============================================================ */

elements.btnScanUrl.addEventListener("click", () => submitUrlScan());

elements.urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitUrlScan();
});

async function submitUrlScan() {
    const url = elements.urlInput.value.trim();

    if (!url) {
        showError(elements.urlError, "Please enter a URL to scan");
        return;
    }

    if (!isValidUrl(url)) {
        showError(elements.urlError, "Please enter a valid URL starting with http:// or https://");
        return;
    }

    hideAllErrors();
    showLoading("Analyzing URL...", "Fetching page metadata and checking threat databases");

    try {
        const response = await fetch("/api/scan/url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Server error: ${response.status}`);
        }

        const data = await response.json();
        hideLoading();
        renderResults(data);

    } catch (error) {
        hideLoading();
        showError(elements.urlError, error.message || "Scan failed — please try again");
    }
}

function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === "http:" || url.protocol === "https:";
    } catch {
        return false;
    }
}


/* ============================================================
   File Upload & Scanning
   ============================================================ */

let selectedFile = null;

/* Click to browse */
elements.dropZone.addEventListener("click", () => elements.fileInput.click());

/* Drag and drop */
elements.dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    elements.dropZone.classList.add("drag-over");
});

elements.dropZone.addEventListener("dragleave", () => {
    elements.dropZone.classList.remove("drag-over");
});

elements.dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    elements.dropZone.classList.remove("drag-over");
    if (event.dataTransfer.files.length > 0) {
        handleFileSelection(event.dataTransfer.files[0]);
    }
});

elements.fileInput.addEventListener("change", () => {
    if (elements.fileInput.files.length > 0) {
        handleFileSelection(elements.fileInput.files[0]);
    }
});

function handleFileSelection(file) {
    const maxSizeBytes = 10 * 1024 * 1024;

    if (file.size > maxSizeBytes) {
        showError(elements.fileError, "File exceeds maximum size of 10 MB");
        return;
    }

    selectedFile = file;
    elements.fileName.textContent = file.name;
    elements.fileSize.textContent = formatFileSize(file.size);
    elements.fileSelected.classList.add("show");
    elements.fileActions.classList.add("show");
    hideAllErrors();
}

elements.btnScanFile.addEventListener("click", () => submitFileScan());

async function submitFileScan() {
    if (!selectedFile) {
        showError(elements.fileError, "Please select a file to analyze");
        return;
    }

    hideAllErrors();
    showLoading("Analyzing file...", "Running static analysis and checking threat databases");

    try {
        const formData = new FormData();
        formData.append("file", selectedFile);

        const response = await fetch("/api/scan/file", {
            method: "POST",
            body: formData,
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `Server error: ${response.status}`);
        }

        const data = await response.json();
        hideLoading();
        renderResults(data);

    } catch (error) {
        hideLoading();
        showError(elements.fileError, error.message || "Scan failed — please try again");
    }
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}


/* ============================================================
   Loading State
   ============================================================ */

const LOADING_STEPS = [
    "Fetching page metadata and checking redirects",
    "Querying URLhaus threat database",
    "Scanning with VirusTotal multi-engine analysis",
    "Generating AI-powered plain-language explanation",
    "Calculating confidence score and finalizing report",
];

let loadingStepIndex = 0;
let loadingInterval = null;

function showLoading(title, subtitle) {
    elements.loadingText.textContent = title;
    elements.loadingStep.textContent = subtitle;
    elements.loadingOverlay.classList.add("active");
    elements.panelUrl.style.display = "none";
    elements.panelFile.style.display = "none";
    elements.resultsPanel.classList.remove("active");

    /* Cycle through loading steps to show progress */
    loadingStepIndex = 0;
    loadingInterval = setInterval(() => {
        loadingStepIndex = (loadingStepIndex + 1) % LOADING_STEPS.length;
        elements.loadingStep.textContent = LOADING_STEPS[loadingStepIndex];
    }, 2500);
}

function hideLoading() {
    elements.loadingOverlay.classList.remove("active");
    if (loadingInterval) {
        clearInterval(loadingInterval);
        loadingInterval = null;
    }
}


/* ============================================================
   Results Rendering
   ============================================================ */

function renderResults(data) {
    const level = data.threat_level || "suspicious";
    const confidence = data.confidence_percent || 0;

    /* --- Threat Header --- */
    elements.threatHeader.className = `threat-header ${level}`;
    elements.confidenceRing.className = `confidence-ring ${level}`;

    /* Animate confidence ring */
    const circumference = 188.5; // 2 * PI * 30
    const offset = circumference - (circumference * confidence) / 100;
    elements.ringFill.style.strokeDashoffset = circumference; // Start empty
    requestAnimationFrame(() => {
        elements.ringFill.style.strokeDashoffset = offset;
    });

    elements.confidenceValue.className = `confidence-value ${level}`;
    elements.confidenceValue.textContent = `${confidence}%`;

    /* Threat level text */
    const levelLabels = {
        safe: "✅ Safe",
        suspicious: "⚠️ Suspicious",
        dangerous: "🚨 Dangerous",
    };
    elements.threatLevelText.textContent = levelLabels[level] || level;
    elements.threatLevelText.className = level;

    elements.threatSummary.textContent = data.summary || "No summary available";

    /* --- Human Review Banner --- */
    elements.humanReviewBanner.classList.toggle("show", data.human_review_recommended === true);

    /* --- Explanation Sections --- */
    renderBulletList(elements.whatItDoesList, data.what_it_does || []);
    elements.whoTargetsText.textContent = data.who_it_targets || "Not determined";
    elements.whatHappensText.textContent = data.what_would_happen || "Not determined";
    elements.recommendationText.textContent = data.recommendation || "Exercise caution";

    /* --- Technical Details --- */
    elements.technicalContent.textContent = data.technical_details || "No additional technical details";

    /* --- Threat Intel Sources --- */
    renderIntelSources(data.threat_intel_results || []);

    /* --- AI Transparency Log --- */
    renderTransparencyLog(data.ai_transparency_log || []);

    /* Reset all collapsibles to closed */
    document.querySelectorAll(".collapsible-toggle").forEach((btn) => btn.classList.remove("open"));
    document.querySelectorAll(".collapsible-content").forEach((el) => el.classList.remove("open"));

    /* Show results panel */
    elements.resultsPanel.classList.add("active");
}

function renderBulletList(container, items) {
    container.innerHTML = "";
    if (items.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No specific behaviors identified";
        container.appendChild(li);
        return;
    }
    items.forEach((text) => {
        const li = document.createElement("li");
        li.textContent = text;
        container.appendChild(li);
    });
}

function renderIntelSources(sources) {
    elements.intelSources.innerHTML = "";
    sources.forEach((source) => {
        const card = document.createElement("div");
        card.className = "intel-card";

        let dotClass = "error";
        if (source.error) dotClass = "error";
        else if (source.is_known_threat) dotClass = "threat";
        else dotClass = "clean";

        let resultText = "";
        if (source.error) {
            resultText = source.error;
        } else if (source.is_known_threat) {
            resultText = formatIntelDetails(source.details);
        } else {
            resultText = "Not flagged — no known threats found";
        }

        card.innerHTML = `
            <div class="intel-dot ${dotClass}"></div>
            <span class="source-name">${escapeHtml(source.source)}</span>
            <span class="source-result">${escapeHtml(resultText)}</span>
        `;
        elements.intelSources.appendChild(card);
    });
}

function formatIntelDetails(details) {
    if (details.detection_ratio) {
        return `Detected by ${details.detection_ratio} engines`;
    }
    if (details.threat_type) {
        return `Threat: ${details.threat_type} (${details.url_status || "unknown status"})`;
    }
    return "Threat detected";
}

function renderTransparencyLog(logEntries) {
    elements.logEntries.innerHTML = "";
    logEntries.forEach((entry) => {
        const div = document.createElement("div");
        div.className = "log-entry";
        div.innerHTML = `
            <span class="log-step">${escapeHtml(entry.step)}</span>
            <span class="log-detail">${escapeHtml(entry.detail)}</span>
        `;
        elements.logEntries.appendChild(div);
    });
}


/* ============================================================
   Collapsible Sections
   ============================================================ */

document.querySelectorAll(".collapsible-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
        btn.classList.toggle("open");
        const content = btn.nextElementSibling;
        content.classList.toggle("open");
    });
});


/* ============================================================
   Scan Another
   ============================================================ */

elements.btnScanAnother.addEventListener("click", () => {
    /* Hide results, show input panels again */
    elements.resultsPanel.classList.remove("active");
    elements.panelUrl.style.display = "";
    elements.panelFile.style.display = "";

    /* Re-activate the correct panel */
    const activeTab = document.querySelector(".tab-btn.active");
    if (activeTab) switchTab(activeTab.dataset.tab);

    /* Reset file selection */
    selectedFile = null;
    elements.fileSelected.classList.remove("show");
    elements.fileActions.classList.remove("show");
    elements.fileInput.value = "";

    /* Clear URL input */
    elements.urlInput.value = "";

    /* Scroll to top */
    window.scrollTo({ top: 0, behavior: "smooth" });
});


/* ============================================================
   Utility Functions
   ============================================================ */

function showError(element, message) {
    element.textContent = message;
    element.classList.add("show");
}

function hideAllErrors() {
    elements.urlError.classList.remove("show");
    elements.fileError.classList.remove("show");
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
