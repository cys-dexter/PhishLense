document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const pasteBtn = document.getElementById("pasteBtn");
    const clearBtn = document.getElementById("clearBtn");
    const sampleContainer = document.getElementById("sampleContainer");
    const loadingState = document.getElementById("loadingState");
    const emptyState = document.getElementById("emptyState");
    const resultsSection = document.getElementById("resultsSection");
    const errorBanner = document.getElementById("errorBanner");
    const errorMessage = document.getElementById("errorMessage");

    fetchSampleUrls();

    analyzeBtn.addEventListener("click", () => {
        executeAnalysis();
    });

    urlInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            executeAnalysis();
        }
    });

    clearBtn.addEventListener("click", () => {
        urlInput.value = "";
        urlInput.focus();
        hideError();
    });

    pasteBtn.addEventListener("click", async () => {
        try {
            const clipboardText = await navigator.clipboard.readText();
            if (clipboardText) {
                urlInput.value = clipboardText.trim();
                hideError();
                executeAnalysis();
            }
        } catch {
            urlInput.focus();
        }
    });

    async function fetchSampleUrls() {
        try {
            const response = await fetch("/api/v1/samples");
            if (!response.ok) return;
            const samples = await response.json();
            renderSamplePills(samples);
        } catch {}
    }

    function renderSamplePills(samples) {
        if (!sampleContainer) return;
        sampleContainer.innerHTML = "";

        samples.forEach((sample) => {
            const pill = document.createElement("button");
            pill.type = "button";
            pill.className =
                "text-xs px-3 py-1.5 rounded-full font-medium transition-all duration-200 border flex items-center gap-1.5 " +
                getSampleBadgeClasses(sample.expected_risk);

            pill.innerHTML = `
                <span class="w-1.5 h-1.5 rounded-full ${getDotColor(sample.expected_risk)}"></span>
                <span>${escapeHtml(sample.label)}</span>
            `;

            pill.addEventListener("click", () => {
                urlInput.value = sample.url;
                hideError();
                executeAnalysis();
            });

            sampleContainer.appendChild(pill);
        });
    }

    function getSampleBadgeClasses(risk) {
        switch (risk) {
            case "DANGEROUS":
                return "bg-rose-950/40 text-rose-300 border-rose-800/60 hover:bg-rose-900/50 hover:border-rose-600";
            case "SUSPICIOUS":
                return "bg-amber-950/40 text-amber-300 border-amber-800/60 hover:bg-amber-900/50 hover:border-amber-600";
            case "LOW RISK":
                return "bg-blue-950/40 text-blue-300 border-blue-800/60 hover:bg-blue-900/50 hover:border-blue-600";
            default:
                return "bg-emerald-950/40 text-emerald-300 border-emerald-800/60 hover:bg-emerald-900/50 hover:border-emerald-600";
        }
    }

    function getDotColor(risk) {
        switch (risk) {
            case "DANGEROUS":
                return "bg-rose-500";
            case "SUSPICIOUS":
                return "bg-amber-500";
            case "LOW RISK":
                return "bg-blue-500";
            default:
                return "bg-emerald-500";
        }
    }

    async function executeAnalysis() {
        const rawUrl = urlInput.value.trim();
        if (!rawUrl) {
            showError("Please enter a valid URL or IP address to inspect.");
            return;
        }

        hideError();
        showLoading();

        try {
            const response = await fetch("/api/v1/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ url: rawUrl }),
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.detail || "URL inspection request failed.");
            }

            const analysis = await response.json();
            renderAnalysisResults(analysis);
        } catch (error) {
            hideLoading();
            showError(error.message || "Failed to communicate with analysis engine.");
        }
    }

    function showLoading() {
        emptyState.classList.add("hidden");
        resultsSection.classList.add("hidden");
        loadingState.classList.remove("hidden");
        analyzeBtn.disabled = true;
        analyzeBtn.classList.add("opacity-60", "cursor-not-allowed");
    }

    function hideLoading() {
        loadingState.classList.add("hidden");
        analyzeBtn.disabled = false;
        analyzeBtn.classList.remove("opacity-60", "cursor-not-allowed");
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorBanner.classList.remove("hidden");
    }

    function hideError() {
        errorBanner.classList.add("hidden");
        errorMessage.textContent = "";
    }

    function renderAnalysisResults(data) {
        hideLoading();
        emptyState.classList.add("hidden");
        resultsSection.classList.remove("hidden");

        renderVerdictHero(data);
        renderVisualDissection(data.components);
        renderSeverityCounters(data.severity_counts);
        renderFindingsList(data.findings);
        renderRecommendations(data.recommendations);

        resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function renderVerdictHero(data) {
        const scoreElem = document.getElementById("heroScore");
        const riskBadge = document.getElementById("heroRiskBadge");
        const summaryElem = document.getElementById("heroSummary");
        const analyzedUrlElem = document.getElementById("heroAnalyzedUrl");
        const heroCard = document.getElementById("verdictHeroCard");

        analyzedUrlElem.textContent = data.url;
        summaryElem.textContent = data.verdict_summary;

        animateScore(data.risk_score, scoreElem);

        riskBadge.textContent = data.risk_level;
        riskBadge.className = "px-4 py-1.5 rounded-full font-bold text-sm uppercase tracking-wider border flex items-center gap-2 " + getRiskBadgeClasses(data.risk_level);

        heroCard.className = "cyber-card p-6 md:p-8 rounded-2xl border transition-all duration-500 " + getHeroGlowClass(data.risk_level);
    }

    function animateScore(targetScore, element) {
        let current = 0;
        const duration = 650;
        const startTime = performance.now();

        function updateNumber(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            current = Math.floor(progress * targetScore);
            element.textContent = current;
            if (progress < 1) {
                requestAnimationFrame(updateNumber);
            } else {
                element.textContent = targetScore;
            }
        }

        requestAnimationFrame(updateNumber);
    }

    function getRiskBadgeClasses(riskLevel) {
        switch (riskLevel) {
            case "DANGEROUS":
                return "bg-rose-950/80 text-rose-300 border-rose-500 shadow-lg shadow-rose-950/50";
            case "SUSPICIOUS":
                return "bg-amber-950/80 text-amber-300 border-amber-500 shadow-lg shadow-amber-950/50";
            case "LOW RISK":
                return "bg-blue-950/80 text-blue-300 border-blue-500 shadow-lg shadow-blue-950/50";
            default:
                return "bg-emerald-950/80 text-emerald-300 border-emerald-500 shadow-lg shadow-emerald-950/50";
        }
    }

    function getHeroGlowClass(riskLevel) {
        switch (riskLevel) {
            case "DANGEROUS":
                return "glow-border-critical border-rose-800/80";
            case "SUSPICIOUS":
                return "glow-border-high border-amber-800/80";
            case "LOW RISK":
                return "glow-border-low border-blue-800/80";
            default:
                return "glow-border-safe border-emerald-800/80";
        }
    }

    function renderSeverityCounters(counts) {
        document.getElementById("countCritical").textContent = counts.critical;
        document.getElementById("countHigh").textContent = counts.high;
        document.getElementById("countMedium").textContent = counts.medium;
        document.getElementById("countLow").textContent = counts.low;
        document.getElementById("countInfo").textContent = counts.info;
    }

    function renderVisualDissection(c) {
        const visualBar = document.getElementById("visualTokenBar");
        visualBar.innerHTML = "";

        const tokens = [];

        if (c.scheme) {
            tokens.push({
                label: "Protocol",
                val: c.scheme + "://",
                color: "bg-cyan-950/60 text-cyan-400 border-cyan-800/70",
            });
        }

        if (c.subdomain) {
            tokens.push({
                label: "Subdomain",
                val: c.subdomain + ".",
                color: "bg-amber-950/60 text-amber-300 border-amber-800/70",
            });
        }

        tokens.push({
            label: c.is_ip_address ? "Raw IP Host" : "Domain",
            val: c.is_ip_address ? c.hostname : c.domain,
            color: c.is_ip_address
                ? "bg-rose-950/60 text-rose-300 border-rose-800/70"
                : "bg-indigo-950/60 text-indigo-300 border-indigo-800/70",
        });

        if (c.tld) {
            tokens.push({
                label: "TLD",
                val: "." + c.tld,
                color: "bg-purple-950/60 text-purple-300 border-purple-800/70",
            });
        }

        if (c.port) {
            tokens.push({
                label: "Port",
                val: ":" + c.port,
                color: "bg-red-950/60 text-red-300 border-red-800/70",
            });
        }

        if (c.path && c.path !== "/") {
            tokens.push({
                label: "Path",
                val: c.path,
                color: "bg-slate-800/60 text-slate-300 border-slate-700/70",
            });
        }

        if (c.query) {
            tokens.push({
                label: "Query",
                val: "?" + c.query,
                color: "bg-slate-800/40 text-slate-400 border-slate-700/50",
            });
        }

        tokens.forEach((t) => {
            const tokenEl = document.createElement("div");
            tokenEl.className = "flex flex-col items-center gap-1";
            tokenEl.innerHTML = `
                <span class="text-[10px] uppercase font-mono font-bold tracking-wider text-slate-400">${t.label}</span>
                <span class="px-2.5 py-1 rounded font-mono text-xs md:text-sm border break-all ${t.color}">${escapeHtml(t.val)}</span>
            `;
            visualBar.appendChild(tokenEl);
        });

        document.getElementById("gridScheme").textContent = c.scheme ? c.scheme.toUpperCase() : "N/A";
        document.getElementById("gridHost").textContent = c.hostname || "N/A";
        document.getElementById("gridSubdomain").textContent = c.subdomain || "None";
        document.getElementById("gridRegisteredDomain").textContent = c.registered_domain || "N/A";
        document.getElementById("gridTld").textContent = c.tld ? `.${c.tld}` : "None";
        document.getElementById("gridPort").textContent = c.port ? c.port : "Standard (80/443)";
        document.getElementById("gridPath").textContent = c.path || "/";
        document.getElementById("gridIsIp").textContent = c.is_ip_address ? "Yes (Raw IP Host)" : "No (Named Domain)";
    }

    function renderFindingsList(findings) {
        const container = document.getElementById("findingsContainer");
        container.innerHTML = "";

        if (!findings || findings.length === 0) {
            container.innerHTML = `
                <div class="p-6 rounded-xl border border-slate-800 bg-slate-900/40 text-center text-slate-400">
                    No security anomalies identified for this link.
                </div>
            `;
            return;
        }

        findings.forEach((finding) => {
            const card = document.createElement("div");
            card.className = "cyber-card p-5 rounded-xl border flex flex-col gap-3 transition-all " + getCardSeverityClasses(finding.severity);

            card.innerHTML = `
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <div class="flex items-center gap-2">
                        <span class="px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider border ${getSeverityPillClasses(finding.severity)}">
                            ${finding.severity}
                        </span>
                        <span class="text-xs font-mono text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                            ${escapeHtml(finding.category)}
                        </span>
                    </div>
                    <span class="text-xs font-mono font-semibold text-slate-300 bg-slate-900/90 px-2.5 py-0.5 rounded-full border border-slate-800">
                        +${finding.score_impact} Risk Score
                    </span>
                </div>

                <div>
                    <h4 class="text-base font-semibold text-white tracking-tight">${escapeHtml(finding.title)}</h4>
                    <p class="text-sm text-slate-300 mt-1 leading-relaxed">
                        ${escapeHtml(finding.plain_english_explanation)}
                    </p>
                </div>

                <div class="mt-1 pt-2.5 border-t border-slate-800/80 text-xs font-mono text-slate-400 bg-black/20 p-2.5 rounded-lg">
                    <span class="text-slate-500 uppercase font-sans text-[10px] tracking-wider font-semibold block mb-0.5">Technical Context</span>
                    ${escapeHtml(finding.technical_detail)}
                </div>
            `;

            container.appendChild(card);
        });
    }

    function getCardSeverityClasses(severity) {
        switch (severity) {
            case "CRITICAL":
                return "border-rose-900/60 bg-rose-950/10 hover:border-rose-600";
            case "HIGH":
                return "border-orange-900/60 bg-orange-950/10 hover:border-orange-600";
            case "MEDIUM":
                return "border-amber-900/60 bg-amber-950/10 hover:border-amber-600";
            case "LOW":
                return "border-blue-900/60 bg-blue-950/10 hover:border-blue-600";
            default:
                return "border-emerald-900/60 bg-emerald-950/10 hover:border-emerald-600";
        }
    }

    function getSeverityPillClasses(severity) {
        switch (severity) {
            case "CRITICAL":
                return "bg-rose-950/80 text-rose-300 border-rose-700";
            case "HIGH":
                return "bg-orange-950/80 text-orange-300 border-orange-700";
            case "MEDIUM":
                return "bg-amber-950/80 text-amber-300 border-amber-700";
            case "LOW":
                return "bg-blue-950/80 text-blue-300 border-blue-700";
            default:
                return "bg-emerald-950/80 text-emerald-300 border-emerald-700";
        }
    }

    function renderRecommendations(recommendations) {
        const list = document.getElementById("recommendationsList");
        list.innerHTML = "";

        recommendations.forEach((rec) => {
            const item = document.createElement("li");
            item.className = "flex items-start gap-3 text-sm text-slate-300";
            item.innerHTML = `
                <div class="w-5 h-5 rounded-full bg-cyan-950/80 border border-cyan-700/60 flex items-center justify-center shrink-0 mt-0.5 text-cyan-400">
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7" />
                    </svg>
                </div>
                <span>${escapeHtml(rec)}</span>
            `;
            list.appendChild(item);
        });
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});