/**
 * AutoScan — orchestrates automated crawl → inject → upload → AI analysis → targeted re-test pipeline
 */
window.AutoScan = (() => {
    const API = 'http://127.0.0.1:8000/api';

    const PHASES = ['crawl', 'inject', 'upload', 'ai', 'targeted'];
    const PHASE_LABELS = {
        crawl: 'Crawling',
        inject: 'Injection Testing',
        upload: 'Upload Scanning',
        ai: 'AI Analysis',
        targeted: 'Targeted Re-test',
    };

    const PHASE_BADGE_COLORS = {
        crawl: '#4a9eff',
        inject: '#ff9f43',
        upload: '#feca57',
        ai: '#a29bfe',
        targeted: '#ff6b6b',
        pipeline: '#8b949e',
    };

    const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const RISK_COLORS = {
        critical: '#ff4444',
        high: 'var(--danger)',
        medium: 'var(--warning)',
        low: 'var(--success)',
        info: 'var(--accent)',
    };

    // DOM refs
    let targetUrlEl, maxConcurrentEl, delayEl, maxDepthEl, maxPagesEl;
    let enableUploadEl, enableAiEl, enableRetestEl, aiModelEl;
    let startBtn, pauseBtn, stopBtn;
    let progressPanel, phaseTextEl;
    let endpointsCounter, vulnsCounter, requestsCounter;
    let resultsContainer, placeholderEl;
    let authContextEl, authSourceEl, clearAuthBtn;

    // Phase DOM elements (keyed by phase name)
    let phaseEls = {};
    let resultSections = {};
    let resultBodies = {};
    let resultCounts = {};

    // State
    let pollTimer = null;
    let _authHeaders = null;   // stored auth headers from a logged request
    let _authSourceLabel = ''; // display label for the auth source

    // Live feed state
    let lastEventId = 0;
    let eventPollTimer = null;
    let feedCollapsed = false;
    let userScrolledUp = false;

    // ── Helpers ──────────────────────────────────────────────────────

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function _fmtTime(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
                   d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch (_) { return ''; }
    }

    function _findingsTableHead() {
        return `<table class="findings-table"><thead><tr>
<th class="col-risk">Risk</th>
<th class="col-method">Method</th>
<th class="col-path">Path</th>
<th class="col-title">Title</th>
<th class="col-category">Category</th>
</tr></thead><tbody>`;
    }

    function _findingsTableFoot() {
        return `</tbody></table>`;
    }

    function _renderFindingRow(f) {
        const risk = (f.risk || 'info').toLowerCase();
        const details = [];
        if (f.description) details.push({ label: 'Description', text: f.description });
        if (f.evidence)    details.push({ label: 'Evidence', text: f.evidence });
        if (f.recommendation) details.push({ label: 'Recommendation', text: f.recommendation });

        return `<tr class="finding-row" data-risk="${risk}">
<td><span class="finding-expand-icon">&#9654;</span><span class="risk-pill risk-pill-${risk}">${(f.risk || 'INFO').toUpperCase()}</span></td>
<td class="finding-method">${esc(f.method || '')}</td>
<td class="finding-path" title="${esc(f.path || f.endpoint || '')}">${esc(f.path || f.endpoint || '')}</td>
<td class="finding-title-cell" title="${esc(f.title || '')}">${esc(f.title || '')}</td>
<td class="finding-category-cell">${esc(f.category || '')}</td>
</tr>
<tr class="finding-detail-row"><td colspan="5"><div class="finding-detail-content">${details.map(d =>
    `<div class="finding-detail-section"><span class="finding-detail-label">${d.label}</span><span class="finding-detail-text">${esc(d.text)}</span></div>`
).join('')}</div></td></tr>`;
    }

    function _renderPhase(name, status, detail) {
        const el = phaseEls[name];
        if (!el) return;

        // Remove all state classes
        el.classList.remove('phase-active', 'phase-complete', 'phase-skipped');

        const statusSpan = el.querySelector('.autoscan-phase-status');

        if (status === 'complete') {
            el.classList.add('phase-complete');
            if (statusSpan) statusSpan.innerHTML = '&#10003;';
        } else if (status === 'active') {
            el.classList.add('phase-active');
            if (statusSpan) statusSpan.innerHTML = `<span class="ai-progress-dot"></span>`;
        } else if (status === 'skipped') {
            el.classList.add('phase-skipped');
            if (statusSpan) statusSpan.textContent = 'skipped';
        } else {
            // pending
            if (statusSpan) statusSpan.textContent = '';
        }

        if (detail && statusSpan && status === 'active') {
            statusSpan.innerHTML += ` <span style="font-size:10px;color:var(--text-dim)">${esc(detail)}</span>`;
        }
    }

    // ── Init ─────────────────────────────────────────────────────────

    function init() {
        // Config inputs
        targetUrlEl     = document.getElementById('autoscan-target-url');
        maxConcurrentEl = document.getElementById('autoscan-max-concurrent');
        delayEl         = document.getElementById('autoscan-delay');
        maxDepthEl      = document.getElementById('autoscan-max-depth');
        maxPagesEl      = document.getElementById('autoscan-max-pages');
        enableUploadEl  = document.getElementById('autoscan-enable-upload');
        enableAiEl      = document.getElementById('autoscan-enable-ai');
        enableRetestEl  = document.getElementById('autoscan-enable-retest');
        aiModelEl       = document.getElementById('autoscan-ai-model');

        // Buttons
        startBtn = document.getElementById('btn-autoscan-start');
        pauseBtn = document.getElementById('btn-autoscan-pause');
        stopBtn  = document.getElementById('btn-autoscan-stop');

        // Progress
        progressPanel   = document.getElementById('autoscan-progress');
        phaseTextEl     = document.getElementById('autoscan-phase-text');
        endpointsCounter = document.getElementById('autoscan-endpoints-found');
        vulnsCounter     = document.getElementById('autoscan-vulns-found');
        requestsCounter  = document.getElementById('autoscan-requests-sent');

        // Results
        resultsContainer = document.getElementById('autoscan-results');
        placeholderEl    = resultsContainer ? resultsContainer.querySelector('.autoscan-placeholder') : null;

        // Phase pipeline elements
        PHASES.forEach(p => {
            phaseEls[p] = document.querySelector(`.autoscan-phase[data-phase="${p}"]`);
            resultSections[p] = document.querySelector(`.autoscan-result-section[data-result-phase="${p}"]`);
            resultBodies[p]   = document.getElementById(`autoscan-${p === 'targeted' ? 'targeted' : p}-results`);
            resultCounts[p]   = document.getElementById(`autoscan-${p === 'targeted' ? 'targeted' : p}-count`);
        });

        // Auth context
        authContextEl = document.getElementById('autoscan-auth-context');
        authSourceEl  = document.getElementById('autoscan-auth-source');
        clearAuthBtn  = document.getElementById('btn-autoscan-clear-auth');

        // Live feed
        _initFeed();

        // Event listeners
        if (startBtn) startBtn.addEventListener('click', _startScan);
        if (pauseBtn) pauseBtn.addEventListener('click', _pauseScan);
        if (stopBtn)  stopBtn.addEventListener('click', _stopScan);
        if (clearAuthBtn) clearAuthBtn.addEventListener('click', _clearAuth);

        // Register as SendTo target.
        // Auto Scan lives as a subtab inside the "ai" tab, so use tab:'ai'
        // override so _switchTab activates the parent tab correctly.
        SendTo.register('autoscan', {
            label: 'Auto Scan (Auth)',
            tab: 'ai',
            receive(data) {
                receiveAuthContext(data);
                // Switch to the autoscan subtab within the AI tab
                document.querySelectorAll('.ai-subtab').forEach(b =>
                    b.classList.toggle('active', b.dataset.subtab === 'autoscan'));
                document.querySelectorAll('.ai-subtab-pane').forEach(p =>
                    p.classList.toggle('active', p.dataset.subtab === 'autoscan'));
            },
        });

        // Sub-tab switching
        document.querySelectorAll('.ai-subtab').forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.dataset.subtab;
                document.querySelectorAll('.ai-subtab').forEach(b => b.classList.toggle('active', b === btn));
                document.querySelectorAll('.ai-subtab-pane').forEach(p => p.classList.toggle('active', p.dataset.subtab === target));
            });
        });

        // Collapsible result section headers
        if (resultsContainer) {
            resultsContainer.addEventListener('click', (e) => {
                const header = e.target.closest('.autoscan-result-header');
                if (!header) return;
                const collapsed = header.dataset.collapsed === 'true';
                header.dataset.collapsed = collapsed ? 'false' : 'true';
                const body = header.nextElementSibling;
                if (body) body.style.display = collapsed ? '' : 'none';
                const toggle = header.querySelector('.autoscan-result-toggle');
                if (toggle) toggle.textContent = collapsed ? '\u25BC' : '\u25B6';
            });
        }
    }

    // ── Live Activity Feed ──────────────────────────────────────────────

    function _initFeed() {
        const feedEl = document.getElementById('auto-scan-live-feed');
        const toggleBtn = document.getElementById('btn-autoscan-feed-toggle');
        const autoscrollChk = document.getElementById('autoscan-feed-autoscroll');

        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                feedCollapsed = !feedCollapsed;
                if (feedEl) feedEl.style.maxHeight = feedCollapsed ? '0' : '';
                if (feedEl) feedEl.style.overflow = feedCollapsed ? 'hidden' : '';
                toggleBtn.innerHTML = feedCollapsed ? '&#9654;' : '&#9660;';
            });
        }

        if (feedEl) {
            feedEl.addEventListener('scroll', () => {
                const threshold = 30;
                userScrolledUp = (feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight) > threshold;
            });
        }

        if (autoscrollChk) {
            autoscrollChk.addEventListener('change', () => {
                if (autoscrollChk.checked) {
                    userScrolledUp = false;
                    _scrollFeedToBottom();
                }
            });
        }
    }

    function _startEventPolling() {
        _stopEventPolling();
        eventPollTimer = setInterval(_pollEvents, 1000);
    }

    function _stopEventPolling() {
        if (eventPollTimer) { clearInterval(eventPollTimer); eventPollTimer = null; }
    }

    function _clearFeed() {
        lastEventId = 0;
        userScrolledUp = false;
        const feedEl = document.getElementById('auto-scan-live-feed');
        if (feedEl) feedEl.innerHTML = '';
        const countEl = document.getElementById('autoscan-feed-count');
        if (countEl) countEl.textContent = '0 events';
    }

    async function _pollEvents() {
        try {
            const res = await fetch(`${API}/auto-scan/events?since_id=${lastEventId}`);
            const data = await res.json();
            if (!data.events || !data.events.length) return;

            const feedEl = document.getElementById('auto-scan-live-feed');
            if (!feedEl) return;

            const autoscrollChk = document.getElementById('autoscan-feed-autoscroll');
            const shouldAutoScroll = autoscrollChk ? autoscrollChk.checked && !userScrolledUp : !userScrolledUp;

            for (const evt of data.events) {
                feedEl.appendChild(_renderEvent(evt));
            }

            lastEventId = data.last_id;

            const countEl = document.getElementById('autoscan-feed-count');
            if (countEl) countEl.textContent = `${feedEl.children.length} events`;

            if (shouldAutoScroll) _scrollFeedToBottom();
        } catch (_) {}
    }

    function _renderEvent(evt) {
        const div = document.createElement('div');
        div.className = 'auto-scan-event';

        // Timestamp
        const timeStr = _fmtEventTime(evt.timestamp);
        const timeSpan = `<span class="auto-scan-event-time">${esc(timeStr)}</span>`;

        // Phase badge
        const phase = evt.phase || 'pipeline';
        const color = PHASE_BADGE_COLORS[phase] || PHASE_BADGE_COLORS.pipeline;
        const badgeSpan = `<span class="auto-scan-event-phase" style="background:${color}">${esc(phase)}</span>`;

        // Message
        const msgSpan = `<span class="auto-scan-event-message">${esc(evt.message || '')}</span>`;

        div.innerHTML = timeSpan + badgeSpan + msgSpan;

        // Detail (expandable)
        if (evt.detail) {
            const detailDiv = document.createElement('div');
            detailDiv.className = 'auto-scan-event-detail';
            detailDiv.textContent = evt.detail;
            div.appendChild(detailDiv);
            div.style.cursor = 'pointer';
            div.addEventListener('click', () => {
                detailDiv.classList.toggle('expanded');
            });
        }

        return div;
    }

    function _fmtEventTime(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            const h = String(d.getHours()).padStart(2, '0');
            const m = String(d.getMinutes()).padStart(2, '0');
            const s = String(d.getSeconds()).padStart(2, '0');
            return `${h}:${m}:${s}`;
        } catch (_) { return ''; }
    }

    function _scrollFeedToBottom() {
        const feedEl = document.getElementById('auto-scan-live-feed');
        if (feedEl) feedEl.scrollTop = feedEl.scrollHeight;
    }

    function _showFeedSection(show) {
        const section = document.getElementById('autoscan-feed-section');
        if (section) section.classList.toggle('hidden', !show);
    }

    // ── Auth Context ──────────────────────────────────────────────────

    function receiveAuthContext(data) {
        // Extract headers from the request data
        let headers = data.headers || data.request_headers || {};
        if (typeof headers === 'string') {
            try { headers = JSON.parse(headers); } catch (_) { headers = {}; }
        }

        // Filter to auth-relevant headers
        const authKeys = ['authorization', 'cookie', 'x-csrf-token', 'x-xsrf-token', 'x-api-key'];
        const filtered = {};
        for (const [k, v] of Object.entries(headers)) {
            if (authKeys.includes(k.toLowerCase())) {
                filtered[k] = v;
            }
        }

        // Store all headers (the backend may need non-auth ones too like session cookies)
        _authHeaders = Object.keys(filtered).length ? filtered : headers;
        _authSourceLabel = `${data.method || 'GET'} ${data.url || data.path || '(unknown)'}`;

        // Pre-fill target URL if empty
        if (targetUrlEl && !targetUrlEl.value.trim() && data.url) {
            try {
                const u = new URL(data.url);
                targetUrlEl.value = u.origin;
            } catch (_) {}
        }

        _updateAuthUI();
    }

    function _clearAuth() {
        _authHeaders = null;
        _authSourceLabel = '';
        _updateAuthUI();
    }

    function _updateAuthUI() {
        if (!authContextEl) return;
        if (_authHeaders && Object.keys(_authHeaders).length) {
            authContextEl.classList.remove('hidden');
            if (authSourceEl) {
                // Truncate long URLs
                let label = _authSourceLabel;
                if (label.length > 80) label = label.slice(0, 77) + '...';
                authSourceEl.textContent = label;
                authSourceEl.title = _authSourceLabel;
            }
        } else {
            authContextEl.classList.add('hidden');
        }
    }

    // ── Scan Control ─────────────────────────────────────────────────

    async function _startScan() {
        const targetUrl = targetUrlEl ? targetUrlEl.value.trim() : '';
        if (!targetUrl) {
            if (targetUrlEl) { targetUrlEl.style.borderColor = 'var(--danger)'; targetUrlEl.focus(); }
            return;
        }
        if (targetUrlEl) targetUrlEl.style.borderColor = '';

        const config = {
            target_url: targetUrl,
            max_concurrent: parseInt(maxConcurrentEl?.value) || 5,
            delay: parseFloat(delayEl?.value) || 0.5,
            max_depth: parseInt(maxDepthEl?.value) || 3,
            max_pages: parseInt(maxPagesEl?.value) || 50,
            enable_upload: enableUploadEl?.checked ?? true,
            enable_ai: enableAiEl?.checked ?? true,
            enable_retest: enableRetestEl?.checked ?? true,
            ai_model: aiModelEl?.value || 'opus',
        };

        // Attach auth headers if loaded from a logged request
        if (_authHeaders && Object.keys(_authHeaders).length) {
            config.auth_headers = _authHeaders;
        }

        // Reset UI
        _resetProgress();
        _clearFeed();
        _showFeedSection(true);
        startBtn.disabled = true;
        startBtn.textContent = 'Starting...';
        pauseBtn.classList.remove('hidden');
        stopBtn.classList.remove('hidden');
        progressPanel.classList.remove('hidden');
        if (placeholderEl) placeholderEl.classList.add('hidden');

        // Mark skipped phases
        if (!config.enable_upload) _renderPhase('upload', 'skipped');
        if (!config.enable_ai) { _renderPhase('ai', 'skipped'); _renderPhase('targeted', 'skipped'); }
        if (!config.enable_retest) _renderPhase('targeted', 'skipped');

        try {
            const res = await fetch(`${API}/auto-scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });
            const data = await res.json();

            if (data.error) {
                phaseTextEl.innerHTML = `<span style="color:var(--danger)">${esc(data.error)}</span>`;
                _scanStopped();
                return;
            }

            startBtn.textContent = 'Running...';
            _startEventPolling();
            _pollStatus();
        } catch (e) {
            phaseTextEl.innerHTML = `<span style="color:var(--danger)">Error: ${esc(e.message)}</span>`;
            _scanStopped();
        }
    }

    async function _pauseScan() {
        try {
            await fetch(`${API}/auto-scan/pause`, { method: 'POST' });
            pauseBtn.textContent = pauseBtn.textContent === 'Pause' ? 'Resume' : 'Pause';
        } catch (_) {}
    }

    async function _stopScan() {
        try {
            await fetch(`${API}/auto-scan/stop`, { method: 'POST' });
        } catch (_) {}
        _scanStopped();
    }

    function _scanStopped() {
        startBtn.disabled = false;
        startBtn.textContent = 'Start Auto Scan';
        pauseBtn.classList.add('hidden');
        pauseBtn.textContent = 'Pause';
        stopBtn.classList.add('hidden');
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        // Do one final poll to catch last events, then stop
        _pollEvents().finally(() => _stopEventPolling());
    }

    function _resetProgress() {
        PHASES.forEach(p => _renderPhase(p, 'pending'));
        if (phaseTextEl) phaseTextEl.innerHTML = '';
        if (endpointsCounter) endpointsCounter.textContent = '0';
        if (vulnsCounter) vulnsCounter.textContent = '0';
        if (requestsCounter) requestsCounter.textContent = '0';

        // Hide result sections
        PHASES.forEach(p => {
            if (resultSections[p]) resultSections[p].classList.add('hidden');
            if (resultBodies[p]) resultBodies[p].innerHTML = '';
            if (resultCounts[p]) resultCounts[p].textContent = '';
        });
    }

    // ── Polling ──────────────────────────────────────────────────────

    function _pollStatus() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(async () => {
            try {
                const res = await fetch(`${API}/auto-scan/status`);
                const st = await res.json();

                // Update counters
                if (endpointsCounter) endpointsCounter.textContent = st.endpoints_found || 0;
                if (vulnsCounter) vulnsCounter.textContent = st.vulns_found || 0;
                if (requestsCounter) requestsCounter.textContent = st.requests_sent || 0;

                // Update pipeline phases
                const currentPhase = st.current_phase || '';
                const completedPhases = new Set(st.completed_phases || []);
                const skippedPhases = new Set(st.skipped_phases || []);

                PHASES.forEach(p => {
                    if (completedPhases.has(p)) {
                        _renderPhase(p, 'complete');
                    } else if (p === currentPhase) {
                        _renderPhase(p, 'active', st.phase_detail || '');
                    } else if (skippedPhases.has(p)) {
                        _renderPhase(p, 'skipped');
                    } else {
                        _renderPhase(p, 'pending');
                    }
                });

                // Phase progress text
                if (st.running) {
                    const label = PHASE_LABELS[currentPhase] || currentPhase;
                    let msg = `${label}`;
                    if (st.phase_detail) msg += ` — ${st.phase_detail}`;
                    let html = `<div class="ai-progress-indicator">
<div class="ai-progress-dot"></div>
<span>${esc(msg)}</span>
</div>`;
                    if (st.last_event) {
                        html += `<div class="autoscan-last-event">${esc(st.last_event)}</div>`;
                    }
                    if (st.paused) {
                        html += `<span style="color:var(--warning);margin-left:8px">(Paused)</span>`;
                    }
                    phaseTextEl.innerHTML = html;
                } else {
                    // Scan finished
                    clearInterval(pollTimer);
                    pollTimer = null;
                    _scanStopped();

                    if (st.error) {
                        phaseTextEl.innerHTML = `<span style="color:var(--danger)">${esc(st.error)}</span>`;
                    } else {
                        phaseTextEl.innerHTML = '<span style="color:var(--success)">Scan complete!</span>';
                        await _loadResults();
                    }
                }
            } catch (_) {}
        }, 2000);
    }

    // ── Results ──────────────────────────────────────────────────────

    async function _loadResults() {
        try {
            const res = await fetch(`${API}/auto-scan/results`);
            const data = await res.json();
            _renderResults(data);
        } catch (_) {
            if (phaseTextEl) phaseTextEl.innerHTML = '<span style="color:var(--danger)">Failed to load results</span>';
        }
    }

    function _renderResults(data) {
        if (!data) return;
        if (placeholderEl) placeholderEl.classList.add('hidden');

        // Phase 1: Crawl results
        if (data.crawl && data.crawl.urls && data.crawl.urls.length) {
            const urls = data.crawl.urls;
            resultSections.crawl.classList.remove('hidden');
            if (resultCounts.crawl) resultCounts.crawl.textContent = `(${urls.length})`;
            resultBodies.crawl.innerHTML = `<div class="autoscan-url-list">${
                urls.map(u => `<div class="autoscan-url-item">${esc(u)}</div>`).join('')
            }</div>`;
        }

        // Phase 2: Injection results
        if (data.inject && data.inject.findings && data.inject.findings.length) {
            const findings = data.inject.findings
                .sort((a, b) => (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
            resultSections.inject.classList.remove('hidden');
            if (resultCounts.inject) resultCounts.inject.textContent = `(${findings.length})`;
            resultBodies.inject.innerHTML = _findingsTableHead() + findings.map(f => _renderFindingRow(f)).join('') + _findingsTableFoot();
            _bindFindingToggles(resultBodies.inject);
        }

        // Phase 3: Upload results
        if (data.upload && data.upload.findings && data.upload.findings.length) {
            const findings = data.upload.findings
                .sort((a, b) => (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
            resultSections.upload.classList.remove('hidden');
            if (resultCounts.upload) resultCounts.upload.textContent = `(${findings.length})`;
            resultBodies.upload.innerHTML = _findingsTableHead() + findings.map(f => _renderFindingRow(f)).join('') + _findingsTableFoot();
            _bindFindingToggles(resultBodies.upload);
        }

        // Phase 4: AI Analysis
        if (data.ai) {
            resultSections.ai.classList.remove('hidden');
            let html = '';

            if (data.ai.summary) {
                html += `<div class="ai-summary" style="margin-bottom:10px">${esc(data.ai.summary)}</div>`;
            }

            if (data.ai.targeted_requests && data.ai.targeted_requests.length) {
                html += `<div style="margin-bottom:10px">
<strong style="color:var(--accent)">Targeted Requests (${data.ai.targeted_requests.length}):</strong>`;
                html += `<table class="findings-table" style="margin-top:6px"><thead><tr>
<th class="col-risk">Risk</th>
<th class="col-method">Method</th>
<th class="col-path">Path</th>
<th class="col-title">Reason</th>
</tr></thead><tbody>`;
                data.ai.targeted_requests.forEach(r => {
                    const risk = (r.risk || 'medium').toLowerCase();
                    html += `<tr class="finding-row" style="cursor:default">
<td><span class="risk-pill risk-pill-${risk}">${esc((r.risk || 'MEDIUM').toUpperCase())}</span></td>
<td class="finding-method">${esc(r.method || 'GET')}</td>
<td class="finding-path" title="${esc(r.url || r.path || '')}">${esc(r.url || r.path || '')}</td>
<td class="finding-title-cell" style="font-weight:400">${esc(r.reason || '')}</td>
</tr>`;
                });
                html += '</tbody></table></div>';
                if (resultCounts.ai) resultCounts.ai.textContent = `(${data.ai.targeted_requests.length} targets)`;
            }

            if (data.ai.findings && data.ai.findings.length) {
                const aiFindings = data.ai.findings
                    .sort((a, b) => (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
                html += _findingsTableHead() + aiFindings.map(f => _renderFindingRow(f)).join('') + _findingsTableFoot();
            }

            resultBodies.ai.innerHTML = html || '<p class="placeholder-text">No AI analysis results</p>';
            _bindFindingToggles(resultBodies.ai);
        }

        // Phase 5: Targeted re-test results
        if (data.targeted && data.targeted.findings && data.targeted.findings.length) {
            const findings = data.targeted.findings
                .sort((a, b) => (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
            resultSections.targeted.classList.remove('hidden');
            if (resultCounts.targeted) resultCounts.targeted.textContent = `(${findings.length})`;
            resultBodies.targeted.innerHTML = _findingsTableHead() + findings.map(f => _renderFindingRow(f)).join('') + _findingsTableFoot();
            _bindFindingToggles(resultBodies.targeted);
        }
    }

    function _bindFindingToggles(container) {
        if (!container) return;
        container.querySelectorAll('tr.finding-row').forEach(row => {
            // Skip rows that have cursor:default (targeted request rows without detail)
            if (row.style.cursor === 'default') return;
            row.addEventListener('click', () => {
                const detailRow = row.nextElementSibling;
                if (detailRow && detailRow.classList.contains('finding-detail-row')) {
                    const isOpen = detailRow.classList.toggle('visible');
                    row.classList.toggle('expanded', isOpen);
                }
            });
        });
    }

    // ── Public API ───────────────────────────────────────────────────

    async function refresh() {
        try {
            const res = await fetch(`${API}/auto-scan/status`);
            const st = await res.json();

            if (st.running) {
                // Scan in progress — resume polling
                progressPanel.classList.remove('hidden');
                startBtn.disabled = true;
                startBtn.textContent = 'Running...';
                pauseBtn.classList.remove('hidden');
                stopBtn.classList.remove('hidden');
                if (placeholderEl) placeholderEl.classList.add('hidden');
                _showFeedSection(true);
                _startEventPolling();
                _pollStatus();
            } else if (st.endpoints_found || st.vulns_found) {
                // Previous scan completed — load results
                await _loadResults();
            }
        } catch (_) {
            // Backend not reachable — no-op
        }
    }

    function loadHistory() {
        // Clear state on workspace switch
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        _stopEventPolling();
        _clearFeed();
        _showFeedSection(false);
        _resetProgress();
        if (progressPanel) progressPanel.classList.add('hidden');
        if (placeholderEl) placeholderEl.classList.remove('hidden');
        _clearAuth();
        startBtn.disabled = false;
        startBtn.textContent = 'Start Auto Scan';
        pauseBtn.classList.add('hidden');
        pauseBtn.textContent = 'Pause';
        stopBtn.classList.add('hidden');
    }

    return { init, refresh, loadHistory };
})();
