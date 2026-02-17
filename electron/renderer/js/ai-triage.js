/**
 * AiTriage — Quick AI Triage: analyze captured proxy traffic,
 * identify file upload points and weak endpoints, rank by attack priority.
 */
window.AiTriage = (() => {
    const API = 'http://127.0.0.1:8000/api';

    const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    let modelEl, hostFilterEl, previewBtn, runBtn, previewInfoEl, progressEl, resultsEl;
    let pollTimer = null;
    let _lastTriageResult = null; // full parsed result from the AI

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function init() {
        modelEl       = document.getElementById('triage-model');
        hostFilterEl  = document.getElementById('triage-host-filter');
        previewBtn    = document.getElementById('btn-triage-preview');
        runBtn        = document.getElementById('btn-triage-run');
        previewInfoEl = document.getElementById('triage-preview-info');
        progressEl    = document.getElementById('triage-progress');
        resultsEl     = document.getElementById('triage-results');

        if (previewBtn) previewBtn.addEventListener('click', _preview);
        if (runBtn) runBtn.addEventListener('click', _runTriage);

        // Register with SendTo system
        SendTo.register('triage', {
            label: 'Quick Triage',
            tab: 'ai',
            receive(data) {
                // Switch to triage sub-tab
                const triageBtn = document.querySelector('.ai-subtab[data-subtab="triage"]');
                if (triageBtn) triageBtn.click();
                // Pre-fill host filter from the incoming request URL
                if (data.url) {
                    try {
                        const host = new URL(data.url).host;
                        if (hostFilterEl) hostFilterEl.value = host;
                    } catch (_) {}
                }
            },
        });
    }

    /** Send a target to the Injector tab */
    function _sendToInjector(target) {
        const data = {
            method: target.method || 'GET',
            url: target.url || '',
            headers: {},
            body: '',
        };
        if (window.SendTo) {
            window.SendTo.sendTo('injector', data);
        }
    }

    /** Send a target to the Repeater tab */
    function _sendToRepeater(target) {
        const data = {
            method: target.method || 'GET',
            url: target.url || '',
            headers: {},
            body: '',
        };
        if (window.SendTo) {
            window.SendTo.sendTo('repeater', data);
        }
    }

    async function _preview() {
        previewBtn.disabled = true;
        previewBtn.textContent = '...';
        previewInfoEl.textContent = '';

        try {
            const res = await fetch(`${API}/ai/preview`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host_filter: hostFilterEl.value || '' }),
            });
            const data = await res.json();

            let info = `${data.endpoint_count} endpoints from ${data.total_logs} logs`;
            if (data.scan_result_count) {
                info += ` + ${data.scan_result_count} scan results`;
                if (data.confirmed_vulns) info += ` (${data.confirmed_vulns} confirmed)`;
            }
            info += ` (~${data.estimated_size_kb} KB)`;
            previewInfoEl.textContent = info;

            // Populate host dropdown
            if (data.hosts && data.hosts.length) {
                const current = hostFilterEl.value;
                hostFilterEl.innerHTML = '<option value="">All traffic</option>';
                data.hosts.forEach(h => {
                    const opt = document.createElement('option');
                    opt.value = h;
                    opt.textContent = h;
                    if (h === current) opt.selected = true;
                    hostFilterEl.appendChild(opt);
                });
            }
        } catch (e) {
            previewInfoEl.textContent = 'Failed: ' + e.message;
            previewInfoEl.style.color = 'var(--danger)';
        } finally {
            previewBtn.disabled = false;
            previewBtn.textContent = 'Preview';
        }
    }

    async function _runTriage() {
        runBtn.disabled = true;
        runBtn.textContent = 'Starting...';
        progressEl.innerHTML = '';
        progressEl.classList.remove('hidden');

        const model = modelEl.value || 'sonnet';
        const hostFilter = hostFilterEl.value || '';

        try {
            const res = await fetch(`${API}/ai/triage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ model, host_filter: hostFilter }),
            });
            const data = await res.json();

            if (data.error) {
                progressEl.innerHTML = `<span style="color:var(--danger)">${esc(data.error)}</span>`;
                runBtn.disabled = false;
                runBtn.textContent = 'Run Triage';
                return;
            }

            _pollStatus();
        } catch (e) {
            progressEl.innerHTML = `<span style="color:var(--danger)">Error: ${esc(e.message)}</span>`;
            runBtn.disabled = false;
            runBtn.textContent = 'Run Triage';
        }
    }

    function _pollStatus() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(async () => {
            try {
                const res = await fetch(`${API}/ai/triage/status`);
                const st = await res.json();

                if (st.running) {
                    let msg = '';
                    if (st.phase === 'collecting') msg = 'Collecting traffic data...';
                    else if (st.phase === 'analyzing') msg = `Analyzing ${st.endpoint_count} endpoints with Claude...`;
                    else if (st.phase === 'executing') msg = `Executing ${st.endpoint_count} targeted requests...`;
                    progressEl.innerHTML = `<div class="ai-progress-indicator"><div class="ai-progress-dot"></div><span>${esc(msg)}</span></div>`;
                } else {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    runBtn.disabled = false;
                    runBtn.textContent = 'Run Triage';

                    if (st.error) {
                        progressEl.innerHTML = `<span style="color:var(--danger)">${esc(st.error)}</span>`;
                    } else {
                        progressEl.innerHTML = '<span style="color:var(--success)">Triage complete!</span>';
                        setTimeout(() => progressEl.classList.add('hidden'), 3000);
                        await _loadResults();
                    }
                }
            } catch (_) {}
        }, 2000);
    }

    async function _loadResults() {
        try {
            const res = await fetch(`${API}/ai/results`);
            const results = await res.json();
            // Find the most recent triage or triage-exec result
            const triageResults = results.filter(r => {
                const m = r.model || '';
                return m.startsWith('triage:') || m.startsWith('triage-exec:');
            });
            if (triageResults.length) {
                const latest = triageResults[0];
                if ((latest.model || '').startsWith('triage-exec:')) {
                    _renderExecuteResult(latest);
                } else {
                    _renderTriageResult(latest);
                }
            }
        } catch (_) {}
    }

    function _renderTriageResult(result) {
        let rawData;
        try {
            rawData = typeof result.raw_response === 'string'
                ? JSON.parse(result.raw_response)
                : result.raw_response || {};
        } catch (_) { rawData = {}; }

        _lastTriageResult = rawData;

        const summary = rawData.summary || result.summary || '';
        const uploads = rawData.upload_endpoints || [];
        const targets = rawData.priority_targets || [];

        let html = '';

        // Summary
        if (summary) {
            html += `<div class="triage-summary">${esc(summary)}</div>`;
        }

        // Upload endpoints table
        html += `<div class="triage-section">
<div class="triage-section-header">
    <span class="triage-section-icon">&#128229;</span>
    <span class="triage-section-title">File Upload Endpoints</span>
    <span class="triage-section-count">${uploads.length} found</span>
</div>`;
        if (uploads.length) {
            html += '<table class="triage-table"><thead><tr><th>Method</th><th>URL</th><th>Reason</th><th>Tests</th><th></th></tr></thead><tbody>';
            uploads.forEach((u, ui) => {
                const tests = (u.suggested_tests || []).map(t => `<li>${esc(t)}</li>`).join('');
                html += `<tr>
<td><span class="triage-method method-${esc(u.method || 'POST')}">${esc(u.method || 'POST')}</span></td>
<td class="triage-url-cell">${esc(u.url || '')}</td>
<td>${esc(u.reason || '')}</td>
<td>${tests ? `<ul class="triage-test-list">${tests}</ul>` : '-'}</td>
<td class="triage-actions-cell">
    <button class="btn-small triage-inject-btn" data-upload-idx="${ui}" title="Send to Injector">Inject</button>
    <button class="btn-small triage-repeat-btn" data-upload-idx="${ui}" title="Send to Repeater">Send</button>
</td>
</tr>`;
            });
            html += '</tbody></table>';
        } else {
            html += '<p class="triage-empty">No file upload endpoints detected in captured traffic.</p>';
        }
        html += '</div>';

        // Priority targets table
        html += `<div class="triage-section">
<div class="triage-section-header">
    <span class="triage-section-icon">&#127919;</span>
    <span class="triage-section-title">Priority Attack Targets</span>
    <span class="triage-section-count">${targets.length} targets</span>
</div>`;
        if (targets.length) {
            html += '<table class="triage-table triage-targets-table"><thead><tr><th>#</th><th>Risk</th><th>Method</th><th>URL</th><th>Reason</th><th>Payloads</th><th></th></tr></thead><tbody>';
            targets.forEach((t, i) => {
                const risk = _priorityToRisk(t.priority || (i + 1));
                const payloads = t.suggested_payloads || [];
                const payloadSummary = payloads.length
                    ? payloads.map(p => `<span class="triage-payload-chip">${esc(p.type || '?')}: ${esc(p.key || '*')}</span>`).join(' ')
                    : '-';

                html += `<tr data-target-idx="${i}">
<td>${t.priority || (i + 1)}</td>
<td><span class="risk-pill risk-pill-${risk}">${risk.toUpperCase()}</span></td>
<td><span class="triage-method method-${esc(t.method || 'GET')}">${esc(t.method || 'GET')}</span></td>
<td class="triage-url-cell">${esc(t.url || '')}</td>
<td class="triage-reason-cell">${esc(t.risk_reason || '')}</td>
<td class="triage-payloads-cell">${payloadSummary}</td>
<td class="triage-actions-cell">
    <button class="btn-small triage-inject-btn" data-target-idx="${i}" title="Send to Injector">Inject</button>
    <button class="btn-small triage-repeat-btn" data-target-idx="${i}" title="Send to Repeater">Send</button>
    <button class="btn-small triage-execute-btn" data-idx="${i}" title="Execute AI-suggested payloads">Execute</button>
</td>
</tr>`;
            });
            html += '</tbody></table>';

            // Execute All button
            html += `<div class="triage-execute-bar">
<button id="btn-triage-execute-all" class="btn-primary" style="width:auto;padding:0 20px;height:32px">Execute All Payloads</button>
<span class="triage-execute-hint">${targets.reduce((s, t) => s + (t.suggested_payloads || []).length, 0)} payloads across ${targets.length} targets</span>
</div>`;
        } else {
            html += '<p class="triage-empty">No priority targets identified.</p>';
        }
        html += '</div>';

        resultsEl.innerHTML = html;

        // Bind upload table action buttons
        resultsEl.querySelectorAll('.triage-inject-btn[data-upload-idx]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.uploadIdx);
                if (uploads[idx]) _sendToInjector(uploads[idx]);
            });
        });
        resultsEl.querySelectorAll('.triage-repeat-btn[data-upload-idx]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.uploadIdx);
                if (uploads[idx]) _sendToRepeater(uploads[idx]);
            });
        });

        // Bind target table action buttons
        resultsEl.querySelectorAll('.triage-inject-btn[data-target-idx]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.targetIdx);
                if (targets[idx]) _sendToInjector(targets[idx]);
            });
        });
        resultsEl.querySelectorAll('.triage-repeat-btn[data-target-idx]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.targetIdx);
                if (targets[idx]) _sendToRepeater(targets[idx]);
            });
        });

        // Bind execute buttons
        resultsEl.querySelectorAll('.triage-execute-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.idx);
                if (targets[idx]) _executeTarget(targets[idx], btn);
            });
        });

        const executeAllBtn = document.getElementById('btn-triage-execute-all');
        if (executeAllBtn) {
            executeAllBtn.addEventListener('click', () => _executeAll(targets));
        }
    }

    function _renderExecuteResult(result) {
        let rawData;
        try {
            rawData = typeof result.raw_response === 'string'
                ? JSON.parse(result.raw_response)
                : result.raw_response || {};
        } catch (_) { rawData = {}; }

        _lastTriageResult = rawData;

        const summary = rawData.summary || result.summary || '';
        const findings = rawData.findings || [];
        const targeted = rawData.targeted_results || [];

        let html = '';

        // Summary
        if (summary) {
            html += `<div class="triage-summary">${esc(summary)}</div>`;
        }

        // Findings
        html += `<div class="triage-section">
<div class="triage-section-header">
    <span class="triage-section-icon">&#128269;</span>
    <span class="triage-section-title">Findings</span>
    <span class="triage-section-count">${findings.length} found</span>
</div>`;
        if (findings.length) {
            const sorted = [...findings].sort((a, b) =>
                (RISK_ORDER[a.risk] ?? 4) - (RISK_ORDER[b.risk] ?? 4));
            sorted.forEach(f => {
                const risk = f.risk || f.severity || 'info';
                html += `<div class="triage-finding-card">
<div class="triage-finding-header">
    <span class="risk-pill risk-pill-${risk}">${esc(risk.toUpperCase())}</span>
    <span class="triage-finding-title">${esc(f.title || f.name || 'Finding')}</span>
</div>
<div class="triage-finding-body">
    <p>${esc(f.description || f.detail || '')}</p>
    ${f.evidence ? `<div class="triage-evidence"><strong>Evidence:</strong> ${esc(f.evidence)}</div>` : ''}
    ${f.recommendation ? `<div class="triage-recommendation"><strong>Recommendation:</strong> ${esc(f.recommendation)}</div>` : ''}
    ${f.affected_endpoints ? `<div class="triage-affected"><strong>Affected:</strong> ${(Array.isArray(f.affected_endpoints) ? f.affected_endpoints : [f.affected_endpoints]).map(e => esc(e)).join(', ')}</div>` : ''}
</div>
</div>`;
            });
        } else {
            html += '<p class="triage-empty">No findings from the executed payloads.</p>';
        }
        html += '</div>';

        // Targeted request results
        if (targeted.length) {
            html += `<div class="triage-section">
<div class="triage-section-header">
    <span class="triage-section-icon">&#128640;</span>
    <span class="triage-section-title">Executed Requests</span>
    <span class="triage-section-count">${targeted.length} requests</span>
</div>
<table class="triage-table"><thead><tr><th>Method</th><th>URL</th><th>Payload</th><th>Status</th><th>Time</th></tr></thead><tbody>`;
            targeted.forEach(t => {
                const statusClass = t.status_code >= 200 && t.status_code < 300 ? 'status-2xx'
                    : t.status_code >= 400 && t.status_code < 500 ? 'status-4xx'
                    : t.status_code >= 500 ? 'status-5xx' : 'status-0';
                html += `<tr>
<td><span class="triage-method method-${esc(t.method || 'GET')}">${esc(t.method || 'GET')}</span></td>
<td class="triage-url-cell">${esc(t.url || '')}</td>
<td class="triage-payload-cell">${esc(t.payload || '-')}</td>
<td><span class="${statusClass}">${t.status_code || 'err'}</span></td>
<td>${t.response_time_ms ? Math.round(t.response_time_ms) + 'ms' : '-'}</td>
</tr>`;
            });
            html += '</tbody></table></div>';
        }

        resultsEl.innerHTML = html;
    }

    function _priorityToRisk(priority) {
        if (priority <= 3) return 'critical';
        if (priority <= 7) return 'high';
        if (priority <= 13) return 'medium';
        return 'low';
    }

    async function _executeTarget(target, btn) {
        btn.disabled = true;
        btn.textContent = '...';

        const payload = {
            targets: [{
                method: target.method || 'GET',
                url: target.url || '',
                risk_reason: target.risk_reason || '',
                payloads: target.suggested_payloads || [],
            }],
            model: modelEl.value || 'sonnet',
        };

        try {
            const res = await fetch(`${API}/ai/triage/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (data.error) {
                btn.textContent = 'Error';
                btn.style.color = 'var(--danger)';
                return;
            }
            btn.textContent = 'Running...';
            _pollStatus();
        } catch (_) {
            btn.textContent = 'Error';
            btn.style.color = 'var(--danger)';
        }
    }

    async function _executeAll(targets) {
        const btn = document.getElementById('btn-triage-execute-all');
        if (btn) { btn.disabled = true; btn.textContent = 'Starting...'; }

        progressEl.innerHTML = '';
        progressEl.classList.remove('hidden');

        const payload = {
            targets: targets.map(t => ({
                method: t.method || 'GET',
                url: t.url || '',
                risk_reason: t.risk_reason || '',
                payloads: t.suggested_payloads || [],
            })),
            model: modelEl.value || 'sonnet',
        };

        try {
            const res = await fetch(`${API}/ai/triage/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (data.error) {
                progressEl.innerHTML = `<span style="color:var(--danger)">${esc(data.error)}</span>`;
                if (btn) { btn.disabled = false; btn.textContent = 'Execute All Payloads'; }
                return;
            }
            if (btn) btn.textContent = 'Running...';
            _pollStatus();
        } catch (e) {
            progressEl.innerHTML = `<span style="color:var(--danger)">Error: ${esc(e.message)}</span>`;
            if (btn) { btn.disabled = false; btn.textContent = 'Execute All Payloads'; }
        }
    }

    function refresh() {
        _loadResults();
    }

    function loadHistory() {
        _lastTriageResult = null;
        if (resultsEl) resultsEl.innerHTML = `<p class="placeholder-text" style="padding:20px;text-align:center">
            Browse a target site, then click <strong>Run Triage</strong> to analyze your captured proxy traffic.<br>
            The AI will identify file upload points and rank endpoints by attack priority.
        </p>`;
        if (progressEl) { progressEl.innerHTML = ''; progressEl.classList.add('hidden'); }
        if (previewInfoEl) previewInfoEl.textContent = '';
        if (hostFilterEl) hostFilterEl.innerHTML = '<option value="">All traffic</option>';
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        if (runBtn) { runBtn.disabled = false; runBtn.textContent = 'Run Triage'; }
    }

    return { init, refresh, loadHistory };
})();
