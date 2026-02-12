/**
 * AiAnalysis — Claude Code AI analysis of captured traffic
 */
window.AiAnalysis = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let modelEl, hostFilterEl, previewBtn, analyzeBtn, progressEl, resultsEl;
    let previewInfoEl;
    let pollTimer = null;

    const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const RISK_COLORS = {
        critical: '#ff4444',
        high: 'var(--danger)',
        medium: 'var(--warning)',
        low: 'var(--success)',
        info: 'var(--accent)',
    };

    function init() {
        modelEl      = document.getElementById('ai-model');
        hostFilterEl = document.getElementById('ai-host-filter');
        previewBtn   = document.getElementById('btn-ai-preview');
        analyzeBtn   = document.getElementById('btn-ai-analyze');
        progressEl   = document.getElementById('ai-progress');
        resultsEl    = document.getElementById('ai-results');
        previewInfoEl = document.getElementById('ai-preview-info');

        previewBtn.addEventListener('click', preview);
        analyzeBtn.addEventListener('click', analyze);
    }

    async function preview() {
        previewBtn.disabled = true;
        previewBtn.textContent = '...';
        previewInfoEl.textContent = '';

        try {
            const hostFilter = hostFilterEl.value || '';
            const res = await fetch(`${API}/ai/preview`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host_filter: hostFilter }),
            });
            const data = await res.json();

            let info = `${data.endpoint_count} unique endpoints from ${data.total_logs} logs`;
            if (data.scan_result_count) {
                info += ` + ${data.scan_result_count} scan results`;
                if (data.confirmed_vulns)
                    info += ` (${data.confirmed_vulns} confirmed vuln${data.confirmed_vulns === 1 ? '' : 's'})`;
            }
            info += ` (~${data.estimated_size_kb} KB)`;
            previewInfoEl.textContent = info;

            // Populate host filter dropdown
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
            previewInfoEl.textContent = 'Failed to preview: ' + e.message;
            previewInfoEl.style.color = 'var(--danger)';
        } finally {
            previewBtn.disabled = false;
            previewBtn.textContent = 'Preview';
        }
    }

    async function analyze() {
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = 'Starting...';
        progressEl.innerHTML = '';
        progressEl.classList.remove('hidden');

        const model = modelEl.value || 'opus';
        const hostFilter = hostFilterEl.value || '';

        try {
            const res = await fetch(`${API}/ai/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ model, host_filter: hostFilter }),
            });
            const data = await res.json();

            if (data.error) {
                progressEl.innerHTML = `<span style="color:var(--danger)">${esc(data.error)}</span>`;
                analyzeBtn.disabled = false;
                analyzeBtn.textContent = 'Analyze';
                return;
            }

            // Start polling
            _pollStatus();
        } catch (e) {
            progressEl.innerHTML = `<span style="color:var(--danger)">Error: ${esc(e.message)}</span>`;
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = 'Analyze';
        }
    }

    function _pollStatus() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(async () => {
            try {
                const res = await fetch(`${API}/ai/status`);
                const st = await res.json();

                if (st.running) {
                    let msg = '';
                    if (st.phase === 'collecting') {
                        msg = 'Collecting traffic data...';
                    } else if (st.phase === 'analyzing') {
                        msg = `Analyzing ${st.endpoint_count} endpoints with Claude... This may take a minute.`;
                    }
                    progressEl.innerHTML =
`<div class="ai-progress-indicator">
<div class="ai-progress-dot"></div>
<span>${esc(msg)}</span>
</div>`;
                } else {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    analyzeBtn.disabled = false;
                    analyzeBtn.textContent = 'Analyze';

                    if (st.error) {
                        progressEl.innerHTML = `<span style="color:var(--danger)">${esc(st.error)}</span>`;
                    } else {
                        progressEl.innerHTML = '<span style="color:var(--success)">Analysis complete!</span>';
                        setTimeout(() => { progressEl.classList.add('hidden'); }, 3000);
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
            _renderResults(results);
        } catch (_) {
            resultsEl.innerHTML = '<p class="placeholder-text" style="padding:10px">Failed to load results</p>';
        }
    }

    function _renderResults(results) {
        if (!results || !results.length) {
            resultsEl.innerHTML =
                '<p class="placeholder-text" style="padding:20px;text-align:center">No analysis results yet. Click Preview, then Analyze to scan your captured traffic.</p>';
            return;
        }

        resultsEl.innerHTML = results.map((r, idx) => {
            const findings = r.findings || [];
            const riskCounts = {};
            findings.forEach(f => {
                const risk = (f.risk || 'info').toLowerCase();
                riskCounts[risk] = (riskCounts[risk] || 0) + 1;
            });

            const riskBadges = Object.entries(riskCounts)
                .sort((a, b) => (RISK_ORDER[a[0]] || 9) - (RISK_ORDER[b[0]] || 9))
                .map(([risk, count]) => `<span class="ai-risk-badge ai-risk-${risk}">${count} ${risk.toUpperCase()}</span>`)
                .join(' ');

            const modelLabel = (r.model || 'opus').charAt(0).toUpperCase() + (r.model || 'opus').slice(1);
            const time = _fmtTime(r.created_at);
            const hostLabel = r.host_filter || 'All traffic';

            const findingsHtml = findings
                .sort((a, b) => (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9))
                .map(f => _renderFinding(f))
                .join('');

            return `<div class="ai-result-card collapsed" data-idx="${idx}" data-id="${r.id}">
<div class="ai-result-header" data-idx="${idx}">
<div class="ai-result-meta">
<strong>Claude ${esc(modelLabel)}</strong>
<span class="ai-result-time">${esc(time)}</span>
<span class="ai-result-endpoints">${r.endpoint_count} endpoints</span>
<span class="ai-result-host">${esc(hostLabel)}</span>
</div>
<div class="ai-risk-summary">${riskBadges}</div>
</div>
<div class="ai-result-body">
${r.summary ? `<div class="ai-summary">${esc(r.summary)}</div>` : ''}
<div class="ai-findings">${findingsHtml || '<p class="placeholder-text">No findings</p>'}</div>
</div>
</div>`;
        }).join('');

        // Toggle collapse on card headers
        resultsEl.querySelectorAll('.ai-result-header').forEach(hdr => {
            hdr.addEventListener('click', () => {
                const card = hdr.closest('.ai-result-card');
                card.classList.toggle('collapsed');
            });
        });

        // Toggle finding details
        resultsEl.querySelectorAll('.ai-finding-header').forEach(hdr => {
            hdr.addEventListener('click', () => {
                const finding = hdr.closest('.ai-finding');
                finding.classList.toggle('expanded');
            });
        });

        // Right-click to delete
        resultsEl.querySelectorAll('.ai-result-card').forEach(card => {
            card.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const id = card.dataset.id;
                if (!id) return;
                _showDeleteMenu(e.clientX, e.clientY, Number(id), card);
            });
        });
    }

    function _showDeleteMenu(x, y, resultId, cardEl) {
        _removeDeleteMenu();
        const menu = document.createElement('div');
        menu.className = 'ctx-menu ai-ctx-menu';
        menu.innerHTML = '<div class="ctx-menu-item ctx-menu-item--danger">Delete Analysis</div>';
        menu.style.left = x + 'px';
        menu.style.top = y + 'px';
        document.body.appendChild(menu);

        menu.querySelector('.ctx-menu-item').addEventListener('click', async () => {
            _removeDeleteMenu();
            if (!confirm('Delete this analysis result?')) return;
            try {
                await fetch(`${API}/ai/results/${resultId}`, { method: 'DELETE' });
                cardEl.remove();
            } catch (_) {}
        });

        const dismiss = (e) => {
            if (!menu.contains(e.target)) { _removeDeleteMenu(); document.removeEventListener('click', dismiss); }
        };
        setTimeout(() => document.addEventListener('click', dismiss), 0);
    }

    function _removeDeleteMenu() {
        document.querySelectorAll('.ai-ctx-menu').forEach(m => m.remove());
    }

    function _renderFinding(f) {
        const risk = (f.risk || 'info').toLowerCase();
        const color = RISK_COLORS[risk] || 'var(--text-dim)';
        return `<div class="ai-finding" data-risk="${risk}">
<div class="ai-finding-header">
<span class="ai-finding-risk" style="color:${color}">${(f.risk || 'INFO').toUpperCase()}</span>
<span class="ai-finding-method">${esc(f.method || '')}</span>
<span class="ai-finding-path">${esc(f.path || f.endpoint || '')}</span>
<span class="ai-finding-title">${esc(f.title || '')}</span>
<span class="ai-finding-category">${esc(f.category || '')}</span>
</div>
<div class="ai-finding-details">
<div class="ai-finding-row"><strong>Description:</strong> ${esc(f.description || '')}</div>
<div class="ai-finding-row"><strong>Evidence:</strong> ${esc(f.evidence || '')}</div>
<div class="ai-finding-row"><strong>Recommendation:</strong> ${esc(f.recommendation || '')}</div>
</div>
</div>`;
    }

    function _fmtTime(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
                   d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch (_) { return ''; }
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    /** Called when switching to the AI tab */
    async function refresh() {
        await _loadResults();
    }

    /** Called on workspace switch */
    function loadHistory() {
        if (resultsEl) resultsEl.innerHTML = '';
        if (progressEl) { progressEl.innerHTML = ''; progressEl.classList.add('hidden'); }
        if (previewInfoEl) previewInfoEl.textContent = '';
        if (hostFilterEl) hostFilterEl.innerHTML = '<option value="">All traffic</option>';
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        if (analyzeBtn) { analyzeBtn.disabled = false; analyzeBtn.textContent = 'Analyze'; }
    }

    /** Clear all results */
    async function clearHistory() {
        try { await fetch(`${API}/ai/results`, { method: 'DELETE' }); } catch (_) {}
        if (resultsEl) resultsEl.innerHTML = '';
    }

    return { init, refresh, loadHistory, clearHistory };
})();
