/**
 * AiAnalysis — Claude Code AI analysis of captured traffic
 */
window.AiAnalysis = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let modelEl, hostFilterEl, previewBtn, analyzeBtn, progressEl, resultsEl;
    let previewInfoEl, authContextBar;
    let pollTimer = null;
    let _authContext = null; // { method, url, headers, body } from a logged request
    let _lastResults = null; // cached for copy buttons

    const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const RISK_COLORS = {
        critical: '#ff4444',
        high: 'var(--danger)',
        medium: 'var(--warning)',
        low: 'var(--success)',
        info: 'var(--accent)',
    };

    let exportToolbar;

    function init() {
        modelEl      = document.getElementById('ai-model');
        hostFilterEl = document.getElementById('ai-host-filter');
        previewBtn   = document.getElementById('btn-ai-preview');
        analyzeBtn   = document.getElementById('btn-ai-analyze');
        progressEl   = document.getElementById('ai-progress');
        resultsEl    = document.getElementById('ai-results');
        previewInfoEl = document.getElementById('ai-preview-info');
        authContextBar = document.getElementById('ai-auth-context');
        exportToolbar = document.getElementById('ai-export-toolbar');

        previewBtn.addEventListener('click', preview);
        analyzeBtn.addEventListener('click', analyze);

        // Clear auth context button
        const clearBtn = document.getElementById('btn-ai-clear-auth');
        if (clearBtn) clearBtn.addEventListener('click', _clearAuthContext);

        // Export toolbar buttons (these work purely client-side from cached results)
        _bindExport('btn-ai-download-md', () => _downloadFile(_buildAllMarkdown(), 'ai-analysis.md', 'text/markdown'));
        _bindExport('btn-ai-download-json', () => _downloadFile(JSON.stringify(_lastResults, null, 2), 'ai-analysis.json', 'application/json'));
        _bindExport('btn-ai-download-csv', () => _downloadFile(_buildAllCSV(), 'ai-analysis.csv', 'text/csv'));
        _bindExport('btn-ai-copy-md', (btn) => _copyWithFeedback(btn, _buildAllMarkdown()));
        _bindExport('btn-ai-copy-json', (btn) => _copyWithFeedback(btn, JSON.stringify(_lastResults, null, 2)));

        // Register with SendTo system
        SendTo.register('ai', {
            label: 'AI Analysis',
            receive(data) { _receiveFromLog(data); },
        });
    }

    function _bindExport(id, handler) {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', () => {
            if (!_lastResults || !_lastResults.length) return;
            handler(el);
        });
    }

    function _downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function _buildAllMarkdown() {
        let md = '';
        (_lastResults || []).forEach(r => { md += _generateMarkdownSingle(r) + '\n\n---\n\n'; });
        return md;
    }

    function _buildAllCSV() {
        const rows = [['Risk', 'Title', 'Category', 'Endpoint', 'Description', 'Evidence', 'Recommendation'].join(',')];
        (_lastResults || []).forEach(r => {
            (r.findings || []).forEach(f => {
                rows.push([
                    _csvCell(f.risk || 'info'),
                    _csvCell(f.title || ''),
                    _csvCell(f.category || ''),
                    _csvCell((f.method || '') + ' ' + (f.path || f.endpoint || '')),
                    _csvCell(f.description || ''),
                    _csvCell(f.evidence || ''),
                    _csvCell(f.recommendation || ''),
                ].join(','));
            });
        });
        return rows.join('\n');
    }

    function _csvCell(s) {
        if (!s) return '""';
        return '"' + String(s).replace(/"/g, '""').replace(/\n/g, ' ') + '"';
    }

    function _updateExportToolbar() {
        if (!exportToolbar) return;
        if (_lastResults && _lastResults.length) {
            exportToolbar.classList.remove('hidden');
        } else {
            exportToolbar.classList.add('hidden');
        }
    }

    /** Receive a request from the log viewer / context menu */
    function _receiveFromLog(data) {
        _authContext = {
            method: data.method || 'GET',
            url: data.url || '',
            headers: data.headers || data.request_headers || {},
            body: data.body || data.request_body || '',
        };
        _renderAuthContext();

        // Switch to manual analysis sub-tab
        const manualBtn = document.querySelector('.ai-subtab[data-subtab="manual"]');
        if (manualBtn) manualBtn.click();
    }

    function _renderAuthContext() {
        if (!authContextBar) return;
        if (!_authContext) {
            authContextBar.classList.add('hidden');
            return;
        }
        authContextBar.classList.remove('hidden');
        const labelEl = authContextBar.querySelector('.ai-auth-label');
        if (labelEl) {
            let path = _authContext.url;
            try { path = new URL(_authContext.url).pathname; } catch (_) {}
            labelEl.textContent = `${_authContext.method} ${path}`;
        }
    }

    function _clearAuthContext() {
        _authContext = null;
        _renderAuthContext();
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

        // Use /ai/analyze-request when auth context is available
        let endpoint = `${API}/ai/analyze`;
        const payload = { model, host_filter: hostFilter };
        if (_authContext) {
            endpoint = `${API}/ai/analyze-request`;
            payload.method = _authContext.method;
            payload.url = _authContext.url;
            payload.headers = _authContext.headers;
            payload.body = _authContext.body;
        }

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
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
            _updateExportToolbar();
        } catch (_) {
            resultsEl.innerHTML = '<p class="placeholder-text" style="padding:10px">Failed to load results</p>';
        }
    }

    function _copyWithFeedback(btn, text) {
        const orig = btn.textContent;
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = 'Copied!';
            btn.style.color = 'var(--success)';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
        }).catch(() => {
            btn.textContent = 'Failed';
            btn.style.color = 'var(--danger)';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
        });
    }

    function _allFindingsFlat(results) {
        const all = [];
        (results || []).forEach(r => {
            (r.findings || []).forEach(f => all.push(f));
        });
        return all.sort((a, b) =>
            (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) -
            (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
    }

    function _generatePlainText(results) {
        let txt = '=== AI Security Analysis ===\n\n';
        (results || []).forEach(r => {
            const modelLabel = (r.model || 'opus').charAt(0).toUpperCase() + (r.model || 'opus').slice(1);
            txt += `Model: Claude ${modelLabel} | Host: ${r.host_filter || 'All traffic'} | Endpoints: ${r.endpoint_count || 0} | ${_fmtTime(r.created_at)}\n`;
            if (r.summary) txt += `Summary: ${r.summary}\n`;
            txt += '\n';
            const findings = [...(r.findings || [])].sort((a, b) =>
                (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
            findings.forEach((f, i) => {
                txt += `[${(f.risk || 'INFO').toUpperCase()}] ${f.title || 'Untitled'}\n`;
                if (f.method || f.path || f.endpoint) txt += `  Endpoint: ${f.method || ''} ${f.path || f.endpoint || ''}\n`;
                if (f.category) txt += `  Category: ${f.category}\n`;
                if (f.description) txt += `  Description: ${f.description}\n`;
                if (f.evidence) txt += `  Evidence: ${f.evidence}\n`;
                if (f.recommendation) txt += `  Recommendation: ${f.recommendation}\n`;
                txt += '\n';
            });
            txt += '---\n\n';
        });
        return txt;
    }

    function _generateMarkdownSingle(r) {
        const findings = r.findings || [];
        const modelLabel = (r.model || 'opus').charAt(0).toUpperCase() + (r.model || 'opus').slice(1);
        const time = _fmtTime(r.created_at);
        const hostLabel = r.host_filter || 'All traffic';

        const riskCounts = {};
        findings.forEach(f => { const risk = (f.risk || 'info').toLowerCase(); riskCounts[risk] = (riskCounts[risk] || 0) + 1; });
        const riskLine = Object.entries(riskCounts)
            .sort((a, b) => (RISK_ORDER[a[0]] || 9) - (RISK_ORDER[b[0]] || 9))
            .map(([risk, count]) => `${count} ${risk.toUpperCase()}`)
            .join(' | ');

        let md = `# AI Security Analysis\n\n`;
        md += `- **Model:** Claude ${modelLabel}\n`;
        md += `- **Date:** ${time}\n`;
        md += `- **Endpoints analyzed:** ${r.endpoint_count || 0}\n`;
        md += `- **Host filter:** ${hostLabel}\n`;
        md += `- **Findings:** ${riskLine || 'None'}\n\n`;
        if (r.summary) md += `## Summary\n\n${r.summary}\n\n`;
        if (findings.length) {
            md += `## Findings\n\n`;
            const sorted = [...findings].sort((a, b) =>
                (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
            sorted.forEach((f, i) => {
                const risk = (f.risk || 'INFO').toUpperCase();
                md += `### ${i + 1}. [${risk}] ${f.title || 'Untitled'}\n\n`;
                if (f.method || f.path || f.endpoint) md += `**Endpoint:** \`${f.method || ''} ${f.path || f.endpoint || ''}\`\n\n`;
                if (f.category) md += `**Category:** ${f.category}\n\n`;
                if (f.description) md += `**Description:** ${f.description}\n\n`;
                if (f.evidence) md += `**Evidence:** ${f.evidence}\n\n`;
                if (f.recommendation) md += `**Recommendation:** ${f.recommendation}\n\n`;
                md += `---\n\n`;
            });
        }
        return md;
    }

    function _renderResults(results) {
        _lastResults = results;
        if (!results || !results.length) {
            resultsEl.innerHTML =
                '<p class="placeholder-text" style="padding:20px;text-align:center">No analysis results yet. Click Preview, then Analyze to scan your captured traffic.</p>';
            _updateExportToolbar();
            return;
        }

        const totalFindings = results.reduce((s, r) => s + (r.findings || []).length, 0);

        let toolbarHtml = `<div class="ai-copy-toolbar">
<span class="ai-copy-toolbar-label">${totalFindings} finding${totalFindings !== 1 ? 's' : ''}</span>
<button class="btn-small ai-copy-btn" data-copy="text" data-label="Copy All as Text">Copy All as Text</button>
<button class="btn-small ai-copy-btn" data-copy="json" data-label="Copy as JSON">Copy as JSON</button>
<button class="btn-small ai-copy-btn" data-copy="markdown" data-label="Copy as Markdown">Copy as Markdown</button>
<button class="btn-small ai-copy-btn" data-copy="download" data-label="Download .md">Download .md</button>
</div>`;

        let cardsHtml = results.map((r, idx) => {
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

            const sortedFindings = findings
                .sort((a, b) => (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) - (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));

            let findingsHtml = '';
            if (sortedFindings.length) {
                findingsHtml = _findingsTableHead() + sortedFindings.map(f => _renderFindingRow(f)).join('') + _findingsTableFoot();
            } else {
                findingsHtml = '<p class="placeholder-text">No findings</p>';
            }

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
<div class="ai-findings">${findingsHtml}</div>
</div>
</div>`;
        }).join('');

        resultsEl.innerHTML = toolbarHtml + cardsHtml;

        // Bind inline copy toolbar buttons
        resultsEl.querySelectorAll('.ai-copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.copy;
                if (action === 'text') _copyWithFeedback(btn, _generatePlainText(_lastResults));
                else if (action === 'json') _copyWithFeedback(btn, JSON.stringify(_lastResults, null, 2));
                else if (action === 'markdown') _copyWithFeedback(btn, _buildAllMarkdown());
                else if (action === 'download') _downloadFile(_buildAllMarkdown(), 'ai-analysis.md', 'text/markdown');
            });
        });

        _updateExportToolbar();

        // Toggle collapse on card headers
        resultsEl.querySelectorAll('.ai-result-header').forEach(hdr => {
            hdr.addEventListener('click', () => {
                const card = hdr.closest('.ai-result-card');
                card.classList.toggle('collapsed');
            });
        });

        // Toggle finding details (table rows)
        resultsEl.querySelectorAll('tr.finding-row').forEach(row => {
            row.addEventListener('click', () => {
                const detailRow = row.nextElementSibling;
                if (detailRow && detailRow.classList.contains('finding-detail-row')) {
                    const isOpen = detailRow.classList.toggle('visible');
                    row.classList.toggle('expanded', isOpen);
                }
            });
        });

        // Right-click context menu (export / delete)
        resultsEl.querySelectorAll('.ai-result-card').forEach(card => {
            card.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const id = card.dataset.id;
                const idx = card.dataset.idx;
                if (!id || idx == null) return;
                _showCardMenu(e.clientX, e.clientY, Number(id), card, results[Number(idx)]);
            });
        });
    }

    function _showCardMenu(x, y, resultId, cardEl, resultData) {
        _removeDeleteMenu();
        const menu = document.createElement('div');
        menu.className = 'ctx-menu ai-ctx-menu';
        menu.innerHTML = `<div class="ctx-menu-item" data-action="export">Export as Markdown</div>
<div class="ctx-menu-item ctx-menu-item--danger" data-action="delete">Delete Analysis</div>`;
        menu.style.left = x + 'px';
        menu.style.top = y + 'px';
        document.body.appendChild(menu);

        menu.querySelector('[data-action="export"]').addEventListener('click', () => {
            _removeDeleteMenu();
            _exportAsMarkdown(resultData);
        });

        menu.querySelector('[data-action="delete"]').addEventListener('click', async () => {
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

    function _exportAsMarkdown(r) {
        const findings = r.findings || [];
        const modelLabel = (r.model || 'opus').charAt(0).toUpperCase() + (r.model || 'opus').slice(1);
        const time = _fmtTime(r.created_at);
        const hostLabel = r.host_filter || 'All traffic';

        const riskCounts = {};
        findings.forEach(f => {
            const risk = (f.risk || 'info').toLowerCase();
            riskCounts[risk] = (riskCounts[risk] || 0) + 1;
        });
        const riskLine = Object.entries(riskCounts)
            .sort((a, b) => (RISK_ORDER[a[0]] || 9) - (RISK_ORDER[b[0]] || 9))
            .map(([risk, count]) => `${count} ${risk.toUpperCase()}`)
            .join(' | ');

        let md = `# AI Security Analysis\n\n`;
        md += `- **Model:** Claude ${modelLabel}\n`;
        md += `- **Date:** ${time}\n`;
        md += `- **Endpoints analyzed:** ${r.endpoint_count || 0}\n`;
        md += `- **Host filter:** ${hostLabel}\n`;
        md += `- **Findings:** ${riskLine || 'None'}\n\n`;

        if (r.summary) {
            md += `## Summary\n\n${r.summary}\n\n`;
        }

        if (findings.length) {
            md += `## Findings\n\n`;
            const sorted = [...findings].sort((a, b) =>
                (RISK_ORDER[(a.risk || 'info').toLowerCase()] || 9) -
                (RISK_ORDER[(b.risk || 'info').toLowerCase()] || 9));
            sorted.forEach((f, i) => {
                const risk = (f.risk || 'INFO').toUpperCase();
                md += `### ${i + 1}. [${risk}] ${f.title || 'Untitled'}\n\n`;
                if (f.method || f.path || f.endpoint) {
                    md += `**Endpoint:** \`${f.method || ''} ${f.path || f.endpoint || ''}\`\n\n`;
                }
                if (f.category) md += `**Category:** ${f.category}\n\n`;
                if (f.description) md += `**Description:** ${f.description}\n\n`;
                if (f.evidence) md += `**Evidence:** ${f.evidence}\n\n`;
                if (f.recommendation) md += `**Recommendation:** ${f.recommendation}\n\n`;
                md += `---\n\n`;
            });
        }

        md += `*Generated by Endpoint Security Tool — AI Analysis*\n`;

        // Trigger download
        const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const safeName = (r.host_filter || 'all').replace(/[^a-zA-Z0-9.-]/g, '_');
        a.download = `ai-analysis_${safeName}_${(r.model || 'opus')}_${new Date(r.created_at).toISOString().slice(0, 10)}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
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
        _lastResults = null;
        if (resultsEl) resultsEl.innerHTML = '';
        if (progressEl) { progressEl.innerHTML = ''; progressEl.classList.add('hidden'); }
        if (previewInfoEl) previewInfoEl.textContent = '';
        if (hostFilterEl) hostFilterEl.innerHTML = '<option value="">All traffic</option>';
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        if (analyzeBtn) { analyzeBtn.disabled = false; analyzeBtn.textContent = 'Analyze'; }
        if (exportToolbar) exportToolbar.classList.add('hidden');
        _clearAuthContext();
    }

    /** Clear all results */
    async function clearHistory() {
        try { await fetch(`${API}/ai/results`, { method: 'DELETE' }); } catch (_) {}
        _lastResults = null;
        if (resultsEl) resultsEl.innerHTML = '';
        _updateExportToolbar();
    }

    return { init, refresh, loadHistory, clearHistory };
})();
