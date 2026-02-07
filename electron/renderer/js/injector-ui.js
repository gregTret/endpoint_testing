/**
 * InjectorUI — injection scan configuration and results display
 */
window.InjectorUI = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let scanBtn, resultsEl;
    let urlEl, methodEl, typeEl, paramsEl, headersEl, bodyEl;
    let scanPollTimer = null;
    let currentScanId = null;

    let keyPickerGroup, keyPickerEl;

    function init() {
        urlEl      = document.getElementById('inject-url');
        methodEl   = document.getElementById('inject-method');
        typeEl     = document.getElementById('inject-type');
        paramsEl   = document.getElementById('inject-params');
        headersEl  = document.getElementById('inject-headers');
        bodyEl     = document.getElementById('inject-body');
        scanBtn    = document.getElementById('btn-start-scan');
        resultsEl  = document.getElementById('scan-results');
        keyPickerGroup = document.getElementById('key-picker-group');
        keyPickerEl    = document.getElementById('key-picker');

        scanBtn.addEventListener('click', startScan);

        // Refresh key picker whenever params, headers, or body change
        paramsEl.addEventListener('input', refreshKeyPicker);
        headersEl.addEventListener('input', refreshKeyPicker);
        bodyEl.addEventListener('input', refreshKeyPicker);

        // Refresh key picker when injection-point checkboxes toggle
        document.querySelectorAll('#injection-points input[type="checkbox"]')
            .forEach(cb => cb.addEventListener('change', refreshKeyPicker));
    }

    /** Populate the form from a log entry (called when user wants to scan a logged request) */
    function loadFromLog(entry) {
        if (!entry) return;
        urlEl.value = entry.url || '';
        methodEl.value = entry.method || 'GET';

        // Try to extract query params as JSON
        try {
            const u = new URL(entry.url);
            const params = {};
            u.searchParams.forEach((v, k) => { params[k] = v; });
            paramsEl.value = Object.keys(params).length ? JSON.stringify(params, null, 2) : '';
        } catch (_) {
            paramsEl.value = '';
        }

        headersEl.value = entry.request_headers
            ? JSON.stringify(entry.request_headers, null, 2) : '';
        bodyEl.value = entry.request_body || '';
        refreshKeyPicker();
    }

    async function startScan() {
        const points = [];
        document.querySelectorAll('#injection-points input:checked')
            .forEach(cb => points.push(cb.value));

        let params = {};
        try { params = paramsEl.value ? JSON.parse(paramsEl.value) : {}; } catch (_) {}

        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        // Collect selected target keys from the picker
        const targetKeys = [];
        keyPickerEl.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
            targetKeys.push(cb.dataset.key);
        });

        const config = {
            target_url: urlEl.value,
            method: methodEl.value,
            injector_type: typeEl.value,
            params,
            headers,
            body: bodyEl.value,
            injection_points: points.length ? points : ['params'],
            target_keys: targetKeys,
            timeout: 10.0,
        };

        if (!config.target_url) { alert('Enter a target URL'); return; }

        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
        resultsEl.innerHTML = '<p class="placeholder-text">Scan in progress...</p>';

        try {
            const resp = await fetch(`${API}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });
            const data = await resp.json();
            currentScanId = data.scan_id;
            pollResults();
        } catch (e) {
            resultsEl.innerHTML = `<p class="placeholder-text">Error: ${e.message}</p>`;
            scanBtn.disabled = false;
            scanBtn.textContent = 'Launch Scan';
        }
    }

    function pollResults() {
        if (scanPollTimer) clearInterval(scanPollTimer);

        const pollingScanId = currentScanId;

        scanPollTimer = setInterval(async () => {
            try {
                // Check if scan is still running
                const statusRes = await fetch(`${API}/scan/status`);
                const status = await statusRes.json();

                // Make sure we're still tracking the same scan
                if (status.scan_id !== pollingScanId) return;

                // Update progress text
                if (status.running) {
                    scanBtn.textContent = `Scanning... (${status.completed}/${status.total})`;
                }

                // Fetch results scoped to this scan
                const res = await fetch(`${API}/scan/results?session_id=${pollingScanId}&limit=500`);
                const data = await res.json();
                renderResults(data);

                // Stop polling only when backend says scan is done
                if (!status.running) {
                    clearInterval(scanPollTimer);
                    scanPollTimer = null;
                    scanBtn.disabled = false;
                    scanBtn.textContent = 'Launch Scan';

                    if (status.error) {
                        resultsEl.innerHTML += `<p class="placeholder-text" style="color:var(--danger);padding:8px 10px">Scan error: ${esc(status.error)}</p>`;
                    }
                }
            } catch (_) {}
        }, 2000);
    }

    let lastResults = [];
    let activeFilter = 'all';

    function renderResults(results) {
        if (results !== lastResults) {
            lastResults = results;
        }
        if (!lastResults.length) {
            resultsEl.innerHTML = '<p class="placeholder-text">No results yet</p>';
            return;
        }

        const vulns = lastResults.filter(r => r.is_vulnerable);
        const safe  = lastResults.filter(r => !r.is_vulnerable);

        const btnCls = (f) => `scan-filter-btn${activeFilter === f ? ' active' : ''}`;
        const summary = `<div class="scan-summary">
            <span>${lastResults.length} tests | <span style="color:var(--danger)">${vulns.length} vulns</span></span>
            <span class="scan-filters">
                <button class="${btnCls('all')}" data-filter="all">All (${lastResults.length})</button>
                <button class="${btnCls('vuln')}" data-filter="vuln">Vulnerable (${vulns.length})</button>
                <button class="${btnCls('safe')}" data-filter="safe">Safe (${safe.length})</button>
            </span>
        </div>`;

        const filtered = activeFilter === 'vuln' ? vulns
                       : activeFilter === 'safe' ? safe
                       : lastResults;

        const rows = filtered.map(r => {
            const cls = r.is_vulnerable ? 'scan-vuln' : 'scan-safe';
            const confCls = `confidence-${r.confidence}`;
            return `<div class="scan-entry ${cls}">
                <div class="scan-header">
                    <span class="scan-payload" title="${esc(r.payload)}">${esc(r.payload)}</span>
                    <span class="scan-badge">[${esc(r.injection_point)}] ${esc(r.original_param)}</span>
                    <span class="scan-badge">${r.response_code}</span>
                    <span class="scan-badge">${r.response_time_ms}ms</span>
                    <span class="scan-confidence ${confCls}">${r.is_vulnerable ? r.confidence : 'safe'}</span>
                </div>
                <div class="scan-details">${esc(r.details)}</div>
                <div class="scan-response-toggle">▸ Show Details</div>
                <div class="scan-response hidden">
                    <div class="scan-detail-row"><strong>URL:</strong> ${esc(r.target_url)}</div>
                    <div class="scan-detail-row"><strong>Point:</strong> [${esc(r.injection_point)}] ${esc(r.original_param)}</div>
                    <div class="scan-detail-row"><strong>Payload:</strong> ${esc(r.payload)}</div>
                    <div class="scan-detail-row"><strong>Status:</strong> ${r.response_code} &nbsp; <strong>Time:</strong> ${r.response_time_ms}ms</div>
                    <div class="scan-detail-row"><strong>Response Body:</strong></div>
                    <pre class="scan-response-body">${esc(r.response_body || '(empty)')}</pre>
                </div>
            </div>`;
        }).join('');

        resultsEl.innerHTML = summary + (filtered.length ? rows : '<p class="placeholder-text">No matching results</p>');

        // Filter buttons
        resultsEl.querySelectorAll('.scan-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                activeFilter = btn.dataset.filter;
                renderResults(lastResults);
            });
        });

        // Expand/collapse details
        resultsEl.querySelectorAll('.scan-response-toggle').forEach(toggle => {
            toggle.addEventListener('click', () => {
                const detail = toggle.nextElementSibling;
                const open = !detail.classList.contains('hidden');
                detail.classList.toggle('hidden');
                toggle.textContent = open ? '▸ Show Details' : '▾ Hide Details';
            });
        });
    }

    // ── Key Picker ─────────────────────────────────────────────

    function refreshKeyPicker() {
        // Determine which injection points are checked
        const active = new Set();
        document.querySelectorAll('#injection-points input[type="checkbox"]:checked')
            .forEach(cb => active.add(cb.value));

        // Remember previous selections so toggling a checkbox doesn't reset choices
        const prev = new Set();
        keyPickerEl.querySelectorAll('input[type="checkbox"]:checked').forEach(c => prev.add(c.dataset.source + ':' + c.dataset.key));

        const keys = [];

        // Params — only if "params" checked
        if (active.has('params')) {
            try {
                const p = paramsEl.value ? JSON.parse(paramsEl.value) : {};
                Object.keys(p).forEach(k => keys.push({ source: 'param', key: k }));
            } catch (_) {}
        }

        // Headers — only if "headers" checked
        if (active.has('headers')) {
            const skip = new Set(['host', 'content-type', 'content-length', 'transfer-encoding']);
            try {
                const h = headersEl.value ? JSON.parse(headersEl.value) : {};
                Object.keys(h).forEach(k => {
                    if (!skip.has(k.toLowerCase())) keys.push({ source: 'header', key: k });
                });
            } catch (_) {}
        }

        // Body — only if "body" checked
        if (active.has('body') && bodyEl.value.trim()) {
            let parsed = false;
            try {
                const b = JSON.parse(bodyEl.value);
                if (b && typeof b === 'object' && !Array.isArray(b)) {
                    walkKeys(b, '', keys);
                    parsed = true;
                }
            } catch (_) {}
            // Non-JSON or non-object body → offer the whole body as a single target
            if (!parsed) {
                keys.push({ source: 'body', key: 'body' });
            }
        }

        if (keys.length === 0) {
            keyPickerGroup.style.display = 'none';
            keyPickerEl.innerHTML = '';
            return;
        }

        keyPickerGroup.style.display = '';
        const isFirstRender = prev.size === 0;
        keyPickerEl.innerHTML = keys.map(({ source, key }) => {
            const tag = source === 'param' ? 'P' : source === 'header' ? 'H' : 'B';
            const id = source + ':' + key;
            const checked = isFirstRender || prev.has(id) ? 'checked' : '';
            return `<label><input type="checkbox" data-key="${esc(key)}" data-source="${source}" ${checked}> [${tag}] ${esc(key)}</label>`;
        }).join(' ');
    }

    function walkKeys(obj, prefix, out) {
        for (const [k, v] of Object.entries(obj)) {
            const path = prefix ? `${prefix}.${k}` : k;
            if (v && typeof v === 'object' && !Array.isArray(v)) {
                walkKeys(v, path, out);
            } else {
                out.push({ source: 'body', key: path });
            }
        }
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    return { init, loadFromLog };
})();
