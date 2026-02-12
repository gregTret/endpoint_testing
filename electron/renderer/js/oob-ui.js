/**
 * OobUI — dedicated OOB (blind) scan tab with manual callback checking
 */
window.OobUI = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let scanBtn, checkBtn, pauseBtn, stopBtn, resultsEl;
    let urlEl, methodEl, paramsEl, headersEl, bodyEl;
    let scanPollTimer = null;
    let currentScanId = null;

    let keyPickerGroup, keyPickerEl;
    let scanToolbar, textFilterEl;
    let textFilter = '';
    let registryInfoEl;

    let recheckTimer = null;
    let recheckBannerEl = null;

    function init() {
        urlEl      = document.getElementById('oob-url');
        methodEl   = document.getElementById('oob-method');
        paramsEl   = document.getElementById('oob-params');
        headersEl  = document.getElementById('oob-headers');
        bodyEl     = document.getElementById('oob-body');
        scanBtn    = document.getElementById('btn-oob-scan');
        checkBtn   = document.getElementById('btn-oob-check');
        pauseBtn   = document.getElementById('btn-oob-pause');
        stopBtn    = document.getElementById('btn-oob-stop');
        resultsEl  = document.getElementById('oob-results');
        keyPickerGroup = document.getElementById('oob-key-picker-group');
        keyPickerEl    = document.getElementById('oob-key-picker');
        scanToolbar    = document.getElementById('oob-results-toolbar');
        textFilterEl   = document.getElementById('oob-text-filter');
        registryInfoEl = document.getElementById('oob-registry-info');

        scanBtn.addEventListener('click', startScan);
        checkBtn.addEventListener('click', checkCallbacks);
        pauseBtn.addEventListener('click', togglePause);
        stopBtn.addEventListener('click', stopScan);

        textFilterEl.addEventListener('input', () => {
            textFilter = textFilterEl.value.toLowerCase();
            renderResults(lastResults);
        });

        // Refresh key picker on input changes
        urlEl.addEventListener('input', refreshKeyPicker);
        paramsEl.addEventListener('input', refreshKeyPicker);
        headersEl.addEventListener('input', refreshKeyPicker);
        bodyEl.addEventListener('input', refreshKeyPicker);
        document.querySelectorAll('#oob-injection-points input[type="checkbox"]')
            .forEach(cb => cb.addEventListener('change', refreshKeyPicker));

        // Select All / Deselect All for OOB key picker
        document.getElementById('btn-oob-key-select-all').addEventListener('click', () => {
            keyPickerEl.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
        });
        document.getElementById('btn-oob-key-deselect-all').addEventListener('click', () => {
            keyPickerEl.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        });

        // Recheck banner
        recheckBannerEl = document.createElement('div');
        recheckBannerEl.className = 'oob-recheck-banner hidden';
        resultsEl.parentNode.insertBefore(recheckBannerEl, resultsEl);

        loadHistory();

        SendTo.register('oob', {
            label: 'OOB',
            receive(data) { loadFromLog(data); },
        });
    }

    async function loadHistory() {
        stopRecheckPoll();
        textFilter = '';
        if (textFilterEl) textFilterEl.value = '';
        lastResults = [];
        activeFilter = 'all';
        expandedSet.clear();

        if (urlEl) urlEl.value = '';
        if (methodEl) methodEl.value = 'GET';
        if (paramsEl) paramsEl.value = '';
        if (headersEl) headersEl.value = '';
        if (bodyEl) bodyEl.value = '';
        if (keyPickerGroup) keyPickerGroup.style.display = 'none';
        if (keyPickerEl) keyPickerEl.innerHTML = '';
        if (scanToolbar) scanToolbar.classList.add('hidden');

        try {
            const res = await fetch(`${API}/oob/results`);
            const data = await res.json();
            lastResults = data;
            renderResults(lastResults);
        } catch (_) {
            renderResults([]);
        }
        refreshRegistryInfo();
    }

    function loadFromLog(entry) {
        if (!entry) return;
        urlEl.value = entry.url || '';
        methodEl.value = entry.method || 'GET';
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

    // ── Scan ─────────────────────────────────────────────────

    async function startScan() {
        stopRecheckPoll();

        const points = [];
        document.querySelectorAll('#oob-injection-points input:checked')
            .forEach(cb => points.push(cb.value));

        let params = {};
        try { params = paramsEl.value ? JSON.parse(paramsEl.value) : {}; } catch (_) {}

        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        const targetKeys = [];
        keyPickerEl.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
            targetKeys.push(cb.dataset.key);
        });

        const config = {
            target_url: urlEl.value,
            method: methodEl.value,
            injector_type: 'oob',
            params,
            headers,
            body: bodyEl.value,
            injection_points: points.length ? points : ['params'],
            target_keys: targetKeys.length ? targetKeys : null,
            timeout: 10.0,
        };

        if (!config.target_url) { alert('Enter a target URL'); return; }

        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
        checkBtn.disabled = true;
        pauseBtn.classList.remove('hidden');
        stopBtn.classList.remove('hidden');
        pauseBtn.textContent = 'Pause';
        resultsEl.innerHTML = '<p class="placeholder-text">OOB scan in progress...</p>';

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
            scanBtn.textContent = 'Launch OOB Scan';
            checkBtn.disabled = false;
        }
    }

    function pollResults() {
        if (scanPollTimer) clearInterval(scanPollTimer);
        const pollingScanId = currentScanId;

        scanPollTimer = setInterval(async () => {
            try {
                const statusRes = await fetch(`${API}/scan/status`);
                const status = await statusRes.json();
                if (status.scan_id !== pollingScanId) return;

                const paused = status.running && status.control === 'pause';
                if (status.running) {
                    const prefix = paused ? 'Paused' : 'Scanning...';
                    scanBtn.textContent = `${prefix} (${status.completed}/${status.total})`;
                }
                if (paused) return;

                const res = await fetch(`${API}/scan/results?session_id=${pollingScanId}&limit=500`);
                const data = await res.json();
                renderResults(data);

                if (!status.running) {
                    clearInterval(scanPollTimer);
                    scanPollTimer = null;
                    scanBtn.disabled = false;
                    scanBtn.textContent = 'Launch OOB Scan';
                    checkBtn.disabled = false;
                    pauseBtn.classList.add('hidden');
                    stopBtn.classList.add('hidden');
                    refreshRegistryInfo();

                    if (status.error) {
                        resultsEl.innerHTML += `<p class="placeholder-text" style="color:var(--danger);padding:8px 10px">Scan error: ${esc(status.error)}</p>`;
                    }

                    if (status.oob_recheck) {
                        startRecheckPoll(pollingScanId);
                    }
                }
            } catch (_) {}
        }, 2000);
    }

    async function togglePause() {
        try {
            const res = await fetch(`${API}/scan/pause`, { method: 'POST' });
            const data = await res.json();
            pauseBtn.textContent = data.signal === 'pause' ? 'Resume' : 'Pause';
        } catch (_) {}
    }

    async function stopScan() {
        try { await fetch(`${API}/scan/stop`, { method: 'POST' }); } catch (_) {}
    }

    // ── Manual Check ─────────────────────────────────────────

    async function checkCallbacks() {
        checkBtn.disabled = true;
        checkBtn.textContent = 'Checking...';
        try {
            const res = await fetch(`${API}/oob/check`, { method: 'POST' });
            const data = await res.json();

            // Refresh results
            const resultsRes = await fetch(`${API}/oob/results`);
            const resultsData = await resultsRes.json();
            renderResults(resultsData);

            if (data.found > 0) {
                checkBtn.textContent = `Found ${data.found} callback${data.found !== 1 ? 's' : ''}!`;
                checkBtn.style.borderColor = 'var(--danger)';
                setTimeout(() => {
                    checkBtn.textContent = 'Check Callbacks';
                    checkBtn.style.borderColor = '';
                }, 4000);
            } else {
                checkBtn.textContent = `Checked ${data.checked} scan${data.checked !== 1 ? 's' : ''} — none found`;
                setTimeout(() => { checkBtn.textContent = 'Check Callbacks'; }, 3000);
            }
        } catch (e) {
            checkBtn.textContent = 'Check failed';
            setTimeout(() => { checkBtn.textContent = 'Check Callbacks'; }, 3000);
        }
        checkBtn.disabled = false;
    }

    // ── Recheck Polling ──────────────────────────────────────

    function startRecheckPoll(scanId) {
        stopRecheckPoll();
        recheckBannerEl.classList.remove('hidden');
        recheckBannerEl.innerHTML =
            '<span class="oob-recheck-dot"></span>' +
            '<span class="oob-recheck-text">OOB recheck active &mdash; monitoring for delayed callbacks...</span>';

        recheckTimer = setInterval(async () => {
            try {
                const statusRes = await fetch(`${API}/oob/status`);
                const status = await statusRes.json();

                // Refresh results
                const res = await fetch(`${API}/oob/results`);
                const data = await res.json();
                renderResults(data);

                if (status.recheck_active) {
                    const mins = Math.floor(status.recheck_remaining / 60);
                    const secs = status.recheck_remaining % 60;
                    const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
                    const foundStr = status.recheck_found > 0
                        ? ` | <strong style="color:var(--danger)">${status.recheck_found} delayed callback${status.recheck_found !== 1 ? 's' : ''} found</strong>`
                        : '';
                    recheckBannerEl.innerHTML =
                        '<span class="oob-recheck-dot"></span>' +
                        `<span class="oob-recheck-text">OOB recheck active &mdash; monitoring for delayed callbacks (${timeStr} remaining)${foundStr}</span>`;
                } else {
                    const finalRes = await fetch(`${API}/oob/results`);
                    const finalData = await finalRes.json();
                    renderResults(finalData);

                    const foundStr = status.recheck_found > 0
                        ? ` &mdash; ${status.recheck_found} delayed callback${status.recheck_found !== 1 ? 's' : ''} found`
                        : ' &mdash; no delayed callbacks';
                    recheckBannerEl.innerHTML =
                        '<span class="oob-recheck-dot oob-recheck-done"></span>' +
                        `<span class="oob-recheck-text">OOB recheck complete${foundStr}</span>`;

                    clearInterval(recheckTimer);
                    recheckTimer = null;
                    setTimeout(() => { recheckBannerEl.classList.add('hidden'); }, 30000);
                }
            } catch (_) {}
        }, 15000);
    }

    function stopRecheckPoll() {
        if (recheckTimer) { clearInterval(recheckTimer); recheckTimer = null; }
        if (recheckBannerEl) recheckBannerEl.classList.add('hidden');
    }

    // ── Registry Info ────────────────────────────────────────

    async function refreshRegistryInfo() {
        try {
            const res = await fetch(`${API}/oob/status`);
            const data = await res.json();
            if (registryInfoEl) {
                registryInfoEl.textContent = `${data.registry_count} scan${data.registry_count !== 1 ? 's' : ''} registered`;
            }
        } catch (_) {}
    }

    // ── Results ──────────────────────────────────────────────

    let lastResults = [];
    let activeFilter = 'all';
    const expandedSet = new Set();

    function getVisibleResults() {
        let results = lastResults;
        if (activeFilter === 'vuln') results = results.filter(r => r.is_vulnerable);
        else if (activeFilter === 'safe') results = results.filter(r => !r.is_vulnerable);

        if (textFilter) {
            results = results.filter(r => {
                const haystack = [
                    r.payload, r.original_param, r.target_url,
                    r.details, r.injection_point, r.injector_type,
                ].join(' ').toLowerCase();
                return haystack.includes(textFilter);
            });
        }
        return results;
    }

    function renderResults(results) {
        if (results !== lastResults) lastResults = results;
        if (scanToolbar) scanToolbar.classList.toggle('hidden', !lastResults.length);

        if (!lastResults.length) {
            resultsEl.innerHTML = '<p class="placeholder-text">No OOB results yet</p>';
            return;
        }

        const vulns = lastResults.filter(r => r.is_vulnerable);
        const safe  = lastResults.filter(r => !r.is_vulnerable);
        const filtered = getVisibleResults();

        const btnCls = (f) => `scan-filter-btn${activeFilter === f ? ' active' : ''}`;
        const summary = `<div class="scan-summary">
            <span>${lastResults.length} tests | <span style="color:var(--danger)">${vulns.length} callbacks confirmed</span>${textFilter ? ` | <span style="color:var(--accent)">${filtered.length} matching</span>` : ''}</span>
            <span class="scan-filters">
                <button class="${btnCls('all')}" data-filter="all">All (${lastResults.length})</button>
                <button class="${btnCls('vuln')}" data-filter="vuln">Confirmed (${vulns.length})</button>
                <button class="${btnCls('safe')}" data-filter="safe">Waiting (${safe.length})</button>
            </span>
        </div>`;

        const rows = filtered.map((r, i) => {
            const cls = r.is_vulnerable ? 'scan-vuln' : 'scan-safe';
            const confCls = `confidence-${r.confidence}`;
            const key = r.id || `${r.payload}_${r.original_param}_${i}`;
            const isOpen = expandedSet.has(key);
            const isDelayed = (r.details || '').includes('delayed');
            const confirmedBadge = r.is_vulnerable
                ? `<span class="oob-badge">${isDelayed ? 'Delayed Callback' : 'OOB Confirmed'}</span>`
                : '';
            const typeBadge = `<span class="scan-badge">${esc(r.injector_type)}</span>`;

            return `<div class="scan-entry ${cls}" data-key="${esc(String(key))}">
                <div class="scan-header">
                    <span class="scan-payload" title="${esc(r.payload)}">${esc(r.payload)}</span>
                    ${confirmedBadge}
                    ${typeBadge}
                    <span class="scan-badge">[${esc(r.injection_point)}] ${esc(r.original_param)}</span>
                    <span class="scan-confidence ${confCls}">${r.is_vulnerable ? r.confidence : 'waiting'}</span>
                </div>
                <div class="scan-details">${esc(r.details)}</div>
                <div class="scan-response-toggle">${isOpen ? '\u25be Hide Details' : '\u25b8 Show Details'}</div>
                <div class="scan-response ${isOpen ? '' : 'hidden'}">
                    <div class="scan-detail-row"><strong>URL:</strong> ${esc(r.target_url)}</div>
                    <div class="scan-detail-row"><strong>Point:</strong> [${esc(r.injection_point)}] ${esc(r.original_param)}</div>
                    <div class="scan-detail-row"><strong>Payload:</strong> ${esc(r.payload)}</div>
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

        // Expand/collapse
        resultsEl.querySelectorAll('.scan-response-toggle').forEach(toggle => {
            toggle.addEventListener('click', () => {
                const entry = toggle.closest('.scan-entry');
                const key = entry.dataset.key;
                const detail = toggle.nextElementSibling;
                const open = !detail.classList.contains('hidden');
                detail.classList.toggle('hidden');
                toggle.textContent = open ? '\u25b8 Show Details' : '\u25be Hide Details';
                if (open) { expandedSet.delete(key); } else { expandedSet.add(key); }
            });
        });
    }

    // ── Key Picker ───────────────────────────────────────────

    function refreshKeyPicker() {
        const active = new Set();
        document.querySelectorAll('#oob-injection-points input[type="checkbox"]:checked')
            .forEach(cb => active.add(cb.value));

        const prev = new Set();
        keyPickerEl.querySelectorAll('input[type="checkbox"]:checked')
            .forEach(c => prev.add(c.dataset.source + ':' + c.dataset.key));

        const keys = [];

        if (active.has('paths') && urlEl.value) {
            try {
                const u = new URL(urlEl.value);
                u.pathname.split('/').filter(Boolean).forEach(seg =>
                    keys.push({ source: 'path', key: '/' + seg }));
            } catch (_) {}
        }

        if (active.has('params')) {
            try {
                const p = paramsEl.value ? JSON.parse(paramsEl.value) : {};
                Object.keys(p).forEach(k => keys.push({ source: 'param', key: k }));
            } catch (_) {}
        }

        if (active.has('headers')) {
            const skip = new Set(['host', 'content-type', 'content-length', 'transfer-encoding']);
            try {
                const h = headersEl.value ? JSON.parse(headersEl.value) : {};
                Object.keys(h).forEach(k => {
                    if (!skip.has(k.toLowerCase())) keys.push({ source: 'header', key: k });
                });
            } catch (_) {}
        }

        if (active.has('body') && bodyEl.value.trim()) {
            let parsed = false;
            try {
                const b = JSON.parse(bodyEl.value);
                if (b && typeof b === 'object' && !Array.isArray(b)) {
                    _walkKeys(b, '', keys);
                    parsed = true;
                }
            } catch (_) {}
            if (!parsed) keys.push({ source: 'body', key: 'body' });
        }

        if (!keys.length) {
            keyPickerGroup.style.display = 'none';
            keyPickerEl.innerHTML = '';
            return;
        }

        keyPickerGroup.style.display = '';
        const isFirstRender = prev.size === 0;

        const AUTH_KEYS = new Set([
            'jwt', 'token', 'idtoken', 'id_token', 'access_token',
            'accesstoken', 'refresh_token', 'refreshtoken', 'auth',
            'authorization', 'auth_token', 'password', 'secret',
            'api_key', 'apikey', 'session', 'session_token', 'csrf',
            'csrftoken', 'csrf_token', 'x-csrf-token',
        ]);

        const grouped = {};
        keys.forEach(({ source, key }) => {
            if (!grouped[source]) grouped[source] = [];
            grouped[source].push(key);
        });

        const sourceLabels = { path: 'Paths', param: 'Params', header: 'Headers', body: 'Body' };
        let html = '<table><thead><tr><th></th><th>Source</th><th>Key</th></tr></thead><tbody>';
        for (const [source, sourceKeys] of Object.entries(grouped)) {
            sourceKeys.forEach((key, i) => {
                const id = source + ':' + key;
                const leafKey = key.includes('.') ? key.split('.').pop() : key;
                const isAuth = AUTH_KEYS.has(leafKey.toLowerCase());
                const checked = isFirstRender
                    ? (isAuth ? '' : 'checked')
                    : (prev.has(id) ? 'checked' : '');
                const label = i === 0 ? `<span class="key-picker-source">${sourceLabels[source] || source}</span>` : '';
                html += `<tr><td><input type="checkbox" data-key="${esc(key)}" data-source="${source}" ${checked}></td><td>${label}</td><td class="key-picker-key">${esc(key)}</td></tr>`;
            });
        }
        html += '</tbody></table>';
        keyPickerEl.innerHTML = html;

        keyPickerEl.querySelectorAll('tr').forEach(row => {
            const cb = row.querySelector('input[type="checkbox"]');
            if (!cb) return;
            row.style.cursor = 'pointer';
            row.addEventListener('click', (e) => {
                if (e.target === cb) return;
                cb.checked = !cb.checked;
            });
        });
    }

    function _walkKeys(obj, prefix, out) {
        for (const [k, v] of Object.entries(obj)) {
            const path = prefix ? `${prefix}.${k}` : k;
            if (v && typeof v === 'object' && !Array.isArray(v)) {
                _walkKeys(v, path, out);
            } else {
                out.push({ source: 'body', key: path });
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    async function clearHistory() {
        try { await fetch(`${API}/oob/results`, { method: 'DELETE' }); } catch (_) {}
        lastResults = [];
        expandedSet.clear();
        resultsEl.innerHTML = '<p class="placeholder-text">No OOB results yet</p>';
    }

    async function clearRegistry() {
        try { await fetch(`${API}/oob/registry`, { method: 'DELETE' }); } catch (_) {}
        refreshRegistryInfo();
    }

    return { init, loadHistory, loadFromLog, clearHistory, clearRegistry };
})();
