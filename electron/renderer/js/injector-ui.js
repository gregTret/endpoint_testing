/**
 * InjectorUI — injection scan configuration and results display
 */
window.InjectorUI = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let scanBtn, pauseBtn, stopBtn, resultsEl;
    let urlEl, methodEl, typeEl, paramsEl, headersEl, bodyEl;
    let scanPollTimer = null;
    let currentScanId = null;

    let keyPickerGroup, keyPickerEl;
    let scanToolbar, textFilterEl, analyzeBtn;
    let textFilter = '';
    let bulkUrlsEl = null;
    let bulkMode = false;

    // Upload scanner state
    let uploadConfigEl, uploadSourceBadge, uploadLogIdEl, uploadCategoriesEl;
    const UPLOAD_CATEGORIES = [
        "Extension Bypass", "MIME Mismatch", "Polyglot", "SVG",
        "SVG (React/Flask)", "Path Traversal", "Filename Injection",
        "Webshell", "Out-of-Band", "Python Execution", "Edge Cases",
    ];

    // ── Debug helper (console only, no overlay) ──
    function _dbg(msg) { console.log(msg); }

    function init() {
        urlEl      = document.getElementById('inject-url');
        methodEl   = document.getElementById('inject-method');
        typeEl     = document.getElementById('inject-type');
        paramsEl   = document.getElementById('inject-params');
        headersEl  = document.getElementById('inject-headers');
        bodyEl     = document.getElementById('inject-body');
        scanBtn    = document.getElementById('btn-start-scan');
        pauseBtn   = document.getElementById('btn-pause-scan');
        stopBtn    = document.getElementById('btn-stop-scan');
        resultsEl  = document.getElementById('scan-results');
        keyPickerGroup = document.getElementById('key-picker-group');
        keyPickerEl    = document.getElementById('key-picker');
        scanToolbar    = document.getElementById('scan-results-toolbar');
        textFilterEl   = document.getElementById('scan-text-filter');
        analyzeBtn     = document.getElementById('btn-analyze-filtered');

        scanBtn.addEventListener('click', startScan);
        pauseBtn.addEventListener('click', togglePause);
        stopBtn.addEventListener('click', stopScan);
        document.getElementById('btn-send-single').addEventListener('click', sendSingle);

        textFilterEl.addEventListener('input', () => {
            textFilter = textFilterEl.value.toLowerCase();
            renderResults(lastResults);
        });

        analyzeBtn.addEventListener('click', () => {
            const visible = getVisibleResults();
            if (!visible.length) { alert('No results to analyze'); return; }
            if (!document.querySelector('#tab-bar .tab[data-tab="analytics"]')) {
                alert('Analytics tab is hidden. Enable it in Settings first.');
                return;
            }
            Analytics.analyzeSubset(visible);
            document.querySelectorAll('#tab-bar .tab').forEach(t =>
                t.classList.toggle('active', t.dataset.tab === 'analytics'));
            document.querySelectorAll('.tab-pane').forEach(p =>
                p.classList.toggle('active', p.dataset.tab === 'analytics'));
        });


        // Refresh key picker whenever URL, params, headers, or body change
        urlEl.addEventListener('input', refreshKeyPicker);
        paramsEl.addEventListener('input', refreshKeyPicker);
        headersEl.addEventListener('input', refreshKeyPicker);
        bodyEl.addEventListener('input', refreshKeyPicker);

        // Refresh key picker when injection-point checkboxes toggle
        document.querySelectorAll('#injection-points input[type="checkbox"]')
            .forEach(cb => cb.addEventListener('change', refreshKeyPicker));

        // Select All / Deselect All for key picker
        document.getElementById('btn-key-select-all').addEventListener('click', () => {
            keyPickerEl.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = true);
        });
        document.getElementById('btn-key-deselect-all').addEventListener('click', () => {
            keyPickerEl.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
        });

        // Paste Raw HTTP — parse clipboard into form fields
        document.getElementById('btn-paste-raw-http').addEventListener('click', async () => {
            let raw;
            try {
                raw = await navigator.clipboard.readText();
            } catch (_) {
                raw = prompt('Paste raw HTTP request:');
            }
            if (!raw) return;
            const parsed = EPTUtils.parseRawHttp(raw);
            if (!parsed) { alert('Could not parse raw HTTP request'); return; }
            urlEl.value = parsed.url || '';
            methodEl.value = parsed.method || 'GET';
            paramsEl.value = Object.keys(parsed.params).length
                ? JSON.stringify(parsed.params, null, 2) : '';
            headersEl.value = Object.keys(parsed.headers).length
                ? JSON.stringify(parsed.headers, null, 2) : '';
            bodyEl.value = parsed.body || '';
            refreshKeyPicker();
        });

        // Bulk URL toggle
        bulkUrlsEl = document.getElementById('inject-bulk-urls');
        document.getElementById('btn-toggle-bulk').addEventListener('click', (e) => {
            bulkMode = !bulkMode;
            document.getElementById('bulk-url-section').classList.toggle('hidden', !bulkMode);
            e.target.textContent = bulkMode ? 'Single URL' : 'Bulk URLs';
        });

        // Load saved scan history for this workspace
        loadHistory();

        SendTo.register('injector', {
            label: 'Injector',
            receive(data) { loadFromLog(data); },
        });

        // ── Upload scanner setup ──────────────────────────────
        uploadConfigEl = document.getElementById('upload-config');
        uploadSourceBadge = document.getElementById('upload-source-badge');
        uploadLogIdEl = document.getElementById('upload-log-id');
        uploadCategoriesEl = document.getElementById('upload-categories');

        // Populate category checkboxes
        uploadCategoriesEl.innerHTML = UPLOAD_CATEGORIES.map(cat =>
            `<label><input type="checkbox" value="${esc(cat)}" checked> ${esc(cat)}</label>`
        ).join('');

        // Show/hide upload config when injector type changes
        typeEl.addEventListener('change', _onTypeChange);

        // Register SendTo target for upload scanner
        SendTo.register('upload-scanner', {
            label: 'Upload Scanner',
            tab: 'injector',
            receive(data) {
                // Accept both multipart uploads and JSON-based upload flows.
                // Use REQUEST content-type from headers (not response content_type).
                const reqHeaders = data.request_headers || data.headers || {};
                const headerCt = Object.entries(reqHeaders).find(
                    ([k]) => k.toLowerCase() === 'content-type'
                );
                const requestCt = headerCt ? headerCt[1].toLowerCase() : '';
                const isMultipart = requestCt.includes('multipart/form-data');
                const isJson = requestCt.includes('json');
                if (!isMultipart && !isJson) {
                    alert('This request is not a file upload (multipart) or upload initiation (JSON). Select an appropriate request.');
                    return;
                }
                // Switch to upload type
                typeEl.value = 'upload';
                _onTypeChange();
                // Set log_id and source badge
                uploadLogIdEl.value = data.id || '';
                const modeLabel = isMultipart ? 'multipart' : 'json flow';
                uploadSourceBadge.innerHTML =
                    `<strong>Source:</strong> ${esc(data.method || 'POST')} ${esc(data.url || '')} ` +
                    `<span style="color:var(--accent)">(Log #${data.id || '?'} — ${modeLabel})</span>`;
                // Also populate the URL field for display
                urlEl.value = data.url || '';
                methodEl.value = data.method || 'POST';
            },
        });
    }

    /** Toggle visibility of upload-specific vs standard fields */
    function _onTypeChange() {
        const isUpload = typeEl.value === 'upload';
        // Hide standard fields when upload is selected
        const standardFields = [
            paramsEl, headersEl, bodyEl,
        ];
        standardFields.forEach(el => {
            if (el) el.closest('.form-group').style.display = isUpload ? 'none' : '';
        });
        // Hide injection points and key picker for upload
        const injPointsGroup = document.getElementById('injection-points')?.closest('.form-group');
        if (injPointsGroup) injPointsGroup.style.display = isUpload ? 'none' : '';
        if (keyPickerGroup) keyPickerGroup.style.display = isUpload ? 'none' : keyPickerGroup.style.display;
        // Show/hide upload config
        if (uploadConfigEl) uploadConfigEl.classList.toggle('hidden', !isUpload);
    }

    async function loadHistory() {
        textFilter = '';
        if (textFilterEl) textFilterEl.value = '';

        // Always reset state so stale data from previous workspace is cleared
        lastResults = [];
        activeFilter = 'all';
        expandedSet.clear();

        // Clear form fields
        if (urlEl) urlEl.value = '';
        if (methodEl) methodEl.value = 'GET';
        if (paramsEl) paramsEl.value = '';
        if (headersEl) headersEl.value = '';
        if (bodyEl) bodyEl.value = '';
        // Clear upload scanner state so stale log_ids don't leak across workspaces
        if (uploadLogIdEl) uploadLogIdEl.value = '';
        if (uploadSourceBadge) uploadSourceBadge.innerHTML =
            'No source request loaded. Right-click a file upload request (multipart or JSON upload initiation) in the Logs tab \u2192 "Send to Upload Scanner".';
        if (bulkUrlsEl) bulkUrlsEl.value = '';
        bulkMode = false;
        const bulkSection = document.getElementById('bulk-url-section');
        if (bulkSection) bulkSection.classList.add('hidden');
        const bulkBtn = document.getElementById('btn-toggle-bulk');
        if (bulkBtn) bulkBtn.textContent = 'Bulk URLs';
        if (keyPickerGroup) keyPickerGroup.style.display = 'none';
        if (keyPickerEl) keyPickerEl.innerHTML = '';
        if (scanToolbar) scanToolbar.classList.add('hidden');

        try {
            _dbg('[loadHistory] fetching...');
            const t0 = performance.now();
            const res = await fetch(`${API}/scan/history`);
            const raw = await res.text();
            _dbg(`[loadHistory] ${(performance.now() - t0).toFixed(0)}ms, ${(raw.length / 1024).toFixed(0)}KB`);
            const data = JSON.parse(raw);
            _dbg(`[loadHistory] ${data.length} results parsed`);
            lastResults = data;
            renderResults(lastResults);
        } catch (err) {
            _dbg(`[loadHistory] ERROR: ${err.message}`);
            renderResults([]);
        }
    }

    /** Send the request exactly as shown in the form — no injection */
    async function sendSingle() {
        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        const payload = {
            url: urlEl.value,
            method: methodEl.value,
            headers,
            body: bodyEl.value,
        };
        if (!payload.url) { alert('Enter a target URL'); return; }

        resultsEl.innerHTML = '<p class="placeholder-text">Sending...</p>';
        try {
            const res = await fetch(`${API}/send`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            resultsEl.innerHTML =
`<div class="scan-entry">
<div class="scan-header">
<span class="scan-badge">${data.status_code}</span>
<span class="scan-payload">${esc(data.request_method || payload.method)} ${esc(payload.url)}</span>
</div>
<div class="scan-detail-row"><strong>Request Headers Sent:</strong></div>
${EPTUtils.headersBlock(data.request_headers || {})}
<div class="scan-detail-row"><strong>Request Body Sent:</strong></div>
${EPTUtils.bodyPreBlock(data.request_body || '')}
<div class="scan-detail-row"><strong>Response Headers:</strong></div>
${EPTUtils.headersBlock(data.headers || {})}
<div class="scan-detail-row"><strong>Response Body:</strong></div>
${EPTUtils.bodyPreBlock(data.body || '')}
</div>`;
        } catch (e) {
            resultsEl.innerHTML = `<p class="placeholder-text" style="color:var(--danger)">Error: ${e.message}</p>`;
        }
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

    /** Build a scan config from the current form state */
    function _buildScanConfig(targetUrl) {
        // Upload scanner uses a different config shape
        if (typeEl.value === 'upload') {
            const logId = parseInt(uploadLogIdEl.value, 10);
            if (!logId) {
                alert('No source request loaded. Right-click a file upload request in the Logs tab → "Send to Upload Scanner".');
                return null;
            }
            const selectedCats = [];
            uploadCategoriesEl.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
                selectedCats.push(cb.value);
            });
            return {
                target_url: targetUrl || urlEl.value || '(upload)',
                method: methodEl.value,
                injector_type: 'upload',
                params: {},
                headers: {},
                body: '',
                injection_points: [],
                target_keys: null,
                timeout: 30.0,
                extra: {
                    log_id: logId,
                    categories: selectedCats.length < UPLOAD_CATEGORIES.length ? selectedCats : null,
                },
            };
        }

        const points = [];
        document.querySelectorAll('#injection-points input:checked')
            .forEach(cb => points.push(cb.value));

        let params = {};
        try { params = paramsEl.value ? JSON.parse(paramsEl.value) : {}; } catch (_) {}

        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        const targetKeys = [];
        keyPickerEl.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
            targetKeys.push(cb.dataset.key);
        });

        return {
            target_url: targetUrl,
            method: methodEl.value,
            injector_type: typeEl.value,
            params,
            headers,
            body: bodyEl.value,
            injection_points: points.length ? points : ['params'],
            target_keys: targetKeys.length ? targetKeys : null,
            timeout: 10.0,
        };
    }

    async function startScan() {
        // Collect URLs — bulk mode or single
        const urls = [];
        if (bulkMode && bulkUrlsEl && bulkUrlsEl.value.trim()) {
            bulkUrlsEl.value.trim().split('\n')
                .map(l => l.trim()).filter(Boolean)
                .forEach(u => urls.push(u));
        }
        if (!urls.length) {
            if (!urlEl.value) { alert('Enter a target URL'); return; }
            urls.push(urlEl.value);
        }

        scanBtn.disabled = true;
        pauseBtn.classList.remove('hidden');
        stopBtn.classList.remove('hidden');
        pauseBtn.textContent = 'Pause';

        // Run scans sequentially for each URL
        for (let idx = 0; idx < urls.length; idx++) {
            const label = urls.length > 1 ? `URL ${idx + 1}/${urls.length}: ` : '';
            scanBtn.textContent = `${label}Scanning...`;
            if (idx === 0) {
                resultsEl.innerHTML = '<p class="placeholder-text">Scan in progress...</p>';
            }

            const config = _buildScanConfig(urls[idx]);
            if (!config) {
                scanBtn.disabled = false;
                scanBtn.textContent = 'Launch Scan';
                pauseBtn.classList.add('hidden');
                stopBtn.classList.add('hidden');
                return;
            }

            try {
                const resp = await fetch(`${API}/scan`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config),
                });
                const data = await resp.json();
                currentScanId = data.scan_id;

                // Wait for this scan to finish before starting next
                await _waitForScanDone(label);
            } catch (e) {
                resultsEl.innerHTML += `<p class="placeholder-text" style="color:var(--danger)">Error on ${esc(urls[idx])}: ${e.message}</p>`;
            }
        }

        scanBtn.disabled = false;
        scanBtn.textContent = 'Launch Scan';
        pauseBtn.classList.add('hidden');
        stopBtn.classList.add('hidden');
    }

    /** Poll until the current scan finishes, updating results along the way */
    function _waitForScanDone(label) {
        return new Promise((resolve) => {
            const pollingScanId = currentScanId;
            const timer = setInterval(async () => {
                try {
                    const statusRes = await fetch(`${API}/scan/status`);
                    const status = await statusRes.json();
                    if (status.scan_id !== pollingScanId) return;

                    const paused = status.running && status.control === 'pause';
                    if (status.running) {
                        const prefix = paused ? 'Paused' : `${label}Scanning...`;
                        scanBtn.textContent = `${prefix} (${status.completed}/${status.total})`;
                    }
                    if (paused) return;

                    const res = await fetch(`${API}/scan/results?session_id=${pollingScanId}&limit=500`);
                    const data = await res.json();
                    renderResults(data);

                    if (!status.running) {
                        clearInterval(timer);
                        if (status.error) {
                            resultsEl.innerHTML += `<p class="placeholder-text" style="color:var(--danger);padding:8px 10px">Scan error: ${esc(status.error)}</p>`;
                        }
                        // Load full workspace history so bulk results accumulate
                        try {
                            const histRes = await fetch(`${API}/scan/history`);
                            const histData = await histRes.json();
                            renderResults(histData);
                        } catch (_) {}
                        resolve();
                    }
                } catch (_) {}
            }, 2000);
        });
    }

    async function togglePause() {
        try {
            const res = await fetch(`${API}/scan/pause`, { method: 'POST' });
            const data = await res.json();
            pauseBtn.textContent = data.signal === 'pause' ? 'Resume' : 'Pause';
        } catch (_) {}
    }

    async function stopScan() {
        try {
            await fetch(`${API}/scan/stop`, { method: 'POST' });
        } catch (_) {}
    }

    let lastResults = [];
    let activeFilter = 'all';
    let renderCap = 50; // only render this many results at a time to prevent freezes
    const expandedSet = new Set(); // track expanded result indices across re-renders

    function getVisibleResults() {
        let results = lastResults;
        if (activeFilter === 'vuln') results = results.filter(r => r.is_vulnerable);
        else if (activeFilter === 'safe') results = results.filter(r => !r.is_vulnerable);

        if (textFilter) {
            results = results.filter(r => {
                const haystack = [
                    r.payload, r.original_param, r.target_url,
                    r.details, r.injection_point, r.injector_type,
                    String(r.response_code),
                ].join(' ').toLowerCase();
                return haystack.includes(textFilter);
            });
        }
        return results;
    }

    function renderResults(results) {
        if (results !== lastResults) {
            // Preserve any lazily-loaded detail data from previous results
            if (lastResults.length && results.length) {
                const oldById = {};
                for (const r of lastResults) {
                    if (r._detailLoaded && r.id) oldById[r.id] = r;
                }
                for (const r of results) {
                    const prev = r.id && oldById[r.id];
                    if (prev) {
                        r._detailLoaded = true;
                        r.response_body = prev.response_body;
                        r.request_headers = prev.request_headers;
                        r.request_body = prev.request_body;
                    }
                }
            }
            lastResults = results;
        }

        if (scanToolbar) scanToolbar.classList.toggle('hidden', !lastResults.length);

        if (!lastResults.length) {
            resultsEl.innerHTML = '<p class="placeholder-text">No results yet</p>';
            return;
        }

        const vulns = lastResults.filter(r => r.is_vulnerable);
        const safe  = lastResults.filter(r => !r.is_vulnerable);
        const filtered = getVisibleResults();

        const btnCls = (f) => `scan-filter-btn${activeFilter === f ? ' active' : ''}`;
        const summary = `<div class="scan-summary">
            <span>${lastResults.length} tests | <span style="color:var(--danger)">${vulns.length} vulns</span>${textFilter ? ` | <span style="color:var(--accent)">${filtered.length} matching</span>` : ''}</span>
            <span class="scan-filters">
                <button class="${btnCls('all')}" data-filter="all">All (${lastResults.length})</button>
                <button class="${btnCls('vuln')}" data-filter="vuln">Vulnerable (${vulns.length})</button>
                <button class="${btnCls('safe')}" data-filter="safe">Safe (${safe.length})</button>
            </span>
        </div>`;

        // Cap rendered items to prevent main-thread freeze
        const capped = filtered.slice(0, renderCap);
        const hasMore = filtered.length > renderCap;

        const rows = capped.map((r, i) => {
            const cls = r.is_vulnerable ? 'scan-vuln' : 'scan-safe';
            const confCls = `confidence-${r.confidence}`;
            const key = r.id || `${r.payload}_${r.original_param}_${i}`;
            const isOpen = expandedSet.has(key);
            const isOob = (r.injector_type || '').startsWith('oob:');
            const oobBadge = isOob && r.is_vulnerable ? '<span class="oob-badge">OOB Confirmed</span>' : '';
            const oobTypeBadge = isOob ? `<span class="scan-badge">${esc(r.injector_type)}</span>` : '';
            const detailContent = isOpen ? _buildDetailHtml(r) : '';
            return `<div class="scan-entry ${cls}" data-key="${esc(String(key))}" data-idx="${i}">` +
`<div class="scan-header">` +
`<span class="scan-payload" title="${esc(r.payload)}">${esc(r.payload)}</span>` +
oobBadge + oobTypeBadge +
`<span class="scan-badge">[${esc(r.injection_point)}] ${esc(r.original_param)}</span>` +
(!isOob ? `<span class="scan-badge">${r.response_code}</span>` : '') +
(!isOob ? `<span class="scan-badge">${r.response_time_ms}ms</span>` : '') +
`<span class="scan-confidence ${confCls}">${r.is_vulnerable ? r.confidence : 'safe'}</span>` +
`</div>` +
`<div class="scan-details">${esc(r.details)}</div>` +
`<div class="scan-response-toggle">${isOpen ? '▾ Hide Details' : '▸ Show Details'}</div>` +
`<div class="scan-response ${isOpen ? '' : 'hidden'}">${detailContent}</div>` +
`</div>`;
        }).join('');

        const loadMoreBtn = hasMore
            ? `<button class="btn-small scan-load-more" style="margin:8px auto;display:block">Show more (${filtered.length - renderCap} remaining)</button>`
            : '';

        const t0 = performance.now();
        resultsEl.innerHTML = summary + (capped.length ? rows + loadMoreBtn : '<p class="placeholder-text">No matching results</p>');
        _dbg(`[render] ${filtered.length} total, ${capped.length} shown, ${(performance.now() - t0).toFixed(0)}ms, ${(summary.length + rows.length) / 1024 | 0}KB html`);

        // ── Event delegation — all handlers on container ──
        // (previous per-element listeners replaced by a single delegated setup)
        if (!resultsEl._delegated) {
            resultsEl._delegated = true;

            resultsEl.addEventListener('click', (ev) => {
                // "Show more" button — increase render cap and re-render
                if (ev.target.classList.contains('scan-load-more')) {
                    renderCap += 50;
                    renderResults(lastResults);
                    return;
                }
                // Filter buttons
                const filterBtn = ev.target.closest('.scan-filter-btn');
                if (filterBtn) {
                    activeFilter = filterBtn.dataset.filter;
                    renderCap = 50; // reset cap on filter change
                    renderResults(lastResults);
                    return;
                }
                // Expand/collapse details (lazy-load on first open)
                const toggle = ev.target.closest('.scan-response-toggle');
                if (toggle) {
                    const entry = toggle.closest('.scan-entry');
                    const key = entry.dataset.key;
                    const detail = toggle.nextElementSibling;
                    const open = !detail.classList.contains('hidden');
                    if (!open && !detail.innerHTML) {
                        // Lazy-load: render detail content on first expand
                        const idx = Number(entry.dataset.idx);
                        const r = getVisibleResults()[idx];
                        if (r) {
                            detail.innerHTML = _buildDetailHtml(r);
                            // Fetch heavy fields if not already loaded
                            if (!r._detailLoaded) _loadResultDetail(r, detail);
                        }
                    }
                    detail.classList.toggle('hidden');
                    toggle.textContent = open ? '▸ Show Details' : '▾ Hide Details';
                    if (open) { expandedSet.delete(key); } else { expandedSet.add(key); }
                    return;
                }
            });

            resultsEl.addEventListener('contextmenu', (ev) => {
                const el = ev.target.closest('.scan-entry');
                if (!el) return;
                ev.preventDefault();
                const idx = Number(el.dataset.idx);
                const r = getVisibleResults()[idx];
                if (r) _showScanCtxMenu(ev.clientX, ev.clientY, r);
            });
        }
    }

    /** Build detail HTML for a scan result. Heavy fields are fetched on demand. */
    function _buildDetailHtml(r) {
        const base =
`<div class="scan-detail-row"><strong>URL:</strong> ${esc(r.target_url)}</div>` +
`<div class="scan-detail-row"><strong>Point:</strong> [${esc(r.injection_point)}] ${esc(r.original_param)}</div>` +
`<div class="scan-detail-row"><strong>Payload:</strong> ${esc(r.payload)}</div>` +
`<div class="scan-detail-row"><strong>Status:</strong> ${r.response_code} &nbsp; <strong>Time:</strong> ${r.response_time_ms}ms</div>`;
        // If heavy fields are already loaded (from live polling or previous fetch), show them
        if (r._detailLoaded) {
            return base +
`<div class="scan-detail-row"><strong>Request Headers:</strong></div>` +
EPTUtils.headersBlock(r.request_headers || '') +
`<div class="scan-detail-row"><strong>Request Body:</strong></div>` +
EPTUtils.bodyPreBlock(r.request_body || '') +
`<div class="scan-detail-row"><strong>Response Body:</strong></div>` +
EPTUtils.bodyPreBlock(r.response_body || '');
        }
        // Otherwise return base with a loading placeholder; fetch will fill it in
        return base + `<div class="scan-detail-loading" data-result-id="${r.id}"><em>Loading details...</em></div>`;
    }

    /** Fetch full details for a single scan result and update the expanded view */
    async function _loadResultDetail(r, detailEl) {
        if (r._detailLoaded || !r.id) return;
        try {
            const resp = await fetch(`${API}/scan/result/${r.id}`);
            if (!resp.ok) return;
            const full = await resp.json();
            r.response_body = full.response_body || '';
            r.request_headers = full.request_headers || '';
            r.request_body = full.request_body || '';
            r._detailLoaded = true;
            // Re-render the detail content now that we have the full data
            detailEl.innerHTML = _buildDetailHtml(r);
        } catch (_) {
            const placeholder = detailEl.querySelector('.scan-detail-loading');
            if (placeholder) placeholder.innerHTML = '<em>Failed to load details</em>';
        }
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

        // Paths — only if "paths" checked
        if (active.has('paths') && urlEl.value) {
            try {
                const u = new URL(urlEl.value);
                const segments = u.pathname.split('/').filter(Boolean);
                segments.forEach(seg => keys.push({ source: 'path', key: '/' + seg }));
            } catch (_) {}
        }

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

        // Auth-related keys that should default to UNCHECKED to avoid
        // accidentally injecting into authentication tokens
        const AUTH_KEYS = new Set([
            'jwt', 'token', 'idtoken', 'id_token', 'access_token',
            'accesstoken', 'refresh_token', 'refreshtoken', 'auth',
            'authorization', 'auth_token', 'password', 'secret',
            'api_key', 'apikey', 'session', 'session_token', 'csrf',
            'csrftoken', 'csrf_token', 'x-csrf-token',
        ]);

        // Group keys by source
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

        // Click anywhere on a row to toggle its checkbox
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

    function walkKeys(obj, prefix, out) {
        const MAX_ARRAY_ELEMENTS = 20;
        for (const [k, v] of Object.entries(obj)) {
            const path = prefix ? `${prefix}.${k}` : k;
            if (Array.isArray(v)) {
                out.push({ source: 'body', key: path });
                _walkArray(v, path, out, MAX_ARRAY_ELEMENTS);
            } else if (v && typeof v === 'object') {
                out.push({ source: 'body', key: path });
                walkKeys(v, path, out);
            } else {
                out.push({ source: 'body', key: path });
            }
        }
    }

    function _walkArray(arr, prefix, out, maxElements) {
        const limit = Math.min(arr.length, maxElements);
        for (let i = 0; i < limit; i++) {
            const elemPath = `${prefix}[${i}]`;
            const el = arr[i];
            if (Array.isArray(el)) {
                out.push({ source: 'body', key: elemPath });
                _walkArray(el, elemPath, out, maxElements);
            } else if (el && typeof el === 'object') {
                out.push({ source: 'body', key: elemPath });
                walkKeys(el, elemPath, out);
            } else {
                out.push({ source: 'body', key: elemPath });
            }
        }
    }

    // ── Context menu on scan results ──────────────────────
    function _showScanCtxMenu(x, y, r) {
        let hdrs = {};
        try { hdrs = typeof r.request_headers === 'string' ? JSON.parse(r.request_headers) : (r.request_headers || {}); } catch (_) {}

        let fullUrl = r.target_url || '';
        if (r.injection_point === 'params') {
            let params = {};
            try { params = paramsEl.value ? JSON.parse(paramsEl.value) : {}; } catch (_) {}
            params[r.original_param] = r.payload;
            const qs = new URLSearchParams(params).toString();
            if (qs) fullUrl += '?' + qs;
        }

        SendTo.showContextMenu(x, y, {
            method: methodEl.value || 'POST',
            url: fullUrl,
            headers: hdrs,
            body: r.request_body || '',
            request_headers: hdrs,
            request_body: r.request_body || '',
        }, 'injector');
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    async function clearHistory() {
        try { await fetch(`${API}/scan/history`, { method: 'DELETE' }); } catch (_) {}
        lastResults = [];
        expandedSet.clear();
        resultsEl.innerHTML = '<p class="placeholder-text">No results yet</p>';
    }

    return { init, loadFromLog, populateFromLog: loadFromLog, loadHistory, clearHistory, getVisibleResults };
})();
