/**
 * InjectorUI — injection scan configuration and results display
 */
window.InjectorUI = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let scanBtn, resultsEl;
    let urlEl, methodEl, typeEl, paramsEl, headersEl, bodyEl;
    let scanPollTimer = null;

    function init() {
        urlEl      = document.getElementById('inject-url');
        methodEl   = document.getElementById('inject-method');
        typeEl     = document.getElementById('inject-type');
        paramsEl   = document.getElementById('inject-params');
        headersEl  = document.getElementById('inject-headers');
        bodyEl     = document.getElementById('inject-body');
        scanBtn    = document.getElementById('btn-start-scan');
        resultsEl  = document.getElementById('scan-results');

        scanBtn.addEventListener('click', startScan);
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
    }

    async function startScan() {
        const points = [];
        document.querySelectorAll('#injector-config .checkbox-group input:checked')
            .forEach(cb => points.push(cb.value));

        let params = {};
        try { params = paramsEl.value ? JSON.parse(paramsEl.value) : {}; } catch (_) {}

        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        const config = {
            target_url: urlEl.value,
            method: methodEl.value,
            injector_type: typeEl.value,
            params,
            headers,
            body: bodyEl.value,
            injection_points: points.length ? points : ['params'],
            timeout: 10.0,
        };

        if (!config.target_url) { alert('Enter a target URL'); return; }

        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
        resultsEl.innerHTML = '<p class="placeholder-text">Scan in progress...</p>';

        try {
            await fetch(`${API}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config),
            });
            pollResults();
        } catch (e) {
            resultsEl.innerHTML = `<p class="placeholder-text">Error: ${e.message}</p>`;
            scanBtn.disabled = false;
            scanBtn.textContent = 'Launch Scan';
        }
    }

    function pollResults() {
        if (scanPollTimer) clearInterval(scanPollTimer);

        scanPollTimer = setInterval(async () => {
            try {
                // Check if scan is still running
                const statusRes = await fetch(`${API}/scan/status`);
                const status = await statusRes.json();

                // Update progress text
                if (status.running) {
                    scanBtn.textContent = `Scanning... (${status.completed}/${status.total})`;
                }

                // Fetch results
                const res = await fetch(`${API}/scan/results?limit=500`);
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

    function renderResults(results) {
        if (!results.length) {
            resultsEl.innerHTML = '<p class="placeholder-text">No results yet</p>';
            return;
        }

        const vulns = results.filter(r => r.is_vulnerable);
        const summary = `<div style="padding:6px 10px;font-size:11px;color:var(--text-dim);border-bottom:1px solid var(--border)">
            ${results.length} tests | <span style="color:var(--danger)">${vulns.length} potential vulnerabilities</span>
        </div>`;

        const rows = results.map(r => {
            const cls = r.is_vulnerable ? 'scan-vuln' : 'scan-safe';
            const confCls = `confidence-${r.confidence}`;
            return `<div class="scan-entry ${cls}">
                <div class="scan-header">
                    <span class="scan-payload" title="${esc(r.payload)}">${esc(r.payload)}</span>
                    <span class="scan-confidence ${confCls}">${r.is_vulnerable ? r.confidence : 'safe'}</span>
                </div>
                <div class="scan-details">${esc(r.details)}</div>
            </div>`;
        }).join('');

        resultsEl.innerHTML = summary + rows;
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    return { init, loadFromLog };
})();
