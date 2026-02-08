/**
 * Analytics — full-screen advanced analysis overlay
 *
 * Sections:
 *  1. Security Headers Audit — check responses for missing OWASP-recommended headers
 *  2. Response Timing Analysis — spot outliers suggesting time-based injection or WAFs
 *  3. Parameter Profiling — catalog every parameter, its types, injection acceptance rate
 *  4. Technology Fingerprint — detect server stack from headers and error bodies
 *  5. Attack Surface Heatmap — visual grid: endpoint × injection type → result
 *  6. Postman Export
 */
window.Analytics = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let scanData = [];
    let logData  = [];

    function init() {
        // refresh is called automatically when the analytics tab is activated (via app.js switchTab)
    }

    async function refresh() {
        document.getElementById('analytics-body-content').innerHTML =
            '<p class="placeholder-text" style="padding:20px">Analyzing...</p>';
        await Promise.all([fetchScans(), fetchLogs()]);
        render();
    }

    async function fetchScans() {
        try { scanData = await (await fetch(`${API}/scan/history?limit=5000`)).json(); }
        catch (_) { scanData = []; }
    }
    async function fetchLogs() {
        try { logData = await (await fetch(`${API}/logs?limit=5000`)).json(); }
        catch (_) { logData = []; }
    }

    // ════════════════════════════════════════════════════════════════
    //  RENDER
    // ════════════════════════════════════════════════════════════════

    function render() {
        const el = document.getElementById('analytics-body-content');
        el.innerHTML = '';

        const sections = [
            renderSecurityHeaders,
            renderTimingAnalysis,
            renderParamProfile,
            renderTechFingerprint,
            renderAttackSurface,
        ];
        sections.forEach(fn => {
            const s = document.createElement('div');
            s.className = 'analytics-section';
            fn(s);
            el.appendChild(s);
        });
    }

    // ── 1. Security Headers Audit ───────────────────────────────────

    function renderSecurityHeaders(container) {
        const RECOMMENDED = {
            'strict-transport-security': { label: 'HSTS', severity: 'high', desc: 'Missing — allows protocol downgrade attacks' },
            'content-security-policy':   { label: 'CSP', severity: 'high', desc: 'Missing — increases XSS risk' },
            'x-content-type-options':    { label: 'X-Content-Type-Options', severity: 'medium', desc: 'Missing — allows MIME-sniffing attacks' },
            'x-frame-options':           { label: 'X-Frame-Options', severity: 'medium', desc: 'Missing — allows clickjacking' },
            'referrer-policy':           { label: 'Referrer-Policy', severity: 'low', desc: 'Missing — may leak sensitive URL data in Referer' },
            'permissions-policy':        { label: 'Permissions-Policy', severity: 'low', desc: 'Missing — browser features not restricted' },
            'x-xss-protection':          { label: 'X-XSS-Protection', severity: 'low', desc: 'Missing (deprecated but still useful for legacy browsers)' },
            'cache-control':             { label: 'Cache-Control', severity: 'medium', desc: 'Missing — sensitive responses may be cached' },
        };

        // Collect unique response header sets per host
        const hostHeaders = {};
        logData.forEach(l => {
            const host = _host(l.url);
            if (!hostHeaders[host]) hostHeaders[host] = {};
            const rh = l.response_headers || {};
            for (const k of Object.keys(rh)) {
                hostHeaders[host][k.toLowerCase()] = rh[k];
            }
        });

        let html = '<div class="analytics-section-title">Security Headers Audit</div>';

        if (!Object.keys(hostHeaders).length) {
            html += '<p class="placeholder-text">No logged responses to audit</p>';
            container.innerHTML = html;
            return;
        }

        for (const [host, headers] of Object.entries(hostHeaders)) {
            html += `<div class="audit-host"><strong>${esc(host)}</strong></div>`;
            let issues = 0;
            for (const [key, info] of Object.entries(RECOMMENDED)) {
                const present = key in headers;
                const cls = present ? 'audit-pass' : `audit-fail audit-${info.severity}`;
                const icon = present ? '✓' : '✗';
                const detail = present ? `<span class="audit-value">${esc((headers[key] || '').slice(0, 80))}</span>` : `<span class="audit-desc">${info.desc}</span>`;
                html += `<div class="audit-row ${cls}"><span class="audit-icon">${icon}</span><span class="audit-label">${info.label}</span>${detail}</div>`;
                if (!present) issues++;
            }

            // Check for server header leaking version info
            if (headers['server']) {
                const sv = headers['server'];
                if (/\d/.test(sv)) {
                    html += `<div class="audit-row audit-fail audit-medium"><span class="audit-icon">⚠</span><span class="audit-label">Server</span><span class="audit-desc">Leaks version: ${esc(sv)}</span></div>`;
                    issues++;
                }
            }
            if (headers['x-powered-by']) {
                html += `<div class="audit-row audit-fail audit-medium"><span class="audit-icon">⚠</span><span class="audit-label">X-Powered-By</span><span class="audit-desc">Exposes stack: ${esc(headers['x-powered-by'])}</span></div>`;
                issues++;
            }

            if (issues === 0) html += '<div class="audit-row audit-pass"><span class="audit-icon">✓</span> All recommended headers present</div>';
        }

        container.innerHTML = html;
    }

    // ── 2. Response Timing Analysis ─────────────────────────────────

    function renderTimingAnalysis(container) {
        let html = '<div class="analytics-section-title">Response Timing Analysis</div>';

        // Use scan data for timing (injection tests have timing significance)
        const byEndpoint = {};
        scanData.forEach(r => {
            const key = _basePath(r.target_url);
            if (!byEndpoint[key]) byEndpoint[key] = { entries: [], sample: r };
            byEndpoint[key].entries.push({ time: r.response_time_ms, payload: r.payload, vuln: r.is_vulnerable, type: r.injector_type, scan: r });
        });

        if (!Object.keys(byEndpoint).length) {
            html += '<p class="placeholder-text">No scan data for timing analysis. Run an injection scan first.</p>';
            container.innerHTML = html;
            return;
        }

        html += '<p style="font-size:11px;color:var(--text-dim);margin-bottom:10px">Bars show response time distribution. Red bars are flagged payloads. Outliers may indicate time-based injection or WAF throttling. Right-click an outlier to send to Repeater or Injector.</p>';

        // Flat list of all outlier scan entries for context menu binding
        const outlierScans = [];

        const endpointKeys = Object.keys(byEndpoint);
        for (let ei = 0; ei < endpointKeys.length; ei++) {
            const endpoint = endpointKeys[ei];
            const { entries } = byEndpoint[endpoint];
            const times = entries.map(e => e.time).filter(t => t > 0);
            if (!times.length) continue;

            const avg = times.reduce((a, b) => a + b, 0) / times.length;
            const max = Math.max(...times);
            const stddev = Math.sqrt(times.reduce((s, t) => s + (t - avg) ** 2, 0) / times.length);

            // Find outliers (> 2 stddev from mean)
            const outliers = entries.filter(e => e.time > avg + 2 * stddev);

            html += `<div class="timing-endpoint">`;
            html += `<div class="timing-header analytics-ctx-endpoint" data-te-idx="${ei}"><span class="endpoint-doc-path">${esc(_shortPath(endpoint))}</span>`;
            html += `<span class="badge">${times.length} tests</span>`;
            html += `<span class="badge">avg ${avg.toFixed(0)}ms</span>`;
            html += `<span class="badge">σ ${stddev.toFixed(0)}ms</span>`;
            if (outliers.length) html += `<span class="badge badge-high">${outliers.length} outlier${outliers.length > 1 ? 's' : ''}</span>`;
            html += `</div>`;

            // Mini bar chart (max 60 bars)
            const sampled = entries.length > 60 ? entries.filter((_, i) => i % Math.ceil(entries.length / 60) === 0) : entries;
            const chartMax = max || 1;
            html += '<div class="timing-chart">';
            sampled.forEach(e => {
                const h = Math.max(2, (e.time / chartMax) * 40);
                const cls = e.vuln ? 'timing-bar-vuln' : (e.time > avg + 2 * stddev ? 'timing-bar-outlier' : 'timing-bar');
                html += `<div class="${cls}" style="height:${h}px" title="${esc(e.payload?.slice(0, 40))} — ${e.time.toFixed(0)}ms"></div>`;
            });
            html += '</div>';

            // List outliers — each row is individually interactive
            if (outliers.length) {
                html += '<div class="timing-outliers">';
                outliers.slice(0, 5).forEach(o => {
                    const oi = outlierScans.length;
                    outlierScans.push(o.scan);
                    html += `<div class="timing-outlier-row analytics-ctx-outlier" data-oi="${oi}"><span class="badge badge-high">${o.time.toFixed(0)}ms</span> <span class="audit-desc">${esc(o.type)} — ${esc((o.payload || '').slice(0, 60))}</span></div>`;
                });
                html += '</div>';
            }
            html += '</div>';
        }

        container.innerHTML = html;

        // Bind right-click context menus on endpoint headers
        container.querySelectorAll('.analytics-ctx-endpoint').forEach(el => {
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const key = endpointKeys[Number(el.dataset.teIdx)];
                const sample = byEndpoint[key]?.sample;
                if (!sample) return;
                _showAnalyticsCtx(e.clientX, e.clientY, sample);
            });
        });

        // Bind right-click context menus on individual outlier rows
        container.querySelectorAll('.analytics-ctx-outlier').forEach(el => {
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const scan = outlierScans[Number(el.dataset.oi)];
                if (!scan) return;
                _showAnalyticsCtx(e.clientX, e.clientY, scan);
            });
        });
    }

    // ── 3. Parameter Profiling ──────────────────────────────────────

    function renderParamProfile(container) {
        let html = '<div class="analytics-section-title">Parameter Injection Profile</div>';

        if (!scanData.length) {
            html += '<p class="placeholder-text">No scan data. Run an injection scan to profile parameters.</p>';
            container.innerHTML = html;
            return;
        }

        // Group by parameter + endpoint, keep a representative scan entry per group
        const params = {};
        scanData.forEach(r => {
            const key = `[${r.injection_point}] ${r.original_param}`;
            const endpoint = r.target_url || 'unknown';
            const groupKey = `${key}|||${endpoint}`;
            if (!params[groupKey]) params[groupKey] = { param: key, endpoint, total: 0, vuln: 0, rejected: 0, accepted: 0, types: new Set(), sample: r };
            const p = params[groupKey];
            p.total++;
            p.types.add(r.injector_type);
            if (r.is_vulnerable) p.vuln++;
            else if (r.response_code >= 400 && r.response_code < 500) p.rejected++;
            else p.accepted++;
        });

        html += '<p style="font-size:11px;color:var(--text-dim);margin-bottom:10px">How each parameter handled injected payloads. High acceptance without vulnerability may indicate sanitization. High rejection suggests validation. Right-click a row to send to Repeater or Injector.</p>';

        html += '<table class="analytics-table"><thead><tr><th>Endpoint</th><th>Parameter</th><th>Tests</th><th>Vulnerable</th><th>Accepted (safe)</th><th>Rejected (4xx)</th><th>Acceptance Rate</th><th>Verdict</th></tr></thead><tbody>';

        const sorted = Object.values(params).sort((a, b) => b.vuln - a.vuln || a.endpoint.localeCompare(b.endpoint));
        sorted.forEach((p, idx) => {
            const acceptRate = ((p.accepted + p.vuln) / p.total * 100).toFixed(0);
            let verdict, verdictCls;
            if (p.vuln > 0) { verdict = 'VULNERABLE'; verdictCls = 'badge-high'; }
            else if (p.rejected / p.total > 0.8) { verdict = 'Well validated'; verdictCls = 'badge-safe'; }
            else if (p.accepted / p.total > 0.5) { verdict = 'Review needed'; verdictCls = 'badge-medium'; }
            else { verdict = 'Mixed'; verdictCls = ''; }

            let shortUrl;
            try { const u = new URL(p.endpoint); shortUrl = u.pathname; } catch (_) { shortUrl = p.endpoint; }

            html += `<tr class="analytics-ctx-row" data-pp-idx="${idx}">
                <td title="${esc(p.endpoint)}"><code>${esc(shortUrl)}</code></td>
                <td><code>${esc(p.param)}</code></td>
                <td>${p.total}</td>
                <td>${p.vuln ? `<span class="badge badge-high">${p.vuln}</span>` : '0'}</td>
                <td>${p.accepted}</td>
                <td>${p.rejected}</td>
                <td>
                    <div class="acceptance-bar">
                        <div class="acceptance-fill" style="width:${acceptRate}%"></div>
                    </div>
                    <span style="font-size:10px">${acceptRate}%</span>
                </td>
                <td><span class="badge ${verdictCls}">${verdict}</span></td>
            </tr>`;
        });

        html += '</tbody></table>';
        container.innerHTML = html;

        // Bind right-click context menus
        container.querySelectorAll('.analytics-ctx-row').forEach(row => {
            row.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const p = sorted[Number(row.dataset.ppIdx)];
                if (!p || !p.sample) return;
                _showAnalyticsCtx(e.clientX, e.clientY, p.sample);
            });
        });
    }

    // ── 4. Technology Fingerprint ───────────────────────────────────

    function renderTechFingerprint(container) {
        let html = '<div class="analytics-section-title">Technology Fingerprint</div>';

        const signals = [];

        // Gather from response headers
        const allHeaders = {};
        logData.forEach(l => {
            const rh = l.response_headers || {};
            for (const [k, v] of Object.entries(rh)) allHeaders[k.toLowerCase()] = v;
        });

        if (allHeaders['server']) signals.push({ source: 'Server header', value: allHeaders['server'], confidence: 'high' });
        if (allHeaders['x-powered-by']) signals.push({ source: 'X-Powered-By', value: allHeaders['x-powered-by'], confidence: 'high' });
        if (allHeaders['x-aspnet-version']) signals.push({ source: 'X-AspNet-Version', value: allHeaders['x-aspnet-version'], confidence: 'high' });
        if (allHeaders['x-generator']) signals.push({ source: 'X-Generator', value: allHeaders['x-generator'], confidence: 'high' });

        // Infer from patterns
        if (allHeaders['set-cookie']?.includes('PHPSESSID')) signals.push({ source: 'Cookie pattern', value: 'PHP (PHPSESSID)', confidence: 'medium' });
        if (allHeaders['set-cookie']?.includes('JSESSIONID')) signals.push({ source: 'Cookie pattern', value: 'Java (JSESSIONID)', confidence: 'medium' });
        if (allHeaders['set-cookie']?.includes('connect.sid')) signals.push({ source: 'Cookie pattern', value: 'Node.js/Express (connect.sid)', confidence: 'medium' });
        if (allHeaders['set-cookie']?.includes('ASP.NET')) signals.push({ source: 'Cookie pattern', value: 'ASP.NET', confidence: 'medium' });

        // Check error bodies for framework signatures
        const errorBodies = logData.filter(l => l.status_code >= 400).map(l => l.response_body || '').join(' ').slice(0, 50000);
        if (/Traceback.*Python/is.test(errorBodies)) signals.push({ source: 'Error body', value: 'Python (stack trace leaked)', confidence: 'high' });
        if (/at\s+[\w.]+\(.*\.java:\d+\)/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'Java (stack trace leaked)', confidence: 'high' });
        if (/Laravel|Symfony/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'PHP Laravel/Symfony', confidence: 'medium' });
        if (/Express|node_modules/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'Node.js/Express', confidence: 'medium' });
        if (/django/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'Django', confidence: 'medium' });
        if (/ArangoDB/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'ArangoDB', confidence: 'high' });
        if (/MongoDB|MongoError/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'MongoDB', confidence: 'high' });
        if (/mysql|mariadb/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'MySQL/MariaDB', confidence: 'high' });
        if (/postgres/i.test(errorBodies)) signals.push({ source: 'Error body', value: 'PostgreSQL', confidence: 'high' });

        if (!signals.length) {
            html += '<p class="placeholder-text">No technology signatures detected. The target may have good information hiding.</p>';
            container.innerHTML = html;
            return;
        }

        html += '<div class="fingerprint-grid">';
        signals.forEach(s => {
            html += `<div class="fingerprint-item">
                <span class="badge badge-${s.confidence === 'high' ? 'high' : 'medium'}">${esc(s.confidence)}</span>
                <strong>${esc(s.source)}</strong>
                <span>${esc(s.value)}</span>
            </div>`;
        });
        html += '</div>';

        container.innerHTML = html;
    }

    // ── 5. Attack Surface Heatmap ───────────────────────────────────

    function renderAttackSurface(container) {
        let html = '<div class="analytics-section-title">Attack Surface Heatmap</div>';

        if (!scanData.length) {
            html += '<p class="placeholder-text">No scan data for heatmap</p>';
            container.innerHTML = html;
            return;
        }

        html += '<p style="font-size:11px;color:var(--text-dim);margin-bottom:10px">Each cell shows vulnerability count for an endpoint × injection type combination. Darker = more findings.</p>';

        // Axes: endpoints (rows) × injection types (cols)
        const endpoints = [...new Set(scanData.map(r => _shortPath(r.target_url)))];
        const types = [...new Set(scanData.map(r => r.injector_type))];

        // Build matrix
        const matrix = {};
        scanData.forEach(r => {
            const ep = _shortPath(r.target_url);
            const t = r.injector_type;
            const key = `${ep}||${t}`;
            if (!matrix[key]) matrix[key] = { total: 0, vuln: 0 };
            matrix[key].total++;
            if (r.is_vulnerable) matrix[key].vuln++;
        });

        html += '<div style="overflow-x:auto"><table class="heatmap-table"><thead><tr><th>Endpoint</th>';
        types.forEach(t => { html += `<th>${esc(t.toUpperCase())}</th>`; });
        html += '</tr></thead><tbody>';

        endpoints.forEach(ep => {
            html += `<tr><td class="heatmap-label" title="${esc(ep)}">${esc(ep)}</td>`;
            types.forEach(t => {
                const cell = matrix[`${ep}||${t}`];
                if (!cell) { html += '<td class="heatmap-cell heatmap-none">—</td>'; return; }
                const intensity = cell.vuln > 0 ? Math.min(cell.vuln / 3, 1) : 0;
                const cls = cell.vuln > 0 ? 'heatmap-vuln' : 'heatmap-safe';
                const opacity = cell.vuln > 0 ? 0.3 + intensity * 0.7 : 1;
                html += `<td class="heatmap-cell ${cls}" style="opacity:${opacity}" title="${cell.vuln} vuln / ${cell.total} tests">${cell.vuln}/${cell.total}</td>`;
            });
            html += '</tr>';
        });

        html += '</tbody></table></div>';
        container.innerHTML = html;
    }

    // ── Postman Export ──────────────────────────────────────────────

    function exportPostman() {
        const groups = {};
        logData.forEach(l => {
            const key = `${l.method} ${_basePath(l.url)}`;
            if (groups[key]) return;
            groups[key] = l;
        });

        const items = Object.values(groups).map(l => {
            let u; try { u = new URL(l.url); } catch (_) { return null; }
            const item = {
                name: `${l.method} ${u.pathname}`,
                request: {
                    method: l.method,
                    header: Object.entries(l.request_headers || {})
                        .filter(([k]) => !['host','content-length','transfer-encoding','connection','accept-encoding'].includes(k.toLowerCase()))
                        .map(([k, v]) => ({ key: k, value: v })),
                    url: {
                        raw: l.url,
                        protocol: u.protocol.replace(':', ''),
                        host: u.hostname.split('.'),
                        port: u.port || '',
                        path: u.pathname.split('/').filter(Boolean),
                        query: [...u.searchParams].map(([k, v]) => ({ key: k, value: v })),
                    },
                },
            };
            if (l.request_body) {
                item.request.body = { mode: 'raw', raw: _prettyJson(l.request_body), options: { raw: { language: 'json' } } };
            }
            return item;
        }).filter(Boolean);

        const collection = {
            info: { name: `Endpoint Security — ${new Date().toLocaleDateString()}`, schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
            item: items,
        };
        const blob = new Blob([JSON.stringify(collection, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `postman_collection_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    // ── Context Menu (shared for param profile & timing) ───────────

    function _showAnalyticsCtx(x, y, scanEntry) {
        _closeAnalyticsCtx();
        const menu = document.createElement('div');
        menu.className = 'ctx-menu';
        menu.style.left = x + 'px';
        menu.style.top  = y + 'px';
        menu.innerHTML = `
            <div class="ctx-menu-item" data-action="repeater">Send to Repeater</div>
            <div class="ctx-menu-item" data-action="injector">Send to Injector</div>
        `;

        const req = _buildReqFromScan(scanEntry);

        menu.querySelector('[data-action="repeater"]').addEventListener('click', () => {
            Repeater.addRequest(req);
            _closeAnalyticsCtx();
        });
        menu.querySelector('[data-action="injector"]').addEventListener('click', () => {
            if (InjectorUI && InjectorUI.populateFromLog) InjectorUI.populateFromLog(req);
            document.querySelectorAll('#tab-bar .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'injector'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.dataset.tab === 'injector'));
            _closeAnalyticsCtx();
        });

        document.body.appendChild(menu);
        const dismiss = () => { _closeAnalyticsCtx(); document.removeEventListener('click', dismiss); };
        setTimeout(() => document.addEventListener('click', dismiss), 0);
    }

    function _closeAnalyticsCtx() {
        document.querySelectorAll('.ctx-menu').forEach(m => m.remove());
    }

    function _buildReqFromScan(r) {
        let hdrs = {};
        try { hdrs = typeof r.request_headers === 'string' ? JSON.parse(r.request_headers) : (r.request_headers || {}); } catch (_) {}
        return {
            method: r.method || 'POST',
            url: r.target_url || '',
            headers: hdrs,
            body: r.request_body || '',
            request_headers: hdrs,
            request_body: r.request_body || '',
        };
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _host(url) { try { return new URL(url).host; } catch (_) { return 'unknown'; } }
    function _basePath(url) { try { const u = new URL(url); return u.origin + u.pathname; } catch (_) { return url; } }
    function _shortPath(url) { try { return new URL(url).pathname; } catch (_) { return url.slice(0, 50); } }
    function _prettyJson(s) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch (_) { return s; } }
    function esc(s) { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }

    return { init, refresh };
})();
