/**
 * LogViewer — renders the request/response log panel
 */
window.LogViewer = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let logs = [];
    let selectedId = null;

    // ── DOM refs (resolved after DOMContentLoaded) ──
    let listEl, searchEl, methodFilterEl, clearBtn, detailPanel, detailContent, detailTitle;

    function init() {
        listEl        = document.getElementById('log-list');
        searchEl      = document.getElementById('log-search');
        methodFilterEl= document.getElementById('log-method-filter');
        clearBtn      = document.getElementById('btn-clear-logs');
        detailPanel   = document.getElementById('detail-panel');
        detailContent = document.getElementById('detail-content');
        detailTitle   = document.getElementById('detail-title');

        clearBtn.addEventListener('click', clearLogs);
        searchEl.addEventListener('input', renderList);
        methodFilterEl.addEventListener('change', renderList);
        document.getElementById('btn-close-detail').addEventListener('click', closeDetail);
    }

    /** Called from WebSocket for each new request log */
    function addEntry(entry) {
        logs.unshift(entry);
        if (logs.length > 2000) logs.length = 2000; // cap memory
        renderList();
    }

    /** Batch-add entries without re-rendering on each one */
    function addEntries(entries) {
        for (const e of entries) {
            logs.unshift(e);
        }
        if (logs.length > 2000) logs.length = 2000;
        renderList();
    }

    function renderList() {
        const search = (searchEl.value || '').toLowerCase();
        const method = methodFilterEl.value;

        const filtered = logs.filter(e => {
            if (method && e.method !== method) return false;
            if (search && !e.url.toLowerCase().includes(search)
                       && !(e.host || '').toLowerCase().includes(search)) return false;
            return true;
        });

        listEl.innerHTML = filtered.map(e => {
            const statusClass = e.status_code === 0 ? 'status-0'
                : e.status_code < 300 ? 'status-2xx'
                : e.status_code < 400 ? 'status-3xx'
                : e.status_code < 500 ? 'status-4xx' : 'status-5xx';

            return `<div class="log-entry${e.id === selectedId ? ' selected' : ''}" data-id="${e.id}">
                <span class="log-method method-${e.method}">${e.method}</span>
                <span class="log-status ${statusClass}">${e.status_code || '—'}</span>
                <span class="log-url" title="${esc(e.url)}">${esc(e.path || e.url)}</span>
                <span class="log-time">${fmtTime(e.timestamp)}${e.duration_ms ? ' · ' + e.duration_ms.toFixed(0) + 'ms' : ''}</span>
            </div>`;
        }).join('');

        // Attach click handlers
        listEl.querySelectorAll('.log-entry').forEach(el => {
            el.addEventListener('click', () => selectEntry(Number(el.dataset.id)));
            el.addEventListener('dblclick', () => {
                userClosedDetail = false;
                detailPanel.classList.remove('collapsed');
                selectEntry(Number(el.dataset.id));
            });
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const entry = logs.find(l => l.id === Number(el.dataset.id));
                if (!entry) return;
                _showCtxMenu(e.clientX, e.clientY, entry);
            });
        });
    }

    let userClosedDetail = false;

    async function selectEntry(id) {
        selectedId = id;
        renderList();

        const entry = logs.find(e => e.id === id);
        if (!entry) return;

        if (!userClosedDetail) {
            detailPanel.classList.remove('collapsed');
        }
        detailTitle.textContent = `${entry.method} ${entry.url}`;

        detailContent.innerHTML =
`<div class="detail-section">
<div class="detail-section-title">Request Headers</div>
${formatHeaders(entry.request_headers)}
</div>
<div class="detail-section">
<div class="detail-section-title">Request Body</div>
${EPTUtils.bodyPreBlock(entry.request_body || '')}
</div>
<div class="detail-section">
<div class="detail-section-title">Response Headers</div>
${formatHeaders(entry.response_headers)}
</div>
<div class="detail-section">
<div class="detail-section-title">Response Body</div>
${EPTUtils.bodyPreBlock((entry.response_body || '').substring(0, 5000))}
</div>`;
    }

    function closeDetail() {
        detailPanel.classList.add('collapsed');
        userClosedDetail = true;
        selectedId = null;
        renderList();
    }

    async function clearLogs() {
        try { await fetch(`${API}/logs`, { method: 'DELETE' }); } catch (_) {}
        logs = [];
        selectedId = null;
        renderList();
        closeDetail();
    }

    /** Return currently selected log entry (used by injector to populate form) */
    function getSelected() {
        return logs.find(e => e.id === selectedId) || null;
    }

    // ── Helpers ────────────────────────
    function fmtTime(ts) {
        if (!ts) return '';
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch (_) { return ''; }
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function formatHeaders(hdrs) {
        if (!hdrs || typeof hdrs !== 'object') return '(none)';
        return Object.entries(hdrs)
            .map(([k, v]) => {
                const av = EPTUtils.escAttr(v);
                return `<span class="hdr-key" data-copy-hdr="${av}" title="Click to copy value">${esc(k)}</span>: <span class="hdr-val" data-copy-hdr="${av}" title="Click to copy value">${esc(v)}</span>`;
            })
            .join('\n');
    }

    /** Build a portable request object from a log entry */
    function _buildReq(entry) {
        return {
            method: entry.method,
            url: entry.url,
            headers: entry.request_headers || {},
            body: entry.request_body || '',
            request_headers: entry.request_headers || {},
            request_body: entry.request_body || '',
        };
    }

    function _showCtxMenu(x, y, entry) {
        SendTo.showContextMenu(x, y, _buildReq(entry), 'logs');
    }

    /** Reset all logs (used on workspace switch) */
    function clear() {
        logs = [];
        selectedId = null;
        renderList();
        closeDetail();
    }

    return { init, addEntry, addEntries, getSelected, clear };
})();
