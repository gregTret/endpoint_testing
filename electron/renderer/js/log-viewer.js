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
                <span class="log-time">${e.duration_ms ? e.duration_ms.toFixed(0) + 'ms' : ''}</span>
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

        detailContent.innerHTML = `
<div class="detail-section">
    <div class="detail-section-title">Request Headers</div>
    ${formatHeaders(entry.request_headers)}
</div>
<div class="detail-section">
    <div class="detail-section-title">Request Body</div>
    ${esc(entry.request_body || '(empty)')}
</div>
<div class="detail-section">
    <div class="detail-section-title">Response Headers</div>
    ${formatHeaders(entry.response_headers)}
</div>
<div class="detail-section">
    <div class="detail-section-title">Response Body</div>
    ${esc((entry.response_body || '').substring(0, 5000))}
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
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function formatHeaders(hdrs) {
        if (!hdrs || typeof hdrs !== 'object') return '(none)';
        return Object.entries(hdrs)
            .map(([k, v]) => `<span style="color:var(--accent)">${esc(k)}</span>: ${esc(v)}`)
            .join('\n');
    }

    return { init, addEntry, getSelected };
})();
