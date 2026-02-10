/**
 * Repeater — resend and tweak individual requests
 */
window.Repeater = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let listEl, urlEl, methodEl, headersEl, bodyEl, responseEl, sendBtn;
    let history = []; // { id, method, url, headers, body, label }
    let selectedIdx = null;

    function init() {
        listEl     = document.getElementById('repeater-list');
        urlEl      = document.getElementById('repeater-url');
        methodEl   = document.getElementById('repeater-method');
        headersEl  = document.getElementById('repeater-headers');
        bodyEl     = document.getElementById('repeater-body');
        responseEl = document.getElementById('repeater-response');
        sendBtn    = document.getElementById('btn-repeater-send');

        sendBtn.addEventListener('click', send);
        loadHistory();

        SendTo.register('repeater', {
            label: 'Repeater',
            receive(data) { addRequest(data); },
        });
    }

    /** Load persisted history from backend */
    function loadHistory() {
        // Clear stale state immediately so previous workspace data doesn't linger
        history = [];
        selectedIdx = null;
        if (urlEl) urlEl.value = '';
        if (methodEl) methodEl.value = 'GET';
        if (headersEl) headersEl.value = '';
        if (bodyEl) bodyEl.value = '';
        if (responseEl) responseEl.innerHTML = '';
        renderList();

        fetch(`${API}/repeater/history`)
            .then(r => r.json())
            .then(rows => {
                history = rows.map(r => ({
                    id: r.id,
                    method: r.method || 'GET',
                    url: r.url || '',
                    headers: _parseHeaders(r.headers),
                    body: r.body || '',
                    label: `${r.method || 'GET'} ${_shortUrl(r.url || '')}`,
                }));
                selectedIdx = history.length ? 0 : null;
                if (selectedIdx === 0) _loadEntry(history[0]);
                renderList();
            })
            .catch(() => {});
    }

    /** Persist a single entry to backend */
    function _persist(entry) {
        fetch(`${API}/repeater/history`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                method: entry.method,
                url: entry.url,
                headers: entry.headers,
                body: entry.body,
            }),
        })
        .then(r => r.json())
        .then(data => { if (data.id) entry.id = data.id; })
        .catch(() => {});
    }

    /** Delete a single entry from backend */
    function _unpersist(entry) {
        if (!entry.id) return;
        fetch(`${API}/repeater/history?entry_id=${entry.id}`, { method: 'DELETE' }).catch(() => {});
    }

    /** Add a request to the repeater history and select it */
    function addRequest(req) {
        const entry = {
            id: null,
            method: req.method || 'GET',
            url: req.url || '',
            headers: req.headers || {},
            body: req.body || '',
            label: `${req.method || 'GET'} ${_shortUrl(req.url || '')}`,
        };
        history.unshift(entry);
        if (history.length > 50) history.length = 50;
        selectedIdx = 0;
        _persist(entry);
        _loadEntry(entry);
        renderList();
        _switchToTab();
    }

    function _loadEntry(entry) {
        methodEl.value = entry.method;
        urlEl.value = entry.url;
        headersEl.value = typeof entry.headers === 'string'
            ? entry.headers
            : JSON.stringify(entry.headers, null, 2);
        bodyEl.value = entry.body;
        responseEl.innerHTML = '<p class="placeholder-text">Ready to send</p>';
    }

    function renderList() {
        if (!history.length) {
            listEl.innerHTML = '<p class="placeholder-text" style="padding:10px">No requests yet.<br>Right-click a log or scan result → Send to Repeater</p>';
            return;
        }
        listEl.innerHTML = history.map((h, i) => `
            <div class="repeater-entry${i === selectedIdx ? ' selected' : ''}" data-idx="${i}">
                <span class="repeater-entry-label">${esc(h.label)}</span>
                <button class="repeater-remove" data-idx="${i}" title="Remove">&times;</button>
            </div>
        `).join('');

        listEl.querySelectorAll('.repeater-entry').forEach(el => {
            el.addEventListener('click', (e) => {
                if (e.target.classList.contains('repeater-remove')) return;
                selectedIdx = Number(el.dataset.idx);
                _loadEntry(history[selectedIdx]);
                renderList();
            });
            el.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const entry = history[Number(el.dataset.idx)];
                if (entry) _showCtxMenu(e.clientX, e.clientY, entry);
            });
        });

        listEl.querySelectorAll('.repeater-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = Number(btn.dataset.idx);
                _unpersist(history[idx]);
                history.splice(idx, 1);
                if (selectedIdx >= history.length) selectedIdx = history.length - 1;
                if (selectedIdx >= 0) _loadEntry(history[selectedIdx]);
                renderList();
            });
        });
    }

    function send() {
        let headers = {};
        try { headers = headersEl.value.trim() ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        const url = (urlEl.value || '').trim();
        const method = methodEl.value || 'GET';
        const body = bodyEl.value || '';

        if (!url) { alert('Enter a URL'); return; }

        // Always create a new history entry per send
        const entry = {
            id: null,
            method, url, headers, body,
            label: `${method} ${_shortUrl(url)}`,
        };
        history.unshift(entry);
        if (history.length > 50) history.length = 50;
        selectedIdx = 0;
        _persist(entry);
        renderList();

        sendBtn.disabled = true;
        sendBtn.textContent = '...';
        responseEl.innerHTML = '<p class="placeholder-text">Sending...</p>';

        const payload = { url, method, headers, body };

        fetch(`${API}/send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        })
        .then(r => r.json())
        .then(data => {
            responseEl.innerHTML = `
                <div class="repeater-response-block">
                    <div class="scan-header">
                        <span class="scan-badge">${data.status_code || data.error || '?'}</span>
                        <span class="scan-payload">${esc(method)} ${esc(url)}</span>
                    </div>
                    <div class="scan-detail-row"><strong>Response Headers:</strong></div>
                    <pre class="scan-response-body">${esc(JSON.stringify(data.headers || {}, null, 2))}</pre>
                    <div class="scan-detail-row"><strong>Response Body:</strong></div>
                    <pre class="scan-response-body">${esc(data.body || data.error || '(empty)')}</pre>
                </div>`;
        })
        .catch(e => {
            responseEl.innerHTML = `<p class="placeholder-text" style="color:var(--danger)">Error: ${e.message}</p>`;
        })
        .finally(() => {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send';
        });
    }

    function clearAll() {
        fetch(`${API}/repeater/history`, { method: 'DELETE' }).catch(() => {});
        history = [];
        selectedIdx = null;
        renderList();
        urlEl.value = '';
        methodEl.value = 'GET';
        headersEl.value = '';
        bodyEl.value = '';
        responseEl.innerHTML = '';
    }

    function _switchToTab() {
        document.querySelectorAll('#tab-bar .tab').forEach(t =>
            t.classList.toggle('active', t.dataset.tab === 'repeater'));
        document.querySelectorAll('.tab-pane').forEach(p =>
            p.classList.toggle('active', p.dataset.tab === 'repeater'));
    }

    function _shortUrl(url) {
        try { return new URL(url).pathname; } catch (_) { return url.slice(0, 40); }
    }

    function _parseHeaders(h) {
        if (!h) return {};
        if (typeof h === 'object') return h;
        try { return JSON.parse(h); } catch (_) { return {}; }
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function _showCtxMenu(x, y, entry) {
        SendTo.showContextMenu(x, y, {
            method: entry.method,
            url: entry.url,
            headers: entry.headers || {},
            body: entry.body || '',
            request_headers: entry.headers || {},
            request_body: entry.body || '',
        }, 'repeater');
    }

    return { init, addRequest, clearAll, loadHistory };
})();
