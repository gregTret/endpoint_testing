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
    }

    /** Add a request to the repeater history and select it */
    function addRequest(req) {
        const entry = {
            id: Date.now(),
            method: req.method || 'GET',
            url: req.url || '',
            headers: req.headers || {},
            body: req.body || '',
            label: `${req.method || 'GET'} ${_shortUrl(req.url || '')}`,
        };
        history.unshift(entry);
        if (history.length > 50) history.length = 50;
        selectedIdx = 0;
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
        });

        listEl.querySelectorAll('.repeater-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = Number(btn.dataset.idx);
                history.splice(idx, 1);
                if (selectedIdx >= history.length) selectedIdx = history.length - 1;
                if (selectedIdx >= 0) _loadEntry(history[selectedIdx]);
                renderList();
            });
        });
    }

    async function send() {
        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        const payload = {
            url: urlEl.value,
            method: methodEl.value,
            headers,
            body: bodyEl.value,
        };
        if (!payload.url) { alert('Enter a URL'); return; }

        // Save into history — update selected entry or create new one
        if (selectedIdx != null && selectedIdx < history.length) {
            const h = history[selectedIdx];
            h.method = payload.method;
            h.url = payload.url;
            h.headers = headers;
            h.body = payload.body;
            h.label = `${payload.method} ${_shortUrl(payload.url)}`;
        } else {
            history.unshift({
                id: Date.now(),
                method: payload.method,
                url: payload.url,
                headers,
                body: payload.body,
                label: `${payload.method} ${_shortUrl(payload.url)}`,
            });
            if (history.length > 50) history.length = 50;
            selectedIdx = 0;
        }
        renderList();

        sendBtn.disabled = true;
        sendBtn.textContent = '...';
        responseEl.innerHTML = '<p class="placeholder-text">Sending...</p>';

        try {
            const res = await fetch(`${API}/send`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            responseEl.innerHTML = `
                <div class="repeater-response-block">
                    <div class="scan-header">
                        <span class="scan-badge">${data.status_code}</span>
                        <span class="scan-payload">${esc(payload.method)} ${esc(payload.url)}</span>
                    </div>
                    <div class="scan-detail-row"><strong>Response Headers:</strong></div>
                    <pre class="scan-response-body">${esc(JSON.stringify(data.headers || {}, null, 2))}</pre>
                    <div class="scan-detail-row"><strong>Response Body:</strong></div>
                    <pre class="scan-response-body">${esc(data.body || '(empty)')}</pre>
                </div>`;
        } catch (e) {
            responseEl.innerHTML = `<p class="placeholder-text" style="color:var(--danger)">Error: ${e.message}</p>`;
        }
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send';
    }

    function clearAll() {
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

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    return { init, addRequest, clearAll };
})();
