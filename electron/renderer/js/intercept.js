/**
 * Intercept — Burp-style proxy intercept mode.
 *
 * Toggle on → every request/response flowing through mitmproxy
 * is paused and shown for editing.  User can Forward or Drop.
 */
window.Intercept = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let enabled = false;
    let currentFlow = null;
    let queue = [];

    // DOM refs
    let toggleBtn, queueBadge, statusEl;
    let editorEl, emptyEl, historyEl;
    let phaseEl, hostEl, methodEl, urlEl, headersEl, bodyEl;
    let respSection, respStatusEl, respHeadersEl, respBodyEl;
    let forwardBtn, dropBtn;

    function init() {
        toggleBtn    = document.getElementById('btn-intercept-toggle');
        queueBadge   = document.getElementById('intercept-queue-count');
        statusEl     = document.getElementById('intercept-status');
        editorEl     = document.getElementById('intercept-current');
        emptyEl      = document.getElementById('intercept-empty');
        historyEl    = document.getElementById('intercept-history');
        phaseEl      = document.getElementById('intercept-phase-badge');
        hostEl       = document.getElementById('intercept-host');
        methodEl     = document.getElementById('intercept-method');
        urlEl        = document.getElementById('intercept-url');
        headersEl    = document.getElementById('intercept-headers');
        bodyEl       = document.getElementById('intercept-body');
        respSection  = document.getElementById('intercept-response-section');
        respStatusEl = document.getElementById('intercept-resp-status');
        respHeadersEl= document.getElementById('intercept-resp-headers');
        respBodyEl   = document.getElementById('intercept-resp-body');
        forwardBtn   = document.getElementById('btn-intercept-forward');
        dropBtn      = document.getElementById('btn-intercept-drop');

        toggleBtn.addEventListener('click', toggle);
        forwardBtn.addEventListener('click', () => decide('forward'));
        dropBtn.addEventListener('click', () => decide('drop'));

        fetchStatus();
    }

    async function fetchStatus() {
        try {
            const res = await fetch(API + '/intercept/status');
            const data = await res.json();
            enabled = data.enabled;
            updateUI();
        } catch (_) {}
    }

    async function toggle() {
        try {
            const res = await fetch(API + '/intercept/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !enabled }),
            });
            const data = await res.json();
            enabled = data.enabled;
            if (!enabled) {
                currentFlow = null;
                queue = [];
            }
            updateUI();
        } catch (_) {}
    }

    /** Called from app.js when WebSocket delivers an intercepted_flow message */
    function onInterceptedFlow(flowData) {
        if (!currentFlow) {
            currentFlow = flowData;
            showFlow(flowData);
        } else {
            queue.push(flowData);
        }
        updateUI();
    }

    function showFlow(flow) {
        editorEl.classList.remove('hidden');
        emptyEl.classList.add('hidden');

        phaseEl.textContent = flow.phase.toUpperCase();
        phaseEl.className = 'badge ' + (flow.phase === 'request' ? 'badge-request' : 'badge-response');
        hostEl.textContent = flow.host || '';

        // Reset disabled state
        headersEl.disabled = false;
        bodyEl.disabled = false;

        if (flow.phase === 'request') {
            methodEl.value = flow.method || 'GET';
            methodEl.disabled = false;
            urlEl.value = flow.url || '';
            headersEl.value = _fmtHeaders(flow.headers);
            bodyEl.value = flow.body || '';
            respSection.classList.add('hidden');
        } else {
            // Response phase — request info is read-only, response is editable
            methodEl.value = flow.method || 'GET';
            methodEl.disabled = true;
            urlEl.value = flow.url || '';
            headersEl.value = _fmtHeaders(flow.request_headers);
            headersEl.disabled = true;
            bodyEl.value = flow.request_body || '';
            bodyEl.disabled = true;
            respSection.classList.remove('hidden');
            respStatusEl.value = flow.status_code || 200;
            respHeadersEl.value = _fmtHeaders(flow.headers);
            respBodyEl.value = flow.body || '';
        }
    }

    function decide(decision) {
        if (!currentFlow) return;

        let modifications = null;
        if (decision === 'forward') {
            modifications = {};
            if (currentFlow.phase === 'request') {
                modifications.method = methodEl.value;
                try { modifications.headers = JSON.parse(headersEl.value); } catch (_) {}
                modifications.body = bodyEl.value;
            } else {
                modifications.status_code = Number(respStatusEl.value);
                try { modifications.headers = JSON.parse(respHeadersEl.value); } catch (_) {}
                modifications.body = respBodyEl.value;
            }
        }

        // Send decision via WebSocket for low latency
        if (window.AppWS) {
            AppWS.send({
                type: 'intercept_decision',
                flow_id: currentFlow.flow_id,
                decision: decision,
                modifications: modifications,
            });
        }

        addToHistory(currentFlow, decision);
        _showNext();
    }

    function _showNext() {
        if (queue.length > 0) {
            currentFlow = queue.shift();
            showFlow(currentFlow);
        } else {
            currentFlow = null;
            editorEl.classList.add('hidden');
            // Reset disabled state
            headersEl.disabled = false;
            bodyEl.disabled = false;
            if (enabled) {
                emptyEl.innerHTML = '<p class="placeholder-text">Waiting for requests...</p>';
            }
            emptyEl.classList.remove('hidden');
        }
        updateUI();
    }

    function addToHistory(flow, decision) {
        const item = document.createElement('div');
        item.className = 'intercept-history-entry';
        const badge = decision === 'drop'
            ? '<span class="badge badge-high">DROPPED</span>'
            : '<span class="badge badge-safe">FORWARDED</span>';
        item.innerHTML =
            badge +
            '<span class="log-method method-' + (flow.method || 'GET') + '">' + (flow.method || 'GET') + '</span>' +
            '<span class="log-url">' + esc(flow.url || '') + '</span>' +
            '<span class="log-time">' + flow.phase + '</span>';

        // Right-click to send to other tabs
        item.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            SendTo.showContextMenu(e.clientX, e.clientY, {
                method: flow.method,
                url: flow.url,
                headers: flow.headers || flow.request_headers || {},
                body: flow.body || flow.request_body || '',
                request_headers: flow.request_headers || flow.headers || {},
                request_body: flow.request_body || flow.body || '',
            }, 'intercept');
        });
        historyEl.prepend(item);
    }

    function updateUI() {
        toggleBtn.textContent = enabled ? 'Intercept On' : 'Intercept Off';
        toggleBtn.className = enabled ? 'btn-primary intercept-on' : 'btn-primary intercept-off';
        statusEl.textContent = enabled
            ? (currentFlow ? 'Intercepted' : 'Waiting...')
            : 'Disabled';

        if (queue.length > 0) {
            queueBadge.textContent = queue.length + ' queued';
            queueBadge.style.display = '';
        } else {
            queueBadge.style.display = 'none';
        }

        if (!enabled && !currentFlow) {
            editorEl.classList.add('hidden');
            emptyEl.classList.remove('hidden');
            emptyEl.innerHTML = '<p class="placeholder-text">Intercept is disabled. Toggle above to start intercepting proxy traffic.</p>';
        }
    }

    function _fmtHeaders(hdrs) {
        if (!hdrs) return '{}';
        if (typeof hdrs === 'string') return hdrs;
        try { return JSON.stringify(hdrs, null, 2); } catch (_) { return '{}'; }
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    return { init, onInterceptedFlow };
})();
