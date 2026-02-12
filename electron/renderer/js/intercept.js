/**
 * Intercept — Burp-style proxy intercept mode.
 *
 * Toggle on → every request/response flowing through mitmproxy
 * is paused and shown for editing.  User can Forward or Drop.
 *
 * Multipart/form-data requests get a specialised per-part editor
 * with preset attack templates for file-upload security testing.
 */
window.Intercept = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let enabled = false;
    let currentFlow = null;
    let queue = [];

    // DOM refs
    let toggleBtn, queueBadge, statusEl;
    let editorEl, emptyEl, historyEl;
    let phaseEl, hostEl, methodEl, urlEl, headersEl, bodyEl, bodyGroup;
    let respSection, respStatusEl, respHeadersEl, respBodyEl;
    let forwardBtn, dropBtn;
    let multipartSection, multipartPartsEl, presetSelect;

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
        bodyGroup    = document.getElementById('intercept-body-group');
        respSection  = document.getElementById('intercept-response-section');
        respStatusEl = document.getElementById('intercept-resp-status');
        respHeadersEl= document.getElementById('intercept-resp-headers');
        respBodyEl   = document.getElementById('intercept-resp-body');
        forwardBtn   = document.getElementById('btn-intercept-forward');
        dropBtn      = document.getElementById('btn-intercept-drop');
        multipartSection = document.getElementById('intercept-multipart-section');
        multipartPartsEl = document.getElementById('intercept-multipart-parts');
        presetSelect     = document.getElementById('multipart-preset-select');

        toggleBtn.addEventListener('click', toggle);
        forwardBtn.addEventListener('click', () => decide('forward'));
        dropBtn.addEventListener('click', () => decide('drop'));
        document.getElementById('btn-multipart-add-part').addEventListener('click', addEmptyPart);
        document.getElementById('btn-multipart-apply-preset').addEventListener('click', applyPreset);

        _populatePresetDropdown();
        fetchStatus();
    }

    // ── Preset dropdown ──────────────────────────────────────────

    function _populatePresetDropdown() {
        if (!window.UploadPresets || !presetSelect) return;
        const cats = {};
        UploadPresets.forEach(p => {
            if (!cats[p.category]) cats[p.category] = [];
            cats[p.category].push(p);
        });
        Object.entries(cats).forEach(([cat, presets]) => {
            const og = document.createElement('optgroup');
            og.label = cat;
            presets.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.id;
                opt.textContent = p.name;
                opt.title = p.description || '';
                og.appendChild(opt);
            });
            presetSelect.appendChild(og);
        });
    }

    // ── Status / Toggle ──────────────────────────────────────────

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

    // ── Show flow ────────────────────────────────────────────────

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

            // Multipart detection
            if (flow.is_multipart && flow.multipart_parts) {
                bodyGroup.classList.add('hidden');
                multipartSection.classList.remove('hidden');
                _renderMultipartParts(flow.multipart_parts);
            } else {
                bodyGroup.classList.remove('hidden');
                multipartSection.classList.add('hidden');
            }
        } else {
            // Response phase — request info is read-only, response is editable
            bodyGroup.classList.remove('hidden');
            multipartSection.classList.add('hidden');
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

    // ── Multipart part rendering ─────────────────────────────────

    function _renderMultipartParts(parts) {
        multipartPartsEl.innerHTML = '';
        parts.forEach((part, idx) => {
            const card = document.createElement('div');
            card.className = 'multipart-part-card';
            card.dataset.idx = idx;

            const isFile = !!part.filename;
            const badgeClass = isFile ? 'badge-high' : 'badge-low';
            const badgeText = isFile ? 'FILE' : 'FIELD';
            const contentVal = part.is_binary ? (part.content_b64 || '') : (part.content_text || '');

            card.innerHTML =
                '<div class="multipart-part-header">' +
                    '<span class="badge ' + badgeClass + '">' + badgeText + '</span>' +
                    '<span class="multipart-part-name">' + esc(part.name || '') + '</span>' +
                    (part.filename ? '<span class="multipart-part-filename">' + esc(part.filename) + '</span>' : '') +
                    '<span class="multipart-part-size">' + _fmtSize(part.size || 0) + '</span>' +
                    '<button class="btn-small danger multipart-remove-btn" title="Remove part">&times;</button>' +
                '</div>' +
                '<div class="multipart-part-body">' +
                    '<div class="form-row" style="gap:6px;margin-bottom:6px">' +
                        '<div class="form-group half" style="margin-bottom:0">' +
                            '<label>Field Name</label>' +
                            '<input type="text" class="mp-name" value="' + _escAttr(part.name || '') + '">' +
                        '</div>' +
                        '<div class="form-group half" style="margin-bottom:0">' +
                            '<label>Filename</label>' +
                            '<input type="text" class="mp-filename" value="' + _escAttr(part.filename || '') + '"' +
                                (!isFile ? ' placeholder="(not a file field)"' : '') + '>' +
                        '</div>' +
                    '</div>' +
                    '<div class="form-group" style="margin-bottom:6px">' +
                        '<label>Content-Type</label>' +
                        '<input type="text" class="mp-content-type" value="' + _escAttr(part.content_type || 'text/plain') + '">' +
                    '</div>' +
                    '<div class="form-group" style="margin-bottom:0">' +
                        '<label>Content' + (part.is_binary ? ' <span class="badge badge-low">BASE64</span>' : '') + '</label>' +
                        '<textarea class="mp-content" rows="' + (part.is_binary ? 3 : 4) + '"' +
                            ' data-binary="' + (part.is_binary ? '1' : '0') + '">' +
                            esc(contentVal) +
                        '</textarea>' +
                    '</div>' +
                '</div>';

            // Toggle collapse on header click
            const header = card.querySelector('.multipart-part-header');
            header.addEventListener('click', (e) => {
                if (e.target.closest('.multipart-remove-btn')) return;
                header.classList.toggle('collapsed');
            });

            // Remove button
            card.querySelector('.multipart-remove-btn').addEventListener('click', () => card.remove());

            multipartPartsEl.appendChild(card);
        });
    }

    function _collectMultipartParts() {
        const parts = [];
        multipartPartsEl.querySelectorAll('.multipart-part-card').forEach(card => {
            const name = card.querySelector('.mp-name').value;
            const filename = card.querySelector('.mp-filename').value || null;
            const contentType = card.querySelector('.mp-content-type').value;
            const contentEl = card.querySelector('.mp-content');
            const isBinary = contentEl.dataset.binary === '1';
            const content = contentEl.value;

            parts.push({
                name: name,
                filename: filename,
                content_type: contentType,
                content_b64: isBinary ? content : null,
                content_text: isBinary ? null : content,
                is_binary: isBinary,
            });
        });
        return parts;
    }

    function addEmptyPart() {
        const parts = _collectMultipartParts();
        parts.push({
            name: 'newfield',
            filename: null,
            content_type: 'text/plain',
            content_text: '',
            content_b64: null,
            is_binary: false,
            size: 0,
        });
        _renderMultipartParts(parts);
    }

    function applyPreset() {
        const presetId = presetSelect.value;
        if (!presetId || !window.UploadPresets) return;
        const preset = UploadPresets.find(p => p.id === presetId);
        if (!preset) return;

        // Find first file part, or fall back to last part
        const cards = multipartPartsEl.querySelectorAll('.multipart-part-card');
        let target = null;
        for (const card of cards) {
            if (card.querySelector('.mp-filename').value) {
                target = card;
                break;
            }
        }
        if (!target && cards.length > 0) {
            target = cards[cards.length - 1];
        }

        if (target) {
            target.querySelector('.mp-filename').value = preset.filename;
            target.querySelector('.mp-content-type').value = preset.content_type;
            const contentEl = target.querySelector('.mp-content');
            if (preset.is_binary && preset.content_b64) {
                contentEl.value = preset.content_b64;
                contentEl.dataset.binary = '1';
            } else {
                contentEl.value = preset.content || '';
                contentEl.dataset.binary = '0';
            }
        }

        presetSelect.value = '';
    }

    // ── Decide (forward / drop) ──────────────────────────────────

    function decide(decision) {
        if (!currentFlow) return;

        let modifications = null;
        if (decision === 'forward') {
            modifications = {};
            if (currentFlow.phase === 'request') {
                modifications.method = methodEl.value;
                try { modifications.headers = JSON.parse(headersEl.value); } catch (_) {}

                // Multipart: send structured parts instead of raw body
                if (currentFlow.is_multipart && !multipartSection.classList.contains('hidden')) {
                    modifications.multipart_parts = _collectMultipartParts();
                    modifications.multipart_boundary = currentFlow.multipart_boundary;
                } else {
                    modifications.body = bodyEl.value;
                }
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
            bodyGroup.classList.remove('hidden');
            multipartSection.classList.add('hidden');
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
        const uploadBadge = flow.is_multipart ? ' <span class="badge badge-request">UPLOAD</span>' : '';
        item.innerHTML =
            badge + uploadBadge +
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

    // ── UI update ────────────────────────────────────────────────

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

    // ── Helpers ───────────────────────────────────────────────────

    function _fmtHeaders(hdrs) {
        if (!hdrs) return '{}';
        if (typeof hdrs === 'string') return hdrs;
        try { return JSON.stringify(hdrs, null, 2); } catch (_) { return '{}'; }
    }

    function _fmtSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function _escAttr(s) {
        return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    return { init, onInterceptedFlow };
})();
