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
    let _lastPresetPayload = null; // raw content from last applied preset

    // DOM refs
    let toggleBtn, queueBadge, statusEl;
    let editorEl, emptyEl, historyEl;
    let phaseEl, hostEl, methodEl, urlEl, headersEl, bodyEl, bodyGroup;
    let respSection, respStatusEl, respHeadersEl, respBodyEl;
    let forwardBtn, dropBtn;
    let multipartSection, multipartPartsEl, presetSelect;
    let jsonUploadSection, jsonUploadFilesEl, jsonUploadPresetSelect, jsonUploadRawEl;
    let historyCountEl, interceptPane;

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

        jsonUploadSection      = document.getElementById('intercept-json-upload-section');
        jsonUploadFilesEl      = document.getElementById('intercept-json-upload-files');
        jsonUploadPresetSelect = document.getElementById('json-upload-preset-select');
        jsonUploadRawEl        = document.getElementById('intercept-json-upload-raw');

        toggleBtn.addEventListener('click', toggle);
        forwardBtn.addEventListener('click', () => decide('forward'));
        dropBtn.addEventListener('click', () => decide('drop'));
        document.getElementById('btn-multipart-add-part').addEventListener('click', addEmptyPart);
        document.getElementById('btn-multipart-apply-preset').addEventListener('click', applyPreset);
        document.getElementById('btn-multipart-copy-payload').addEventListener('click', _copyPresetPayload);
        document.getElementById('btn-json-upload-inject-data').addEventListener('click', _jsonUploadInjectData);
        document.getElementById('btn-json-upload-apply-preset').addEventListener('click', _applyJsonUploadPreset);
        document.getElementById('btn-json-upload-copy-payload').addEventListener('click', _copyPresetPayload);

        historyCountEl = document.getElementById('intercept-history-count');
        interceptPane  = document.querySelector('.tab-pane[data-tab="intercept"]');

        document.getElementById('btn-clear-intercept-history').addEventListener('click', clearHistory);
        document.getElementById('btn-collapse-intercept-history').addEventListener('click', toggleHistoryCollapse);

        _populatePresetDropdown();
        _initHistoryResize();
        fetchStatus();
    }

    // ── History resize / collapse / clear ─────────────────────────

    function _initHistoryResize() {
        const handle = document.getElementById('intercept-history-resize');
        if (!handle || !interceptPane) return;

        let dragging = false;

        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            dragging = true;
            handle.classList.add('dragging');
            document.body.style.cursor = 'ns-resize';
            document.body.style.userSelect = 'none';
        });

        document.addEventListener('mousemove', (e) => {
            if (!dragging) return;
            const paneRect = interceptPane.getBoundingClientRect();
            const newHeight = Math.max(60, Math.min(paneRect.bottom - e.clientY, paneRect.height - 120));
            interceptPane.style.setProperty('--intercept-history-height', newHeight + 'px');
        });

        document.addEventListener('mouseup', () => {
            if (!dragging) return;
            dragging = false;
            handle.classList.remove('dragging');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        });
    }

    function toggleHistoryCollapse() {
        if (!interceptPane) return;
        interceptPane.classList.toggle('history-collapsed');
        const btn = document.getElementById('btn-collapse-intercept-history');
        btn.innerHTML = interceptPane.classList.contains('history-collapsed') ? '&#9650;' : '&#9660;';
    }

    function clearHistory() {
        historyEl.innerHTML = '';
        _updateHistoryCount();
    }

    function _updateHistoryCount() {
        if (!historyCountEl) return;
        const n = historyEl.querySelectorAll('.intercept-history-entry').length;
        historyCountEl.textContent = n;
    }

    // ── Preset dropdown ──────────────────────────────────────────

    function _populatePresetDropdown() {
        if (!window.UploadPresets) return;
        const cats = {};
        UploadPresets.forEach(p => {
            if (!cats[p.category]) cats[p.category] = [];
            cats[p.category].push(p);
        });
        [presetSelect, jsonUploadPresetSelect].forEach(sel => {
            if (!sel) return;
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
                sel.appendChild(og);
            });
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
                jsonUploadSection.classList.add('hidden');
                _renderMultipartParts(flow.multipart_parts);
            } else if (flow.is_json_upload && flow.json_upload_files) {
                bodyGroup.classList.add('hidden');
                multipartSection.classList.add('hidden');
                jsonUploadSection.classList.remove('hidden');
                _renderJsonUploadFiles(flow.json_upload_files);
                jsonUploadRawEl.value = flow.body || '';
            } else {
                bodyGroup.classList.remove('hidden');
                multipartSection.classList.add('hidden');
                jsonUploadSection.classList.add('hidden');

            }
        } else {
            // Response phase — request info is read-only, response is editable
            bodyGroup.classList.remove('hidden');
            multipartSection.classList.add('hidden');
            jsonUploadSection.classList.add('hidden');
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

        // Store raw payload for Copy Payload button
        if (preset.is_binary && preset.content_b64) {
            _lastPresetPayload = preset.content_b64;
        } else {
            _lastPresetPayload = preset.content || '';
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
                } else if (currentFlow.is_json_upload && !jsonUploadSection.classList.contains('hidden')) {
                    modifications.json_upload_body = _collectJsonUploadBody();
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
            jsonUploadSection.classList.add('hidden');
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
        const uploadBadge = flow.is_multipart
            ? ' <span class="badge badge-request">UPLOAD</span>'
            : (flow.is_json_upload ? ' <span class="badge badge-request">JSON UPLOAD</span>' : '');
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
        _updateHistoryCount();
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

    // ── JSON file-upload rendering ──────────────────────────────

    const _FN_KEYS = ['filename', 'file_name', 'name', 'fileName'];
    const _MIME_KEYS = ['mime_type', 'content_type', 'mimeType', 'contentType', 'type'];
    const _SIZE_KEYS = ['file_size', 'size', 'fileSize', 'content_length'];
    const _DATA_KEYS = ['content', 'data', 'file_data', 'fileData', 'file_content', 'body', 'base64', 'b64'];

    function _getFieldKey(obj, keys) {
        for (const k of keys) { if (k in obj) return k; }
        return null;
    }

    function _renderJsonUploadFiles(files) {
        jsonUploadFilesEl.innerHTML = '';
        files.forEach((entry, idx) => {
            const f = entry.fields;
            const fnKey = _getFieldKey(f, _FN_KEYS);
            const mtKey = _getFieldKey(f, _MIME_KEYS);
            const szKey = _getFieldKey(f, _SIZE_KEYS);
            const dataKey = _getFieldKey(f, _DATA_KEYS);

            const filename = fnKey ? String(f[fnKey] || '') : '';
            const mimeType = mtKey ? String(f[mtKey] || '') : '';
            const sizeStr = szKey != null && f[szKey] != null ? _fmtSize(Number(f[szKey])) : '';

            const card = document.createElement('div');
            card.className = 'multipart-part-card';
            card.dataset.idx = idx;
            card.dataset.jsonPath = entry.json_path;

            // Build known-field inputs
            const knownKeys = new Set([fnKey, mtKey, szKey, dataKey].filter(Boolean));
            let fieldsHtml = '';
            if (fnKey) fieldsHtml += _juField('Filename', 'ju-filename', fnKey, filename);
            if (mtKey) fieldsHtml += _juField('MIME Type', 'ju-mimetype', mtKey, mimeType);
            if (szKey) fieldsHtml += _juField('File Size', 'ju-filesize', szKey, String(f[szKey] ?? ''));
            if (dataKey) fieldsHtml += _juField('Data / Content', 'ju-data', dataKey, String(f[dataKey] ?? ''), true);

            // Other fields
            for (const [k, v] of Object.entries(f)) {
                if (knownKeys.has(k)) continue;
                fieldsHtml += _juField(k, 'ju-other', k, String(v ?? ''));
            }

            card.innerHTML =
                '<div class="multipart-part-header">' +
                    '<span class="badge badge-high">FILE</span>' +
                    '<span class="multipart-part-name">' + esc(entry.json_path) + '</span>' +
                    '<span class="multipart-part-filename">' + esc(filename) + '</span>' +
                    (sizeStr ? '<span class="multipart-part-size">' + sizeStr + '</span>' : '') +
                '</div>' +
                '<div class="multipart-part-body">' + fieldsHtml + '</div>';

            card.querySelector('.multipart-part-header').addEventListener('click', (e) => {
                e.currentTarget.classList.toggle('collapsed');
            });

            jsonUploadFilesEl.appendChild(card);
        });
    }

    function _juField(label, cssClass, key, value, isTextarea) {
        const keyBadge = '<span class="badge badge-low" style="margin-left:4px;font-size:9px">' + esc(key) + '</span>';
        if (isTextarea) {
            return '<div class="form-group" style="margin-bottom:6px">' +
                '<label>' + esc(label) + keyBadge + '</label>' +
                '<textarea class="' + cssClass + '" rows="3" data-key="' + _escAttr(key) + '">' + esc(value) + '</textarea>' +
                '</div>';
        }
        return '<div class="form-group" style="margin-bottom:6px">' +
            '<label>' + esc(label) + keyBadge + '</label>' +
            '<input type="text" class="' + cssClass + '" value="' + _escAttr(value) + '" data-key="' + _escAttr(key) + '">' +
            '</div>';
    }

    function _collectJsonUploadBody() {
        let parsed;
        try {
            parsed = JSON.parse(jsonUploadRawEl.value);
        } catch (_) {
            return jsonUploadRawEl.value;
        }

        jsonUploadFilesEl.querySelectorAll('.multipart-part-card').forEach(card => {
            const target = _resolveJsonPath(parsed, card.dataset.jsonPath);
            if (!target || typeof target !== 'object') return;

            card.querySelectorAll('input[data-key], textarea[data-key]').forEach(el => {
                const key = el.dataset.key;
                let val = el.value;
                // Preserve number types
                if (typeof target[key] === 'number') {
                    const num = Number(val);
                    if (!isNaN(num)) val = num;
                }
                target[key] = val;
            });
        });

        return JSON.stringify(parsed, null, 2);
    }

    function _resolveJsonPath(obj, path) {
        if (!path || path === '(root)') return obj;
        const parts = path.replace(/\[(\d+)\]/g, '.$1').split('.').filter(Boolean);
        let cur = obj;
        for (const p of parts) {
            if (cur == null) return null;
            cur = cur[/^\d+$/.test(p) ? Number(p) : p];
        }
        return cur;
    }

    function _jsonUploadInjectData() {
        const cards = jsonUploadFilesEl.querySelectorAll('.multipart-part-card');
        if (cards.length === 0) return;
        const card = cards[0];

        if (card.querySelector('.ju-data')) {
            card.querySelector('.ju-data').focus();
            return;
        }

        const group = document.createElement('div');
        group.className = 'form-group';
        group.style.marginBottom = '6px';
        group.innerHTML =
            '<label>Injected Data <span class="badge badge-low" style="margin-left:4px;font-size:9px">content</span></label>' +
            '<textarea class="ju-data" rows="3" data-key="content" placeholder="Paste base64-encoded file content here..."></textarea>';
        card.querySelector('.multipart-part-body').appendChild(group);
    }

    function _applyJsonUploadPreset() {
        const presetId = jsonUploadPresetSelect.value;
        if (!presetId || !window.UploadPresets) return;
        const preset = UploadPresets.find(p => p.id === presetId);
        if (!preset) return;

        const cards = jsonUploadFilesEl.querySelectorAll('.multipart-part-card');
        if (cards.length === 0) return;
        const card = cards[0];

        // Apply filename
        const fnInput = card.querySelector('.ju-filename');
        if (fnInput) fnInput.value = preset.filename;

        // Apply MIME type
        const mtInput = card.querySelector('.ju-mimetype');
        if (mtInput) mtInput.value = preset.content_type;

        // Calculate payload byte size (independent of data field injection)
        let payloadBytes = 0;
        if (preset.is_binary && preset.content_b64) {
            payloadBytes = preset.content_b64.length;
        } else if (preset.content) {
            payloadBytes = new Blob([preset.content]).size;
        }

        // Inject content into data field (base64-encode text for JSON transport)
        let dataEl = card.querySelector('.ju-data');
        if (!dataEl) {
            _jsonUploadInjectData();
            dataEl = card.querySelector('.ju-data');
        }
        if (dataEl) {
            if (preset.is_binary && preset.content_b64) {
                dataEl.value = preset.content_b64;
            } else {
                try { dataEl.value = btoa(preset.content || ''); } catch (_) { dataEl.value = preset.content || ''; }
            }
        }

        // Auto-update file_size to match payload so the server doesn't
        // reject with a size mismatch.
        const szInput = card.querySelector('.ju-filesize');
        if (szInput) szInput.value = String(payloadBytes);

        // Store raw payload for the Copy Payload button
        if (preset.is_binary && preset.content_b64) {
            _lastPresetPayload = preset.content_b64;
        } else {
            _lastPresetPayload = preset.content || '';
        }

        // Sync changes into the raw JSON textarea
        const rebuilt = _collectJsonUploadBody();
        if (typeof rebuilt === 'string') jsonUploadRawEl.value = rebuilt;

        jsonUploadPresetSelect.value = '';
    }

    function _copyPresetPayload() {
        if (!_lastPresetPayload) return;
        navigator.clipboard.writeText(_lastPresetPayload).then(() => {
            const btn = document.getElementById('btn-json-upload-copy-payload');
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1500);
        });
    }

    return { init, onInterceptedFlow };
})();
