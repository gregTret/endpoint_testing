/**
 * Intercept — Burp-style proxy intercept mode.
 *
 * Toggle on → every request/response flowing through mitmproxy
 * is paused and shown for editing.  User can Forward or Drop.
 *
 * Multipart/form-data requests get a specialised per-part editor
 * with preset attack templates for file-upload security testing.
 *
 * Token overlays: textareas get transparent overlays that tokenize
 * values for right-click AI injection suggestions.
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

    // Token overlay state
    const _overlays = {};         // fieldId → { el, overlay, wrapper, fieldType }
    let _activeToken = null;      // { fieldId, start, end, value, name }
    let _selectionDebounce = null; // timer for mouseup text-selection trigger

    // Revert-to-original state
    let _originalValues = null;   // { method, url, headers, body } | null
    let revertBtn = null;

    // ── JSON-safe replacement helper ─────────────────────────────

    function _jsonSafeReplace(fieldValue, start, end, payload) {
        const trimmed = fieldValue.trim();
        if (trimmed[0] !== '{' && trimmed[0] !== '[') {
            return fieldValue.substring(0, start) + payload + fieldValue.substring(end);
        }
        try { JSON.parse(trimmed); } catch (_) {
            return fieldValue.substring(0, start) + payload + fieldValue.substring(end);
        }
        // Field is valid JSON — check if the token sits inside a JSON string
        let inString = false;
        for (let i = start - 1; i >= 0; i--) {
            const ch = fieldValue[i];
            if (ch === '"' && (i === 0 || fieldValue[i - 1] !== '\\')) {
                inString = true;
                break;
            }
            if (ch === ':' || ch === ',' || ch === '{' || ch === '[' || ch === '}' || ch === ']') {
                break;
            }
        }
        if (inString) {
            const escaped = JSON.stringify(payload).slice(1, -1);
            return fieldValue.substring(0, start) + escaped + fieldValue.substring(end);
        }
        return fieldValue.substring(0, start) + payload + fieldValue.substring(end);
    }

    /**
     * Check if a cursor position inside a textarea sits within a JSON string value.
     * Used to tell the AI backend to return JSON-compatible payloads.
     */
    function _isInsideJsonString(el, pos) {
        if (!el) return false;
        const text = el.value || '';
        const trimmed = text.trim();
        if (trimmed[0] !== '{' && trimmed[0] !== '[') return false;
        try { JSON.parse(trimmed); } catch (_) { return false; }
        // Walk backwards from pos looking for an unescaped quote
        for (let i = pos - 1; i >= 0; i--) {
            const ch = text[i];
            if (ch === '"' && (i === 0 || text[i - 1] !== '\\')) return true;
            if (ch === ':' || ch === ',' || ch === '{' || ch === '[' || ch === '}' || ch === ']') return false;
        }
        return false;
    }

    // ── Revert helpers ────────────────────────────────────────────

    function _snapshotOriginals() {
        _originalValues = {
            method: methodEl ? methodEl.value : 'GET',
            url: urlEl ? urlEl.value : '',
            headers: headersEl ? headersEl.value : '',
            body: bodyEl ? bodyEl.value : '',
        };
        if (revertBtn) revertBtn.classList.add('hidden');
    }

    function _showRevert() {
        if (revertBtn) revertBtn.classList.remove('hidden');
    }

    function _revertToOriginal() {
        if (!_originalValues) return;
        if (methodEl) methodEl.value = _originalValues.method;
        if (urlEl) urlEl.value = _originalValues.url;
        if (headersEl) headersEl.value = _originalValues.headers;
        if (bodyEl) bodyEl.value = _originalValues.body;
        if (revertBtn) revertBtn.classList.add('hidden');
        requestAnimationFrame(_refreshAllOverlays);
    }

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
        revertBtn      = document.getElementById('btn-intercept-revert');

        if (revertBtn) revertBtn.addEventListener('click', _revertToOriginal);
        document.getElementById('btn-clear-intercept-history').addEventListener('click', clearHistory);
        document.getElementById('btn-collapse-intercept-history').addEventListener('click', toggleHistoryCollapse);

        _populatePresetDropdown();
        _initHistoryResize();
        _initAiSuggest();
        _initAiSuggestButtons();
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
        // Snapshot for revert and refresh overlays
        _snapshotOriginals();
        requestAnimationFrame(_refreshAllOverlays);
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

                // Update flow with editor values so history reflects what was actually sent
                currentFlow.method = modifications.method;
                currentFlow.url = urlEl.value;
                if (modifications.headers) currentFlow.headers = modifications.headers;
                if (modifications.body !== undefined) {
                    currentFlow.body = modifications.body;
                } else if (modifications.json_upload_body !== undefined) {
                    currentFlow.body = modifications.json_upload_body;
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

    // ── AI Suggest integration (token overlay system) ──────────

    const _OVERLAY_FIELDS = {
        'intercept-headers': 'header',
        'intercept-body':    'body',
        'intercept-url':     'param',
    };

    function _initAiSuggest() {
        // Build transparent overlay for each editable field
        for (const [id, fieldType] of Object.entries(_OVERLAY_FIELDS)) {
            const el = document.getElementById(id);
            if (!el) continue;
            _buildOverlay(el, id, fieldType);
        }

        // Mode 1: text selection via mouseup with 300ms debounce
        const selectableEls = [headersEl, bodyEl, urlEl];
        selectableEls.forEach(el => {
            if (!el) return;
            el.addEventListener('mouseup', _onFieldMouseUp);
            // Track selection glow
            el.addEventListener('select', () => _updateSelectionGlow(el));
            el.addEventListener('keyup', () => _updateSelectionGlow(el));
            el.addEventListener('blur', () => el.classList.remove('has-selection'));
        });

        // When user picks a suggestion from the AiSuggest popup, replace the token
        document.addEventListener('ai-triage-select', (e) => {
            const payload = (e.detail && e.detail.payload) || '';
            if (!payload) return;
            // Prefer active token (right-click on overlay token)
            if (_activeToken) {
                _applyTokenPayload(payload);
                return;
            }
            // Fallback: replace text selection in the last-focused field
            // Guard: only act if target is an intercept field
            if (_suggestTarget && _isInterceptField(_suggestTarget)) {
                _replaceTextSelection(_suggestTarget, payload);
                _suggestTarget = null;
            }
        });
    }

    function _isInterceptField(el) {
        return el === urlEl || el === headersEl || el === bodyEl ||
               el === respHeadersEl || el === respBodyEl;
    }

    // ── AI Suggest buttons (send entire field) ────────────────────

    function _initAiSuggestButtons() {
        const aiBodyBtn = document.getElementById('btn-intercept-ai-body');
        const aiHeadersBtn = document.getElementById('btn-intercept-ai-headers');

        if (aiBodyBtn) {
            aiBodyBtn.addEventListener('click', (e) => {
                e.preventDefault();
                _sendFieldToAiSuggest(bodyEl, 'body', e);
            });
        }
        if (aiHeadersBtn) {
            aiHeadersBtn.addEventListener('click', (e) => {
                e.preventDefault();
                _sendFieldToAiSuggest(headersEl, 'header', e);
            });
        }
    }

    function _sendFieldToAiSuggest(el, fieldType, e) {
        if (!el || !el.value.trim()) return;
        if (typeof AiSuggest === 'undefined') return;

        const text = el.value.trim();
        _suggestTarget = el;
        _activeToken = null;

        // Select all text so the replacement works on the full content
        el.selectionStart = 0;
        el.selectionEnd = el.value.length;
        el.classList.add('has-selection');

        const context = _buildSelectionContext(el, text);

        const rect = {
            top: e.clientY,
            bottom: e.clientY + 2,
            left: e.clientX,
            right: e.clientX + 2,
        };

        AiSuggest.showForSelection(text, context, rect);
    }

    // ── Selection glow indicator ─────────────────────────────────

    function _updateSelectionGlow(el) {
        if (el.selectionStart !== el.selectionEnd) {
            el.classList.add('has-selection');
        } else {
            el.classList.remove('has-selection');
        }
    }

    // ── Mode 1: text selection trigger ───────────────────────────

    let _suggestTarget = null;

    function _onFieldMouseUp(e) {
        const el = e.target;
        if (el.disabled || el.readOnly) return;

        clearTimeout(_selectionDebounce);
        _selectionDebounce = setTimeout(() => {
            _updateSelectionGlow(el);
            if (el.selectionStart === el.selectionEnd) return;
            const text = el.value.substring(el.selectionStart, el.selectionEnd).trim();
            if (!text || text.length < 2) return;

            _suggestTarget = el;
            _activeToken = null; // clear overlay token since this is a manual selection

            const context = _buildSelectionContext(el, text);

            // Approximate anchor position from mouse event
            const rect = {
                top: e.clientY,
                bottom: e.clientY + 2,
                left: e.clientX,
                right: e.clientX + 2,
            };

            if (typeof AiSuggest !== 'undefined') {
                AiSuggest.showForSelection(text, context, rect);
            }
        }, 300);
    }

    function _buildSelectionContext(el, text) {
        const methodVal = methodEl ? methodEl.value : 'GET';
        const urlVal = urlEl ? urlEl.value : '';
        const bodyVal = bodyEl ? bodyEl.value : '';
        let hdrs = {};
        try { hdrs = JSON.parse(headersEl ? headersEl.value : '{}'); } catch (_) {}

        let fieldType = 'param';
        if (el === urlEl) fieldType = 'url';
        else if (el === headersEl) fieldType = 'header';
        else if (el === bodyEl) fieldType = 'body';

        // Try to find the field name (key) for this value
        let fieldName = 'unknown';
        if (el === urlEl) {
            const qIdx = urlVal.indexOf('?');
            if (qIdx !== -1) {
                const pairs = urlVal.substring(qIdx + 1).split('&');
                for (const p of pairs) {
                    const eqIdx = p.indexOf('=');
                    if (eqIdx !== -1 && decodeURIComponent(p.substring(eqIdx + 1)) === text) {
                        fieldName = p.substring(0, eqIdx);
                        break;
                    }
                }
            }
            if (fieldName === 'unknown') fieldName = 'url_path';
        } else {
            const val = el.value;
            const idx = val.indexOf(text);
            if (idx > 0) {
                const before = val.substring(Math.max(0, idx - 100), idx);
                const keyMatch = before.match(/"([^"]+)"\s*:\s*"?$/);
                if (keyMatch) fieldName = keyMatch[1];
            }
        }

        const isJsonValue = _isInsideJsonString(el, el.selectionStart);

        return {
            field_type: fieldType,
            field_name: fieldName,
            method: methodVal,
            url: urlVal,
            full_body: bodyVal.slice(0, 1000),
            full_headers: hdrs,
            is_json_value: isJsonValue,
        };
    }

    function _replaceTextSelection(el, replacement) {
        if (!el) return;
        const start = el.selectionStart;
        const end = el.selectionEnd;
        if (start === end) return;
        el.value = _jsonSafeReplace(el.value, start, end, replacement);
        el.selectionStart = el.selectionEnd = start + replacement.length;
        el.classList.remove('has-selection');
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.focus();
        _showRevert();
        _flashInjectConfirm();
    }

    function _buildOverlay(el, id, fieldType) {
        const wrapper = document.createElement('div');
        wrapper.className = 'intercept-token-wrapper';

        const overlay = document.createElement('div');
        overlay.className = 'intercept-token-overlay';
        overlay.dataset.fieldId = id;

        el.parentNode.style.position = 'relative';
        el.parentNode.insertBefore(wrapper, el.nextSibling);
        wrapper.appendChild(overlay);

        _overlays[id] = { el, overlay, wrapper, fieldType };

        el.addEventListener('input', () => _refreshOverlay(id));
        el.addEventListener('scroll', () => {
            overlay.scrollTop = el.scrollTop;
            overlay.scrollLeft = el.scrollLeft;
        });

        const ro = new ResizeObserver(() => _refreshOverlay(id));
        ro.observe(el);
    }

    function _refreshAllOverlays() {
        for (const id of Object.keys(_overlays)) {
            _refreshOverlay(id);
        }
    }

    function _refreshOverlay(id) {
        const info = _overlays[id];
        if (!info) return;
        const el = info.el;
        const overlay = info.overlay;
        const wrapper = info.wrapper;

        // Hide overlay if field is invisible or disabled
        if (el.offsetParent === null || el.disabled) {
            wrapper.style.display = 'none';
            return;
        }
        wrapper.style.display = '';

        // Position and size to match the field exactly
        wrapper.style.position = 'absolute';
        wrapper.style.left = el.offsetLeft + 'px';
        wrapper.style.top = el.offsetTop + 'px';
        wrapper.style.width = el.offsetWidth + 'px';
        wrapper.style.height = el.offsetHeight + 'px';
        wrapper.style.overflow = 'hidden';
        wrapper.style.pointerEvents = 'none';
        wrapper.style.zIndex = '5';

        const cs = getComputedStyle(el);
        overlay.style.fontFamily = cs.fontFamily;
        overlay.style.fontSize = cs.fontSize;
        overlay.style.lineHeight = cs.lineHeight;
        overlay.style.letterSpacing = cs.letterSpacing;
        overlay.style.padding = cs.padding;
        overlay.style.whiteSpace = el.tagName === 'TEXTAREA' ? 'pre-wrap' : 'pre';
        overlay.style.overflowWrap = 'break-word';
        overlay.style.wordBreak = cs.wordBreak;
        overlay.style.width = '100%';
        overlay.style.height = '100%';
        overlay.style.overflow = 'hidden';
        overlay.style.color = 'transparent';
        overlay.style.border = 'none';
        overlay.style.background = 'transparent';

        overlay.scrollTop = el.scrollTop;
        overlay.scrollLeft = el.scrollLeft;

        // Tokenize and render
        const text = el.value;
        const tokens = _tokenizeField(text, info.fieldType);
        overlay.innerHTML = '';

        let lastIdx = 0;
        for (const tok of tokens) {
            if (tok.start > lastIdx) {
                overlay.appendChild(document.createTextNode(text.slice(lastIdx, tok.start)));
            }
            const span = document.createElement('span');
            span.className = 'intercept-token';
            span.textContent = tok.value;
            span.dataset.start = tok.start;
            span.dataset.end = tok.end;
            span.dataset.fieldId = id;
            span.dataset.name = tok.name || '';
            span.style.pointerEvents = 'auto';
            span.style.cursor = 'context-menu';

            span.addEventListener('mouseenter', () => span.classList.add('intercept-token-hover'));
            span.addEventListener('mouseleave', () => span.classList.remove('intercept-token-hover'));
            span.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                _onTokenContext(e, id, tok);
            });
            overlay.appendChild(span);
            lastIdx = tok.end;
        }
        if (lastIdx < text.length) {
            overlay.appendChild(document.createTextNode(text.slice(lastIdx)));
        }
    }

    // ── Tokenizers ───────────────────────────────────────────────

    function _tokenizeField(text, fieldType) {
        if (fieldType === 'header') return _tokenizeHeadersJSON(text);
        if (fieldType === 'body')   return _tokenizeBody(text);
        if (fieldType === 'param')  return _tokenizeUrl(text);
        return [];
    }

    function _tokenizeHeadersJSON(text) {
        const tokens = [];
        try {
            const parsed = JSON.parse(text);
            for (const [key, val] of Object.entries(parsed)) {
                if (typeof val !== 'string') continue;
                const valStr = JSON.stringify(val);
                const keyStr = JSON.stringify(key);
                // Match  "key": "value"  or  "key":"value"
                const pat1 = keyStr + ': ' + valStr;
                const pat2 = keyStr + ':' + valStr;
                let idx = text.indexOf(pat1);
                let sepLen = keyStr.length + 2; // ": "
                if (idx < 0) {
                    idx = text.indexOf(pat2);
                    sepLen = keyStr.length + 1;
                }
                if (idx >= 0) {
                    const valStart = idx + sepLen + 1; // +1 skip opening "
                    const valEnd = valStart + val.length;
                    if (valEnd <= text.length && val.length > 0) {
                        tokens.push({ start: valStart, end: valEnd, value: val, name: key });
                    }
                }
            }
        } catch (_) {}
        return tokens;
    }

    function _tokenizeBody(text) {
        const tokens = [];
        const trimmed = text.trim();
        if (!trimmed) return tokens;

        if (trimmed[0] === '{' || trimmed[0] === '[') {
            try {
                const parsed = JSON.parse(trimmed);
                _walkJSON(parsed, trimmed, tokens, '', new Set());
                return tokens;
            } catch (_) {}
        }

        // URL-encoded form
        if (trimmed.includes('=') && !trimmed.includes('<')) {
            const pairs = trimmed.split('&');
            let offset = 0;
            for (const pair of pairs) {
                const eqIdx = pair.indexOf('=');
                if (eqIdx > 0) {
                    const key = pair.slice(0, eqIdx);
                    const val = pair.slice(eqIdx + 1);
                    if (val.length > 0) {
                        const valStart = offset + eqIdx + 1;
                        tokens.push({ start: valStart, end: valStart + val.length, value: val, name: key });
                    }
                }
                offset += pair.length + 1;
            }
        }
        return tokens;
    }

    function _walkJSON(obj, fullText, tokens, prefix, usedPositions) {
        if (obj === null || obj === undefined) return;
        if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
            const valStr = JSON.stringify(obj);
            let from = 0;
            while (from < fullText.length) {
                const idx = fullText.indexOf(valStr, from);
                if (idx < 0) break;
                if (!usedPositions.has(idx)) {
                    const innerStart = typeof obj === 'string' ? idx + 1 : idx;
                    const innerEnd = typeof obj === 'string' ? idx + valStr.length - 1 : idx + valStr.length;
                    if (innerEnd > innerStart) {
                        tokens.push({ start: innerStart, end: innerEnd, value: String(obj), name: prefix || 'value' });
                        usedPositions.add(idx);
                    }
                    break;
                }
                from = idx + 1;
            }
            return;
        }
        if (Array.isArray(obj)) {
            obj.forEach((item, i) => _walkJSON(item, fullText, tokens, prefix ? prefix + '[' + i + ']' : '[' + i + ']', usedPositions));
            return;
        }
        if (typeof obj === 'object') {
            for (const [k, v] of Object.entries(obj)) {
                _walkJSON(v, fullText, tokens, prefix ? prefix + '.' + k : k, usedPositions);
            }
        }
    }

    function _tokenizeUrl(text) {
        const tokens = [];
        try {
            const url = new URL(text);
            for (const [key, val] of url.searchParams.entries()) {
                if (!val) continue;
                const encoded = encodeURIComponent(val);
                const searchStr = key + '=' + encoded;
                const idx = text.indexOf(searchStr);
                if (idx >= 0) {
                    const valStart = idx + key.length + 1;
                    tokens.push({ start: valStart, end: valStart + encoded.length, value: val, name: key });
                }
            }
            const pathStart = text.indexOf(url.pathname);
            if (pathStart >= 0) {
                const segments = url.pathname.split('/').filter(Boolean);
                let segOff = pathStart + 1;
                for (const seg of segments) {
                    const segIdx = text.indexOf(seg, segOff);
                    if (segIdx >= 0 && seg.length > 0) {
                        tokens.push({ start: segIdx, end: segIdx + seg.length, value: seg, name: 'path' });
                        segOff = segIdx + seg.length + 1;
                    }
                }
            }
        } catch (_) {}
        return tokens;
    }

    // ── Token right-click → AiSuggest popup ─────────────────────

    function _onTokenContext(e, fieldId, token) {
        _activeToken = { fieldId, start: token.start, end: token.end, value: token.value, name: token.name };
        _suggestTarget = null; // clear text-selection mode — token mode takes priority

        if (typeof AiSuggest === 'undefined') return;

        const info = _overlays[fieldId];
        const methodVal = methodEl ? methodEl.value : 'GET';
        const urlVal = urlEl ? urlEl.value : '';
        const bodyVal = bodyEl ? bodyEl.value : '';
        let hdrs = {};
        try { hdrs = JSON.parse(headersEl ? headersEl.value : '{}'); } catch (_) {}

        // Detect if the token is inside a JSON string value
        const isJsonValue = _isInsideJsonString(info ? info.el : null, token.start);

        const context = {
            field_type: info ? info.fieldType : 'param',
            field_name: token.name || '',
            method: methodVal,
            url: urlVal,
            full_body: bodyVal.slice(0, 1000),
            full_headers: hdrs,
            is_json_value: isJsonValue,
        };

        const rect = {
            top: e.clientY,
            bottom: e.clientY + 2,
            left: e.clientX,
            right: e.clientX + 2,
        };

        AiSuggest.showForSelection(token.value, context, rect);
    }

    function _applyTokenPayload(payload) {
        if (!_activeToken) return;
        const info = _overlays[_activeToken.fieldId];
        if (!info) return;

        const el = info.el;
        el.value = _jsonSafeReplace(el.value, _activeToken.start, _activeToken.end, payload);
        el.dispatchEvent(new Event('input', { bubbles: true }));

        _showRevert();
        _flashInjectConfirm();
        _activeToken = null;
    }

    function _flashInjectConfirm() {
        const flash = document.createElement('div');
        flash.className = 'intercept-inject-flash';
        flash.textContent = 'Payload injected';
        document.body.appendChild(flash);
        requestAnimationFrame(() => flash.classList.add('visible'));
        setTimeout(() => {
            flash.classList.remove('visible');
            setTimeout(() => flash.remove(), 300);
        }, 1200);
    }

    return { init, onInterceptedFlow };
})();
