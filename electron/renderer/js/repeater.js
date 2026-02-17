/**
 * Repeater — resend and tweak individual requests
 *
 * Token overlays: textareas get transparent overlays that tokenize
 * values for right-click AI injection suggestions (same as Intercept).
 */
window.Repeater = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let listEl, urlEl, methodEl, headersEl, bodyEl, responseEl, sendBtn;
    let history = []; // { id, method, url, headers, body, label }
    let selectedIdx = null;

    // Token overlay state
    const _overlays = {};         // fieldId → { el, overlay, wrapper, fieldType }
    let _activeToken = null;      // { fieldId, start, end, value, name }
    let _selectionDebounce = null;
    let _suggestTarget = null;

    // Revert-to-original state
    let _originalValues = null;   // { url, method, headers, body } | null
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

    // ── Revert helpers ────────────────────────────────────────────

    function _snapshotOriginals() {
        _originalValues = {
            url: urlEl ? urlEl.value : '',
            method: methodEl ? methodEl.value : 'GET',
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
        if (urlEl) urlEl.value = _originalValues.url;
        if (methodEl) methodEl.value = _originalValues.method;
        if (headersEl) headersEl.value = _originalValues.headers;
        if (bodyEl) bodyEl.value = _originalValues.body;
        if (revertBtn) revertBtn.classList.add('hidden');
        requestAnimationFrame(_refreshAllOverlays);
    }

    function init() {
        listEl     = document.getElementById('repeater-list');
        urlEl      = document.getElementById('repeater-url');
        methodEl   = document.getElementById('repeater-method');
        headersEl  = document.getElementById('repeater-headers');
        bodyEl     = document.getElementById('repeater-body');
        responseEl = document.getElementById('repeater-response');
        sendBtn    = document.getElementById('btn-repeater-send');
        revertBtn  = document.getElementById('btn-repeater-revert');

        sendBtn.addEventListener('click', send);
        if (revertBtn) revertBtn.addEventListener('click', _revertToOriginal);
        loadHistory();

        SendTo.register('repeater', {
            label: 'Repeater',
            receive(data) { addRequest(data); },
        });

        _initAiSuggest();
        _initAiSuggestButtons();
    }

    // ── AI Suggest integration (token overlay system) ──────────

    const _OVERLAY_FIELDS = {
        'repeater-headers': 'header',
        'repeater-body':    'body',
        'repeater-url':     'param',
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
            el.addEventListener('select', () => _updateSelectionGlow(el));
            el.addEventListener('keyup', () => _updateSelectionGlow(el));
            el.addEventListener('blur', () => el.classList.remove('has-selection'));
        });

        // When user picks a suggestion from the AiSuggest popup, replace the token
        document.addEventListener('ai-triage-select', (e) => {
            const payload = (e.detail && e.detail.payload) || '';
            if (!payload) return;
            // Prefer active token (right-click on overlay token)
            if (_activeToken && _overlays[_activeToken.fieldId]) {
                _applyTokenPayload(payload);
                return;
            }
            // Fallback: replace text selection in the last-focused field
            if (_suggestTarget && _isRepeaterField(_suggestTarget)) {
                _replaceTextSelection(_suggestTarget, payload);
                _suggestTarget = null;
            }
        });
    }

    function _isRepeaterField(el) {
        return el === urlEl || el === headersEl || el === bodyEl;
    }

    // ── AI Suggest buttons (send entire field) ────────────────────

    function _initAiSuggestButtons() {
        const aiBodyBtn = document.getElementById('btn-repeater-ai-body');

        if (aiBodyBtn) {
            aiBodyBtn.addEventListener('click', (e) => {
                e.preventDefault();
                _sendFieldToAiSuggest(bodyEl, 'body', e);
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

    function _onFieldMouseUp(e) {
        const el = e.target;
        if (el.disabled || el.readOnly) return;
        if (!_isRepeaterField(el)) return;

        clearTimeout(_selectionDebounce);
        _selectionDebounce = setTimeout(() => {
            _updateSelectionGlow(el);
            if (el.selectionStart === el.selectionEnd) return;
            const text = el.value.substring(el.selectionStart, el.selectionEnd).trim();
            if (!text || text.length < 2) return;

            _suggestTarget = el;
            _activeToken = null;

            const context = _buildSelectionContext(el, text);

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

        return {
            field_type: fieldType,
            field_name: fieldName,
            method: methodVal,
            url: urlVal,
            full_body: bodyVal.slice(0, 1000),
            full_headers: hdrs,
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

    // ── Token overlay system ────────────────────────────────────

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

        if (el.offsetParent === null || el.disabled) {
            wrapper.style.display = 'none';
            return;
        }
        wrapper.style.display = '';

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
                const pat1 = keyStr + ': ' + valStr;
                const pat2 = keyStr + ':' + valStr;
                let idx = text.indexOf(pat1);
                let sepLen = keyStr.length + 2;
                if (idx < 0) {
                    idx = text.indexOf(pat2);
                    sepLen = keyStr.length + 1;
                }
                if (idx >= 0) {
                    const valStart = idx + sepLen + 1;
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
        _suggestTarget = null;

        if (typeof AiSuggest === 'undefined') return;

        const info = _overlays[fieldId];
        const context = _buildSelectionContext(info ? info.el : null, token.value);
        // Override field_type from overlay info
        if (info) context.field_type = info.fieldType;
        context.field_name = token.name || '';

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

    // ── Original Repeater Logic ─────────────────────────────────

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
        // Snapshot for revert and refresh overlays
        _snapshotOriginals();
        requestAnimationFrame(_refreshAllOverlays);
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
            responseEl.innerHTML =
`<div class="repeater-response-block">
<div class="scan-header">
<span class="scan-badge">${data.status_code || data.error || '?'}</span>
<span class="scan-payload">${esc(method)} ${esc(url)}</span>
</div>
<div class="scan-detail-row"><strong>Response Headers:</strong></div>
${EPTUtils.headersBlock(data.headers || {})}
<div class="scan-detail-row"><strong>Response Body:</strong></div>
${EPTUtils.bodyPreBlock(data.body || data.error || '')}
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
