/**
 * EPTUtils — shared UI utilities for body formatting, copy, canary
 * highlighting, and raw HTTP request parsing.
 */
window.EPTUtils = (() => {
    // Known canary/marker strings used by injectors for detection
    const KNOWN_CANARIES = ['EPT_CMD_9f3a7c', 'x5s7k9q', '9799447'];

    /**
     * Format a body string for display.
     * Detects JSON and pretty-prints it; formats URL-encoded bodies;
     * handles truncated JSON with best-effort indentation.
     * Returns { text, isJson } so callers can apply syntax coloring.
     */
    function formatBody(bodyStr) {
        if (!bodyStr) return { text: '(empty)', isJson: false };
        let trimmed = bodyStr.trim();

        // Strip common security prefixes from JSON responses
        const prefixes = [")]}'\n", ")]}'", "for(;;);", "while(1);"];
        for (const p of prefixes) {
            if (trimmed.startsWith(p)) { trimmed = trimmed.slice(p.length).trim(); break; }
        }

        // Try JSON parse
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try {
                return { text: JSON.stringify(JSON.parse(trimmed), null, 2), isJson: true };
            } catch (_) {
                // Truncated JSON — best-effort indent
                return { text: _indentJson(trimmed), isJson: true };
            }
        }

        // URL-encoded form body
        if (/^[a-zA-Z0-9_%\-.]+=/.test(trimmed) && trimmed.includes('&')) {
            try {
                const pairs = trimmed.split('&').map(p => {
                    const [k, ...rest] = p.split('=');
                    return decodeURIComponent(k) + ' = ' + decodeURIComponent(rest.join('='));
                });
                return { text: pairs.join('\n'), isJson: false };
            } catch (_) {}
        }

        return { text: bodyStr, isJson: false };
    }

    /**
     * Best-effort indentation for truncated/invalid JSON.
     */
    function _indentJson(str) {
        let indent = 0;
        let out = '';
        let inString = false;
        let escaped = false;
        for (let i = 0; i < str.length; i++) {
            const ch = str[i];
            if (escaped) { out += ch; escaped = false; continue; }
            if (ch === '\\' && inString) { out += ch; escaped = true; continue; }
            if (ch === '"') { inString = !inString; out += ch; continue; }
            if (inString) { out += ch; continue; }
            if (ch === '{' || ch === '[') {
                out += ch + '\n' + '  '.repeat(++indent);
            } else if (ch === '}' || ch === ']') {
                out += '\n' + '  '.repeat(--indent < 0 ? (indent = 0) : indent) + ch;
            } else if (ch === ',') {
                out += ',\n' + '  '.repeat(indent);
            } else if (ch === ':') {
                out += ': ';
            } else if (ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t') {
                // skip original whitespace
            } else {
                out += ch;
            }
        }
        return out;
    }

    /** Escape HTML for safe insertion via innerHTML. */
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    /** Escape a string for safe use inside an HTML attribute (double-quoted). */
    function escAttr(s) {
        return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    /**
     * Wrap known canary strings in <mark> tags.
     * Called AFTER esc() so canaries are plain text, safe to wrap.
     */
    function highlightCanaries(escapedHtml) {
        let result = escapedHtml;
        for (const canary of KNOWN_CANARIES) {
            result = result.replaceAll(
                canary,
                `<mark class="canary-highlight" title="Test canary marker">${canary}</mark>`
            );
        }
        return result;
    }

    /**
     * Build a <pre> block with hover-reveal copy button and JSON syntax coloring.
     * @param {string} bodyStr  Raw body text
     * @returns {string} HTML string
     */
    function bodyPreBlock(bodyStr) {
        const { text, isJson } = formatBody(bodyStr);
        const id = 'body-' + Math.random().toString(36).slice(2, 10);
        let escaped = esc(text);
        escaped = highlightCanaries(escaped);
        if (isJson) escaped = _colorizeJson(escaped);
        const copyIcon = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
        return `<div class="body-pre-wrapper"><button class="btn-copy-body" data-copy-target="${id}" title="Copy to clipboard">${copyIcon}</button><pre class="scan-response-body" id="${id}">${escaped}</pre></div>`;
    }

    /**
     * Apply syntax coloring to HTML-escaped pretty-printed JSON.
     */
    function _colorizeJson(html) {
        return html
            // Keys — "key":
            .replace(/^(\s*)("(?:[^"\\]|\\.)*")(\s*:)/gm,
                '$1<span class="json-key">$2</span>$3')
            // String values — : "value"  (not already wrapped in a span)
            .replace(/(:\s*)("(?:[^"\\]|\\.)*")/g,
                '$1<span class="json-str">$2</span>')
            // Numbers
            .replace(/(:\s*)(-?\d+\.?\d*(?:[eE][+-]?\d+)?)\b/g,
                '$1<span class="json-num">$2</span>')
            // Booleans
            .replace(/(:\s*)(true|false)\b/g,
                '$1<span class="json-bool">$2</span>')
            // Null
            .replace(/(:\s*)(null)\b/g,
                '$1<span class="json-null">$2</span>');
    }

    /**
     * Parse a raw HTTP request string into form-compatible fields.
     *
     * Expected format:
     *   POST /api/users?id=1 HTTP/1.1
     *   Host: example.com
     *   Authorization: Bearer xxx
     *
     *   {"body":"data"}
     *
     * @returns {{ method, url, headers, params, body } | null}
     */
    function parseRawHttp(raw) {
        const lines = raw.replace(/\r\n/g, '\n').split('\n');
        if (!lines.length) return null;

        const reqLine = lines[0].trim();
        const match = reqLine.match(/^(\w+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/i);
        if (!match) return null;

        const method = match[1].toUpperCase();
        const pathOrUrl = match[2];

        const headers = {};
        let i = 1;
        for (; i < lines.length; i++) {
            const line = lines[i];
            if (line.trim() === '') { i++; break; }
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                const key = line.substring(0, colonIdx).trim();
                const val = line.substring(colonIdx + 1).trim();
                headers[key] = val;
            }
        }

        const body = lines.slice(i).join('\n').trim();

        const host = headers['Host'] || headers['host'] || '';
        delete headers['Host'];
        delete headers['host'];

        let url;
        if (pathOrUrl.startsWith('http://') || pathOrUrl.startsWith('https://')) {
            url = pathOrUrl;
        } else {
            url = host ? `https://${host}${pathOrUrl}` : pathOrUrl;
        }

        const params = {};
        try {
            const u = new URL(url);
            u.searchParams.forEach((v, k) => { params[k] = v; });
        } catch (_) {}

        return { method, url, headers, params, body };
    }

    const _copyIcon = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    const _checkIcon = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';

    // Delegated click handler for copy buttons
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-copy-body');
        if (!btn) return;
        const targetId = btn.dataset.copyTarget;
        const pre = document.getElementById(targetId);
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent).then(() => {
            btn.innerHTML = _checkIcon;
            btn.style.color = 'var(--success)';
            setTimeout(() => { btn.innerHTML = _copyIcon; btn.style.color = ''; }, 1500);
        }).catch(() => {
            btn.style.color = 'var(--danger)';
            setTimeout(() => { btn.style.color = ''; }, 1500);
        });
    });

    // Global delegated click handler for header click-to-copy
    document.addEventListener('click', (e) => {
        const el = e.target.closest('[data-copy-hdr]');
        if (!el) return;
        navigator.clipboard.writeText(el.dataset.copyHdr).then(() => {
            el.classList.add('hdr-copied');
            setTimeout(() => el.classList.remove('hdr-copied'), 800);
        });
    });

    /**
     * Render HTTP headers as a clickable key: value block (click to copy value).
     * Accepts a JSON string, object, or null.
     */
    function headersBlock(hdrs) {
        let obj = hdrs;
        if (typeof hdrs === 'string') {
            try { obj = JSON.parse(hdrs); } catch (_) {
                // Not valid JSON — fall back to bodyPreBlock
                return bodyPreBlock(hdrs);
            }
        }
        if (!obj || typeof obj !== 'object') return '<span style="color:var(--text-dim)">(none)</span>';

        const lines = Object.entries(obj).map(([k, v]) => {
            const sv = String(v);
            const attrVal = escAttr(sv);
            return `<span class="hdr-key" data-copy-hdr="${attrVal}" title="Click to copy value">${esc(k)}</span>: <span class="hdr-val" data-copy-hdr="${attrVal}" title="Click to copy value">${esc(sv)}</span>`;
        }).join('\n');

        const id = 'hdr-' + Math.random().toString(36).slice(2, 10);
        const copyIcon = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
        return `<div class="body-pre-wrapper"><button class="btn-copy-body" data-copy-target="${id}" title="Copy all headers">${copyIcon}</button><pre class="scan-response-body" id="${id}">${lines}</pre></div>`;
    }

    return { formatBody, esc, escAttr, bodyPreBlock, headersBlock, highlightCanaries, parseRawHttp, KNOWN_CANARIES };
})();
