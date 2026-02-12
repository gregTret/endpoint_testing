/**
 * EPTUtils — shared UI utilities for body formatting, copy, canary
 * highlighting, and raw HTTP request parsing.
 */
window.EPTUtils = (() => {
    // Known canary/marker strings used by injectors for detection
    const KNOWN_CANARIES = ['EPT_CMD_9f3a7c', 'x5s7k9q', '9799447'];

    /**
     * Format a body string for display.
     * Detects JSON and pretty-prints it; falls back to raw text.
     */
    function formatBody(bodyStr) {
        if (!bodyStr) return '(empty)';
        const trimmed = bodyStr.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try {
                return JSON.stringify(JSON.parse(trimmed), null, 2);
            } catch (_) {}
        }
        return bodyStr;
    }

    /** Escape HTML for safe insertion via innerHTML. */
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
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
     * Build a <pre> block with hover-reveal copy button.
     * @param {string} bodyStr  Raw body text
     * @returns {string} HTML string
     */
    function bodyPreBlock(bodyStr) {
        const formatted = formatBody(bodyStr);
        const id = 'body-' + Math.random().toString(36).slice(2, 10);
        let escaped = esc(formatted);
        escaped = highlightCanaries(escaped);
        return `<div class="body-pre-wrapper"><button class="btn-copy-body" data-copy-target="${id}" title="Copy to clipboard">Copy</button><pre class="scan-response-body" id="${id}">${escaped}</pre></div>`;
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

    // Delegated click handler for copy buttons
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-copy-body');
        if (!btn) return;
        const targetId = btn.dataset.copyTarget;
        const pre = document.getElementById(targetId);
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent).then(() => {
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        }).catch(() => {
            btn.textContent = 'Failed';
            setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        });
    });

    return { formatBody, esc, bodyPreBlock, highlightCanaries, parseRawHttp, KNOWN_CANARIES };
})();
