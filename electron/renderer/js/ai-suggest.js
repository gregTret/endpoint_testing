/**
 * AiSuggest — Floating injection suggestion popup for the Intercept editor.
 *
 * Completely decoupled from the intercept module. Shows a popup at a given
 * position, calls the backend for AI-generated injection suggestions,
 * and dispatches a `ai-triage-select` CustomEvent when the user picks one.
 */
window.AiSuggest = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let popup = null;
    let abortCtrl = null;

    const TYPE_COLORS = {
        sql:        { bg: 'rgba(139, 92, 246, .18)', fg: '#a78bfa' },
        xss:        { bg: 'rgba(251, 146, 60, .18)', fg: '#fb923c' },
        cmd:        { bg: 'rgba(248, 81, 73, .18)',  fg: '#f85149' },
        ssti:       { bg: 'rgba(250, 204, 21, .18)', fg: '#facc15' },
        traversal:  { bg: 'rgba(63, 185, 80, .18)',  fg: '#3fb950' },
        ssrf:       { bg: 'rgba(56, 189, 248, .18)', fg: '#38bdf8' },
        idor:       { bg: 'rgba(232, 121, 249, .18)', fg: '#e879f9' },
        jwt:        { bg: 'rgba(251, 191, 36, .18)', fg: '#fbbf24' },
        nosql:      { bg: 'rgba(167, 139, 250, .18)', fg: '#a78bfa' },
        header:     { bg: 'rgba(148, 163, 184, .18)', fg: '#94a3b8' },
        auth:       { bg: 'rgba(248, 113, 113, .18)', fg: '#f87171' },
    };

    function _esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    function init() {
        popup = document.createElement('div');
        popup.id = 'ai-suggest-popup';
        popup.className = 'ai-suggest-popup hidden';
        popup.innerHTML =
            '<div class="ai-suggest-header">' +
                '<span class="ai-suggest-title"></span>' +
                '<button class="ai-suggest-close" title="Close">&times;</button>' +
            '</div>' +
            '<div class="ai-suggest-body">' +
                '<div class="ai-suggest-loading hidden">' +
                    '<div class="ai-suggest-spinner"></div>' +
                    '<span>Generating suggestions...</span>' +
                '</div>' +
                '<div class="ai-suggest-error hidden">' +
                    '<span class="ai-suggest-error-msg"></span>' +
                    '<button class="ai-suggest-retry btn-small">Retry</button>' +
                '</div>' +
                '<div class="ai-suggest-list"></div>' +
            '</div>';
        document.body.appendChild(popup);

        // Close button
        popup.querySelector('.ai-suggest-close').addEventListener('click', hide);

        // Close on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !popup.classList.contains('hidden')) {
                hide();
            }
        });

        // Close on click outside
        document.addEventListener('mousedown', (e) => {
            if (!popup.classList.contains('hidden') && !popup.contains(e.target)) {
                hide();
            }
        });
    }

    function showForSelection(text, context, anchorRect) {
        if (!popup) return;
        if (!text || !text.trim()) return;

        // Abort any in-flight request
        if (abortCtrl) abortCtrl.abort();
        abortCtrl = new AbortController();

        // Show popup and position it
        popup.classList.remove('hidden');
        _position(anchorRect);

        // Set header text
        const truncated = text.length > 40 ? text.slice(0, 37) + '...' : text;
        popup.querySelector('.ai-suggest-title').textContent = truncated;

        // Show loading, hide others
        const loading = popup.querySelector('.ai-suggest-loading');
        const errorEl = popup.querySelector('.ai-suggest-error');
        const list = popup.querySelector('.ai-suggest-list');
        loading.classList.remove('hidden');
        errorEl.classList.add('hidden');
        list.innerHTML = '';

        // Fire the API call
        _fetchSuggestions(text, context, abortCtrl.signal);
    }

    function hide() {
        if (!popup) return;
        popup.classList.add('hidden');
        if (abortCtrl) {
            abortCtrl.abort();
            abortCtrl = null;
        }
    }

    function _position(anchorRect) {
        if (!anchorRect) return;

        const pad = 8;
        const popupW = 420;
        const popupH = 400;
        const vw = window.innerWidth;
        const vh = window.innerHeight;

        // Prefer below the anchor, fall back to above
        let top = anchorRect.bottom + pad;
        if (top + popupH > vh) {
            top = anchorRect.top - popupH - pad;
        }
        if (top < 0) top = pad;

        // Prefer aligned left with the anchor
        let left = anchorRect.left;
        if (left + popupW > vw) {
            left = vw - popupW - pad;
        }
        if (left < 0) left = pad;

        popup.style.top = top + 'px';
        popup.style.left = left + 'px';
    }

    async function _fetchSuggestions(text, context, signal) {
        const loading = popup.querySelector('.ai-suggest-loading');
        const errorEl = popup.querySelector('.ai-suggest-error');
        const list = popup.querySelector('.ai-suggest-list');

        try {
            const res = await fetch(API + '/ai/suggest-injections', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text, context }),
                signal,
            });

            if (!res.ok) {
                throw new Error('Server returned ' + res.status);
            }

            const data = await res.json();
            loading.classList.add('hidden');

            if (data.error) {
                _showError(data.error, text, context);
                return;
            }

            const suggestions = data.suggestions || [];
            if (suggestions.length === 0) {
                list.innerHTML = '<div class="ai-suggest-empty">No suggestions generated.</div>';
                return;
            }

            _renderSuggestions(suggestions, list);
        } catch (e) {
            if (e.name === 'AbortError') return;
            loading.classList.add('hidden');
            _showError(e.message, text, context);
        }
    }

    function _showError(msg, text, context) {
        const errorEl = popup.querySelector('.ai-suggest-error');
        const errorMsg = popup.querySelector('.ai-suggest-error-msg');
        errorMsg.textContent = msg || 'Request failed';
        errorEl.classList.remove('hidden');

        // Bind retry (replace handler to avoid stacking)
        const retryBtn = popup.querySelector('.ai-suggest-retry');
        const newBtn = retryBtn.cloneNode(true);
        retryBtn.parentNode.replaceChild(newBtn, retryBtn);
        newBtn.addEventListener('click', () => {
            errorEl.classList.add('hidden');
            popup.querySelector('.ai-suggest-loading').classList.remove('hidden');
            if (abortCtrl) abortCtrl.abort();
            abortCtrl = new AbortController();
            _fetchSuggestions(text, context, abortCtrl.signal);
        });
    }

    function _renderSuggestions(suggestions, list) {
        list.innerHTML = '';
        suggestions.forEach(s => {
            const row = document.createElement('div');
            row.className = 'ai-suggest-row';

            const typeKey = (s.type || 'xss').toLowerCase();
            const colors = TYPE_COLORS[typeKey] || { bg: 'rgba(148,163,184,.18)', fg: '#94a3b8' };

            row.innerHTML =
                '<span class="ai-suggest-type" style="background:' + colors.bg + ';color:' + colors.fg + '">' +
                    _esc(s.type || '?') +
                '</span>' +
                '<code class="ai-suggest-payload" title="' + _esc(s.payload || '') + '">' +
                    _esc(s.payload || '') +
                '</code>' +
                '<span class="ai-suggest-info" title="' + _esc(s.description || '') + '">&#9432;</span>';

            row.addEventListener('click', () => {
                document.dispatchEvent(new CustomEvent('ai-triage-select', {
                    detail: {
                        payload: s.payload,
                        type: s.type,
                        description: s.description,
                    }
                }));
                hide();
            });

            list.appendChild(row);
        });
    }

    return { init, showForSelection, hide };
})();
