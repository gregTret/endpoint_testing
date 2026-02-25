/**
 * PayloadSuggest — Floating injection payload popup for the Intercept editor.
 *
 * Pulls payloads from the local injection bank (per-workspace payload configs)
 * instead of AI. Instant results, no network latency.
 */
window.AiSuggest = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let popup = null;
    let _cache = null; // { type: [{payload, type, is_quick}] }
    let _loading = false;

    const BANK_TYPES = ['sql', 'xss', 'cmd', 'traversal', 'ssti', 'mongo', 'aql'];

    const TYPE_COLORS = {
        sql:        { bg: 'rgba(139, 92, 246, .18)', fg: '#a78bfa' },
        xss:        { bg: 'rgba(251, 146, 60, .18)', fg: '#fb923c' },
        cmd:        { bg: 'rgba(248, 81, 73, .18)',  fg: '#f85149' },
        ssti:       { bg: 'rgba(250, 204, 21, .18)', fg: '#facc15' },
        traversal:  { bg: 'rgba(63, 185, 80, .18)',  fg: '#3fb950' },
        mongo:      { bg: 'rgba(232, 121, 249, .18)', fg: '#e879f9' },
        aql:        { bg: 'rgba(251, 191, 36, .18)', fg: '#fbbf24' },
    };

    let _activeType = 'all';

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
                '<span class="ai-suggest-title">Payload Bank</span>' +
                '<button class="ai-suggest-close" title="Close">&times;</button>' +
            '</div>' +
            '<div class="ai-suggest-filter-row">' +
                '<input type="text" class="ai-suggest-filter" placeholder="Filter payloads...">' +
            '</div>' +
            '<div class="ai-suggest-type-tabs"></div>' +
            '<div class="ai-suggest-body">' +
                '<div class="ai-suggest-loading hidden">' +
                    '<div class="ai-suggest-spinner"></div>' +
                    '<span>Loading payloads...</span>' +
                '</div>' +
                '<div class="ai-suggest-list"></div>' +
            '</div>';
        document.body.appendChild(popup);

        popup.querySelector('.ai-suggest-close').addEventListener('click', hide);

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !popup.classList.contains('hidden')) {
                hide();
            }
        });

        document.addEventListener('mousedown', (e) => {
            if (!popup.classList.contains('hidden') && !popup.contains(e.target)) {
                hide();
            }
        });

        // Filter input
        popup.querySelector('.ai-suggest-filter').addEventListener('input', (e) => {
            _renderPayloads(e.target.value);
        });

        // Pre-load the bank
        _loadBank();
    }

    async function _loadBank() {
        if (_cache || _loading) return;
        _loading = true;
        try {
            const results = await Promise.all(
                BANK_TYPES.map(type =>
                    fetch(`${API}/injectors/${type}/payloads`)
                        .then(r => r.ok ? r.json() : null)
                        .catch(() => null)
                )
            );
            _cache = {};
            BANK_TYPES.forEach((type, i) => {
                const data = results[i];
                if (data && data.payloads) {
                    _cache[type] = data.payloads
                        .filter(p => p.enabled)
                        .map(p => ({
                            payload: p.payload_text,
                            type: type,
                            is_quick: p.is_quick || false,
                        }));
                }
            });
        } catch (_) {
            _cache = {};
        }
        _loading = false;
    }

    function showForSelection(text, context, anchorRect) {
        if (!popup) return;

        popup.classList.remove('hidden');
        _position(anchorRect);

        const filterInput = popup.querySelector('.ai-suggest-filter');
        filterInput.value = '';

        if (!_cache) {
            popup.querySelector('.ai-suggest-loading').classList.remove('hidden');
            popup.querySelector('.ai-suggest-list').innerHTML = '';
            _loadBank().then(() => {
                popup.querySelector('.ai-suggest-loading').classList.add('hidden');
                _renderTypeTabs();
                _renderPayloads();
            });
        } else {
            popup.querySelector('.ai-suggest-loading').classList.add('hidden');
            _renderTypeTabs();
            _renderPayloads();
        }
    }

    function _renderTypeTabs() {
        const tabsEl = popup.querySelector('.ai-suggest-type-tabs');
        if (!_cache) { tabsEl.innerHTML = ''; return; }

        let html = '<button class="ai-suggest-tab active" data-type="all">All</button>';
        for (const type of BANK_TYPES) {
            if (_cache[type] && _cache[type].length > 0) {
                const colors = TYPE_COLORS[type] || { bg: 'rgba(148,163,184,.18)', fg: '#94a3b8' };
                const count = _cache[type].length;
                html += '<button class="ai-suggest-tab" data-type="' + type + '" style="color:' + colors.fg + '">' + type + ' (' + count + ')</button>';
            }
        }
        tabsEl.innerHTML = html;
        _activeType = 'all';

        tabsEl.querySelectorAll('.ai-suggest-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                tabsEl.querySelectorAll('.ai-suggest-tab').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                _activeType = btn.dataset.type;
                _renderPayloads();
            });
        });
    }

    function _renderPayloads(filter) {
        const list = popup.querySelector('.ai-suggest-list');
        if (!_cache) { list.innerHTML = ''; return; }

        const filterInput = popup.querySelector('.ai-suggest-filter');
        const filterText = (filter !== undefined ? filter : filterInput.value).toLowerCase().trim();

        let payloads = [];
        if (_activeType === 'all') {
            for (const type of BANK_TYPES) {
                if (_cache[type]) payloads.push(..._cache[type]);
            }
        } else if (_cache[_activeType]) {
            payloads = [..._cache[_activeType]];
        }

        if (filterText) {
            payloads = payloads.filter(p => p.payload.toLowerCase().includes(filterText));
        }

        // Quick payloads first
        payloads.sort((a, b) => (b.is_quick ? 1 : 0) - (a.is_quick ? 1 : 0));

        if (payloads.length === 0) {
            list.innerHTML = '<div class="ai-suggest-empty">No matching payloads.</div>';
            return;
        }

        // Limit to 200 to avoid DOM explosion
        const limited = payloads.slice(0, 200);
        list.innerHTML = '';

        for (const p of limited) {
            const row = document.createElement('div');
            row.className = 'ai-suggest-row';

            const colors = TYPE_COLORS[p.type] || { bg: 'rgba(148,163,184,.18)', fg: '#94a3b8' };

            row.innerHTML =
                '<span class="ai-suggest-type" style="background:' + colors.bg + ';color:' + colors.fg + '">' +
                    _esc(p.type) +
                '</span>' +
                (p.is_quick ? '<span class="ai-suggest-quick" title="Quick scan payload">Q</span>' : '') +
                '<code class="ai-suggest-payload" title="' + _esc(p.payload) + '">' +
                    _esc(p.payload) +
                '</code>';

            row.addEventListener('click', () => {
                document.dispatchEvent(new CustomEvent('ai-triage-select', {
                    detail: { payload: p.payload, type: p.type }
                }));
                hide();
            });

            list.appendChild(row);
        }

        if (payloads.length > 200) {
            const more = document.createElement('div');
            more.className = 'ai-suggest-empty';
            more.textContent = (payloads.length - 200) + ' more — use the filter to narrow down.';
            list.appendChild(more);
        }
    }

    function hide() {
        if (!popup) return;
        popup.classList.add('hidden');
    }

    function _position(anchorRect) {
        if (!anchorRect) return;

        const pad = 8;
        const popupW = 480;
        const popupH = 500;
        const vw = window.innerWidth;
        const vh = window.innerHeight;

        let top = anchorRect.bottom + pad;
        if (top + popupH > vh) top = anchorRect.top - popupH - pad;
        if (top < 0) top = pad;

        let left = anchorRect.left;
        if (left + popupW > vw) left = vw - popupW - pad;
        if (left < 0) left = pad;

        popup.style.top = top + 'px';
        popup.style.left = left + 'px';
    }

    /** Force reload of cached payloads (call after editing bank in settings) */
    function invalidateCache() {
        _cache = null;
        _loading = false;
    }

    return { init, showForSelection, hide, invalidateCache };
})();
