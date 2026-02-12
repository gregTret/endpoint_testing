/**
 * PayloadEditor — per-workspace injector payload configuration
 *
 * Renders a list of configurable injectors in Settings and provides
 * a modal editor for toggling/editing/adding payloads.
 */
// eslint-disable-next-line no-unused-vars
var PayloadEditor = (function () {
    const API = 'http://127.0.0.1:8000/api';

    const CONFIGURABLE = ['sql', 'xss', 'cmd', 'traversal', 'ssti', 'mongo', 'aql'];

    const LABELS = {
        sql: 'SQL Injection',
        xss: 'Cross-Site Scripting',
        cmd: 'Command Injection',
        traversal: 'Path Traversal',
        ssti: 'Server-Side Template Injection',
        mongo: 'MongoDB Injection',
        aql: 'AQL Injection',
    };

    // Current editor state
    let _currentType = null;
    let _payloads = [];       // working copy [{payload_text, enabled, is_quick, sort_order}]
    let _isCustomized = false;

    // DOM refs (set in init)
    let $list, $modal, $editorList, $stats, $search, $addForm,
        $title, $badge, $addText, $addQuick, $addCount;

    // ── Public API ──────────────────────────────────────────────────

    function init() {
        $list       = document.getElementById('injector-payload-list');
        $modal      = document.getElementById('payload-editor-modal');
        $editorList = document.getElementById('payload-editor-list');
        $stats      = document.getElementById('payload-editor-stats');
        $search     = document.getElementById('payload-search');
        $addForm    = document.getElementById('payload-add-form');
        $title      = document.getElementById('payload-editor-title');
        $badge      = document.getElementById('payload-customized-badge');
        $addText    = document.getElementById('payload-add-text');
        $addQuick   = document.getElementById('payload-add-quick');
        $addCount   = document.getElementById('payload-add-count');

        if (!$list || !$modal) return;

        // Close
        document.getElementById('btn-payload-editor-close').addEventListener('click', closeEditor);
        $modal.addEventListener('click', (e) => { if (e.target === $modal) closeEditor(); });

        // Search
        $search.addEventListener('input', renderPayloadRows);

        // Add payload
        document.getElementById('btn-payload-add').addEventListener('click', () => {
            $addForm.classList.remove('hidden');
            $addText.value = '';
            $addQuick.checked = false;
            if ($addCount) $addCount.textContent = '';
            $addText.focus();
        });
        $addText.addEventListener('input', _updateAddCount);
        document.getElementById('btn-payload-add-cancel').addEventListener('click', () => {
            $addForm.classList.add('hidden');
        });
        document.getElementById('btn-payload-add-confirm').addEventListener('click', addPayload);

        // Reset
        document.getElementById('btn-payload-reset').addEventListener('click', resetToDefaults);

        // Save
        document.getElementById('btn-payload-save').addEventListener('click', savePayloads);

        refresh();
    }

    async function refresh() {
        if (!$list) return;
        $list.innerHTML = CONFIGURABLE.map(type => {
            return `<div class="injector-payload-row" data-type="${type}">
                <div class="injector-payload-info">
                    <span class="injector-payload-name">${LABELS[type] || type}</span>
                    <span class="injector-payload-count" data-count="${type}">...</span>
                    <span class="injector-payload-badge hidden" data-badge="${type}">Customized</span>
                </div>
                <button class="btn-small" data-configure="${type}">Configure</button>
            </div>`;
        }).join('');

        // Bind configure buttons
        $list.querySelectorAll('[data-configure]').forEach(btn => {
            btn.addEventListener('click', () => openEditor(btn.dataset.configure));
        });

        // Fetch counts in background
        for (const type of CONFIGURABLE) {
            _fetchPayloadInfo(type);
        }
    }

    async function _fetchPayloadInfo(type) {
        try {
            const res = await fetch(`${API}/injectors/${type}/payloads`);
            if (!res.ok) return;
            const data = await res.json();
            const countEl = $list.querySelector(`[data-count="${type}"]`);
            const badgeEl = $list.querySelector(`[data-badge="${type}"]`);
            if (countEl) {
                const enabled = data.payloads.filter(p => p.enabled !== false).length;
                countEl.textContent = `${enabled} / ${data.payloads.length} payloads`;
            }
            if (badgeEl) {
                badgeEl.classList.toggle('hidden', !data.is_customized);
            }
        } catch (_) {}
    }

    // ── Editor ──────────────────────────────────────────────────────

    async function openEditor(type) {
        _currentType = type;
        $title.textContent = `${LABELS[type] || type} Payloads`;
        $search.value = '';
        $addForm.classList.add('hidden');

        try {
            const res = await fetch(`${API}/injectors/${type}/payloads`);
            const data = await res.json();
            _payloads = data.payloads.map((p, i) => ({
                payload_text: p.payload_text,
                enabled: p.enabled !== false && p.enabled !== 0,
                is_quick: !!p.is_quick,
                sort_order: p.sort_order != null ? p.sort_order : i,
            }));
            _isCustomized = data.is_customized;
        } catch (_) {
            _payloads = [];
            _isCustomized = false;
        }

        $badge.classList.toggle('hidden', !_isCustomized);
        renderPayloadRows();
        updateStats();
        $modal.classList.remove('hidden');
        if (window.electronAPI && window.electronAPI.hideBrowser) window.electronAPI.hideBrowser();
    }

    function closeEditor() {
        $modal.classList.add('hidden');
        _currentType = null;
        _payloads = [];
        // Restore browser
        if (window.electronAPI && window.electronAPI.showBrowser) {
            const wsId = Workspace.getActiveId();
            const lastUrl = localStorage.getItem(`ws_lastUrl_${wsId}`) || '';
            window.electronAPI.showBrowser(wsId, lastUrl);
        }
    }

    function renderPayloadRows() {
        const filter = ($search.value || '').toLowerCase();
        const html = [];
        _payloads.forEach((p, i) => {
            if (filter && !p.payload_text.toLowerCase().includes(filter)) return;
            const disabledClass = p.enabled ? '' : ' disabled';
            const quickActive = p.is_quick ? ' active' : '';
            html.push(`<div class="payload-row${disabledClass}" data-idx="${i}">
                <input type="checkbox" ${p.enabled ? 'checked' : ''} data-toggle="${i}" title="Enable/disable">
                <input type="text" class="payload-row-text" value="${_escAttr(p.payload_text)}" data-edit="${i}">
                <span class="payload-quick-badge${quickActive}" data-quick="${i}" title="Include in Quick Scan">Q</span>
                <button class="payload-row-delete" data-del="${i}" title="Remove">&times;</button>
            </div>`);
        });
        $editorList.innerHTML = html.join('') || '<p class="placeholder-text" style="padding:16px">No payloads</p>';

        // Bind events
        $editorList.querySelectorAll('[data-toggle]').forEach(cb => {
            cb.addEventListener('change', () => {
                const idx = Number(cb.dataset.toggle);
                _payloads[idx].enabled = cb.checked;
                cb.closest('.payload-row').classList.toggle('disabled', !cb.checked);
                updateStats();
            });
        });
        $editorList.querySelectorAll('[data-edit]').forEach(input => {
            input.addEventListener('change', () => {
                const idx = Number(input.dataset.edit);
                _payloads[idx].payload_text = input.value;
            });
        });
        $editorList.querySelectorAll('[data-quick]').forEach(badge => {
            badge.addEventListener('click', () => {
                const idx = Number(badge.dataset.quick);
                _payloads[idx].is_quick = !_payloads[idx].is_quick;
                badge.classList.toggle('active', _payloads[idx].is_quick);
                updateStats();
            });
        });
        $editorList.querySelectorAll('[data-del]').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = Number(btn.dataset.del);
                _payloads.splice(idx, 1);
                renderPayloadRows();
                updateStats();
            });
        });
    }

    function updateStats() {
        const total = _payloads.length;
        const enabled = _payloads.filter(p => p.enabled).length;
        const quick = _payloads.filter(p => p.is_quick && p.enabled).length;
        $stats.textContent = `${enabled} of ${total} enabled, ${quick} quick`;
    }

    function addPayload() {
        const text = ($addText.value || '').trim();
        if (!text) return;

        // Support multi-line: each line becomes a separate payload
        const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
        const isQuick = $addQuick.checked;
        for (const line of lines) {
            _payloads.push({
                payload_text: line,
                enabled: true,
                is_quick: isQuick,
                sort_order: _payloads.length,
            });
        }
        $addForm.classList.add('hidden');
        $addText.value = '';
        renderPayloadRows();
        updateStats();
        // Scroll to bottom
        $editorList.scrollTop = $editorList.scrollHeight;
    }

    async function savePayloads() {
        if (!_currentType) return;

        const payload = _payloads.map((p, i) => ({
            payload_text: p.payload_text,
            enabled: p.enabled,
            is_quick: p.is_quick,
            sort_order: i,
        }));

        try {
            await fetch(`${API}/injectors/${_currentType}/payloads`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payloads: payload }),
            });
        } catch (e) {
            console.error('Failed to save payloads:', e);
        }

        closeEditor();
        refresh();
    }

    async function resetToDefaults() {
        if (!_currentType) return;
        if (!confirm(`Reset ${LABELS[_currentType] || _currentType} payloads to defaults?`)) return;

        try {
            await fetch(`${API}/injectors/${_currentType}/payloads`, { method: 'DELETE' });
        } catch (_) {}

        // Re-open editor with fresh defaults
        await openEditor(_currentType);
    }

    function _updateAddCount() {
        if (!$addCount) return;
        const lines = ($addText.value || '').split('\n').map(l => l.trim()).filter(Boolean);
        $addCount.textContent = lines.length ? `${lines.length} payload${lines.length === 1 ? '' : 's'}` : '';
    }

    function _escAttr(s) {
        return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return { init, refresh };
})();
