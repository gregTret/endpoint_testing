/**
 * App — main orchestrator
 *
 * - Shows workspace launcher on startup
 * - After workspace selected: connects WebSocket, inits sub-modules
 * - Dispatches events to LogViewer / SiteMap / InjectorUI
 * - Handles tab switching + URL bar navigation
 * - Manages per-workspace tab configuration (order + visibility)
 */
(function () {
    const WS_URL = 'ws://127.0.0.1:8000/ws';
    const API    = 'http://127.0.0.1:8000/api';
    let ws = null;
    let statusDot;
    let mainInitialised = false;

    // ── Tab definitions (default order) ─────────────────────────────
    const ALL_TABS = [
        { id: 'logs',      label: 'Logs' },
        { id: 'sitemap',   label: 'Site Map' },
        { id: 'intercept', label: 'Intercept' },
        { id: 'injector',  label: 'Injector' },
        { id: 'oob',       label: 'OOB' },
        { id: 'repeater',  label: 'Repeater' },
        { id: 'analytics', label: 'Analytics' },
        { id: 'settings',  label: 'Settings' },
    ];

    let tabConfig = []; // [{ id, visible }] — current workspace config

    // ── Bootstrap ──────────────────────────────────────────────────

    document.addEventListener('DOMContentLoaded', () => {
        statusDot = document.getElementById('connection-status');

        // Show workspace launcher first — main UI stays hidden
        Workspace.init(onWorkspaceSelected);

        // "Switch Workspace" button
        document.getElementById('btn-switch-ws').addEventListener('click', () => {
            Workspace.show();
            if (ws) { ws.onclose = null; ws.close(); ws = null; }
        });
    });

    /** Called by Workspace module after a workspace is selected */
    function onWorkspaceSelected(workspaceId, workspaceName) {
        if (!mainInitialised) {
            initMainUI();
            mainInitialised = true;
        }

        // Load tab config for this workspace
        loadTabConfig();
        renderTabBar();
        renderTabConfigUI();

        // Reconnect WS + reload data for the new workspace
        if (ws) { ws.onclose = null; ws.close(); ws = null; }
        connectWS();
        reloadWorkspaceData();
    }

    function initMainUI() {
        // Initialise sub-modules (once)
        LogViewer.init();
        SiteMap.init();
        Intercept.init();
        Credentials.init();
        InjectorUI.init();
        OobUI.init();
        Repeater.init();
        Analytics.init();
        PayloadEditor.init();

        // URL bar
        document.getElementById('btn-go').addEventListener('click', navigate);
        document.getElementById('url-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') navigate();
        });

        // Nav buttons
        document.getElementById('btn-back').addEventListener('click', () => window.electronAPI.goBack());
        document.getElementById('btn-forward').addEventListener('click', () => window.electronAPI.goForward());
        document.getElementById('btn-refresh').addEventListener('click', () => window.electronAPI.refresh());

        // URL change from embedded browser
        window.electronAPI.onUrlChanged((url) => {
            document.getElementById('url-input').value = url;
            Workspace.saveLastUrl(url);
        });

        // Settings — clear buttons
        document.getElementById('btn-clear-logs-all').addEventListener('click', () => {
            if (!confirm('Clear all request logs for this workspace?')) return;
            fetch(`${API}/logs`, { method: 'DELETE' }).catch(() => {});
            if (LogViewer.clear) LogViewer.clear();
        });
        document.getElementById('btn-clear-sitemap').addEventListener('click', () => {
            if (!confirm('Clear the entire site map for this workspace?')) return;
            fetch(`${API}/sitemap`, { method: 'DELETE' }).catch(() => {});
            if (SiteMap.clear) SiteMap.clear();
        });
        document.getElementById('btn-clear-injector-history').addEventListener('click', () => {
            if (!confirm('Clear all injector scan history?')) return;
            if (InjectorUI.clearHistory) InjectorUI.clearHistory();
        });
        document.getElementById('btn-clear-repeater-history').addEventListener('click', () => {
            if (!confirm('Clear all repeater history?')) return;
            if (Repeater.clearAll) Repeater.clearAll();
        });
        document.getElementById('btn-clear-oob-history').addEventListener('click', () => {
            if (!confirm('Clear all OOB scan results?')) return;
            if (OobUI.clearHistory) OobUI.clearHistory();
        });
        document.getElementById('btn-clear-oob-registry').addEventListener('click', () => {
            if (!confirm('Clear OOB scan registry? This removes in-memory scan keys used for callback checking.')) return;
            if (OobUI.clearRegistry) OobUI.clearRegistry();
        });

        // Proxy settings toggle
        initProxySettings();

        // OOB callback server settings
        initOobSettings();

        // Export modal
        initExportModal();

        // Panel resize drag handle
        initPanelResize();
    }

    /** Clear current UI data and reload from the active workspace */
    function reloadWorkspaceData() {
        if (LogViewer.clear) LogViewer.clear();
        if (SiteMap.clear) SiteMap.clear();
        loadExistingLogs();
        if (SiteMap.loadSaved) SiteMap.loadSaved();
        if (Credentials.loadCreds) Credentials.loadCreds();
        if (InjectorUI.loadHistory) InjectorUI.loadHistory();
        if (OobUI.loadHistory) OobUI.loadHistory();
        if (Repeater.loadHistory) Repeater.loadHistory();
        if (PayloadEditor.refresh) PayloadEditor.refresh();
        if (window._reloadOobSettings) window._reloadOobSettings();
    }

    // ── Tab Config ──────────────────────────────────────────────────

    function _configKey() {
        const wsId = Workspace.getActiveId() || 'default';
        return `ws_tabConfig_${wsId}`;
    }

    function loadTabConfig() {
        const raw = localStorage.getItem(_configKey());
        if (raw) {
            try {
                const saved = JSON.parse(raw);
                // Merge: keep saved order/visibility, add any new tabs not yet in config
                const savedIds = new Set(saved.map(t => t.id));
                tabConfig = saved.filter(t => ALL_TABS.some(a => a.id === t.id));
                for (const t of ALL_TABS) {
                    if (!savedIds.has(t.id)) {
                        // Insert new tabs before settings
                        const settingsIdx = tabConfig.findIndex(c => c.id === 'settings');
                        if (settingsIdx >= 0) {
                            tabConfig.splice(settingsIdx, 0, { id: t.id, visible: true });
                        } else {
                            tabConfig.push({ id: t.id, visible: true });
                        }
                    }
                }
                return;
            } catch (_) {}
        }
        // Default: all visible in default order
        tabConfig = ALL_TABS.map(t => ({ id: t.id, visible: true }));
    }

    function saveTabConfig() {
        localStorage.setItem(_configKey(), JSON.stringify(tabConfig));
    }

    function renderTabBar() {
        const bar = document.getElementById('tab-bar');
        bar.innerHTML = '';
        const visibleTabs = tabConfig.filter(t => t.visible);
        // Settings is always shown, ensure it's in the list
        if (!visibleTabs.some(t => t.id === 'settings')) {
            visibleTabs.push({ id: 'settings', visible: true });
        }

        visibleTabs.forEach((t, i) => {
            const def = ALL_TABS.find(a => a.id === t.id);
            if (!def) return;
            const btn = document.createElement('button');
            btn.className = 'tab' + (i === 0 ? ' active' : '');
            btn.dataset.tab = t.id;
            btn.textContent = def.label;
            btn.addEventListener('click', () => switchTab(t.id));
            bar.appendChild(btn);
        });

        // Show first visible tab's pane
        const firstTab = visibleTabs[0]?.id || 'logs';
        document.querySelectorAll('.tab-pane').forEach(p => {
            p.classList.toggle('active', p.dataset.tab === firstTab);
        });
    }

    function renderTabConfigUI() {
        const container = document.getElementById('tab-config-list');
        if (!container) return;

        container.innerHTML = tabConfig.map((t, i) => {
            const def = ALL_TABS.find(a => a.id === t.id);
            if (!def) return '';
            const isSettings = t.id === 'settings';
            return `<div class="tab-config-item" draggable="true" data-idx="${i}">
                <span class="drag-handle">⠿</span>
                <label>
                    <input type="checkbox" ${t.visible ? 'checked' : ''} ${isSettings ? 'disabled checked' : ''} data-idx="${i}">
                    ${def.label}
                </label>
            </div>`;
        }).join('');

        // Checkboxes — update config in memory only (applied on Save)
        container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.addEventListener('change', () => {
                const idx = Number(cb.dataset.idx);
                tabConfig[idx].visible = cb.checked;
            });
        });

        // Save button
        document.getElementById('btn-save-tab-config').onclick = () => {
            saveTabConfig();
            renderTabBar();
            // Stay on settings tab
            switchTab('settings');
        };

        // Drag and drop reorder
        let dragIdx = null;
        container.querySelectorAll('.tab-config-item').forEach(item => {
            item.addEventListener('dragstart', (e) => {
                dragIdx = Number(item.dataset.idx);
                e.dataTransfer.effectAllowed = 'move';
                item.style.opacity = '0.4';
            });
            item.addEventListener('dragend', () => {
                item.style.opacity = '';
                container.querySelectorAll('.tab-config-item').forEach(el => el.classList.remove('drag-over'));
            });
            item.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
                item.classList.add('drag-over');
            });
            item.addEventListener('dragleave', () => {
                item.classList.remove('drag-over');
            });
            item.addEventListener('drop', (e) => {
                e.preventDefault();
                item.classList.remove('drag-over');
                const dropIdx = Number(item.dataset.idx);
                if (dragIdx === null || dragIdx === dropIdx) return;
                const moved = tabConfig.splice(dragIdx, 1)[0];
                tabConfig.splice(dropIdx, 0, moved);
                dragIdx = null;
                renderTabConfigUI();
            });
        });
    }

    // ── WebSocket ──────────────────────────────────────────────────

    function connectWS() {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            statusDot.className = 'status-dot connected';
            statusDot.title = 'Connected to backend';
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'request_log' && msg.data) {
                    LogViewer.addEntry(msg.data);
                    SiteMap.addUrl(msg.data.url);
                } else if (msg.type === 'intercepted_flow' && msg.data) {
                    Intercept.onInterceptedFlow(msg.data);
                }
            } catch (_) {}
        };

        ws.onclose = () => {
            statusDot.className = 'status-dot disconnected';
            statusDot.title = 'Disconnected — retrying...';
            setTimeout(connectWS, 3000);
        };

        ws.onerror = () => {
            ws.close();
        };
    }

    // ── Expose WS send for other modules (e.g. Intercept) ─────────
    window.AppWS = {
        send(data) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(data));
            }
        }
    };

    // ── Existing logs ──────────────────────────────────────────────

    async function loadExistingLogs() {
        const logList = document.getElementById('log-list');
        if (logList) logList.innerHTML = '<p class="placeholder-text" style="padding:10px">Loading logs...</p>';

        try {
            const res = await fetch(`${API}/logs?limit=500`);
            const logs = await res.json();
            const reversed = logs.slice().reverse();
            LogViewer.addEntries(reversed);
        } catch (_) {
            if (logList) logList.innerHTML = '';
        }
    }

    // ── Navigation ─────────────────────────────────────────────────

    function navigate() {
        const url = document.getElementById('url-input').value.trim();
        if (url) window.electronAPI.navigate(url);
    }

    // ── Tab switching ──────────────────────────────────────────────

    function switchTab(tabName) {
        document.querySelectorAll('#tab-bar .tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-pane').forEach(p => {
            p.classList.toggle('active', p.dataset.tab === tabName);
        });
        // Load analytics data when switching to that tab
        if (tabName === 'analytics' && Analytics.refresh) Analytics.refresh();
    }

    // ── Panel resize ────────────────────────────────────────────────

    function initPanelResize() {
        const handle = document.getElementById('panel-resize-handle');
        const panel  = document.getElementById('tool-panel');
        if (!handle || !panel) return;

        let dragging = false;

        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            dragging = true;
            handle.classList.add('dragging');
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
        });

        document.addEventListener('mousemove', (e) => {
            if (!dragging) return;
            const newWidth = Math.max(250, Math.min(e.clientX, window.innerWidth - 200));
            document.documentElement.style.setProperty('--panel-width', newWidth + 'px');
            panel.style.width = newWidth + 'px';
            handle.style.left = newWidth + 'px';
            window.electronAPI.setPanelWidth(newWidth);
        });

        document.addEventListener('mouseup', () => {
            if (!dragging) return;
            dragging = false;
            handle.classList.remove('dragging');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        });
    }

    // ── Proxy Settings ──────────────────────────────────────────────

    function initProxySettings() {
        const chkAutoFwd  = document.getElementById('chk-auto-drop-options');
        const chkReq      = document.getElementById('chk-intercept-requests');
        const chkResp     = document.getElementById('chk-intercept-responses');
        if (!chkAutoFwd) return;

        // Load current values from backend
        fetch(`${API}/settings/proxy`)
            .then(r => r.json())
            .then(data => {
                chkAutoFwd.checked = data.auto_drop_options;
                if (chkReq)  chkReq.checked  = data.intercept_requests;
                if (chkResp) chkResp.checked = data.intercept_responses;
            })
            .catch(() => {});

        function postSetting(key, value) {
            fetch(`${API}/settings/proxy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ [key]: value }),
            }).catch(() => {});
        }

        chkAutoFwd.addEventListener('change', () => postSetting('auto_drop_options', chkAutoFwd.checked));
        if (chkReq)  chkReq.addEventListener('change',  () => postSetting('intercept_requests',  chkReq.checked));
        if (chkResp) chkResp.addEventListener('change', () => postSetting('intercept_responses', chkResp.checked));
    }

    // ── OOB Settings ────────────────────────────────────────────────

    function initOobSettings() {
        const urlInput  = document.getElementById('oob-server-url');
        const saveBtn   = document.getElementById('btn-oob-save');
        const testBtn   = document.getElementById('btn-oob-test');
        const statusLbl = document.getElementById('oob-status');
        const catContainer = document.getElementById('oob-categories');
        if (!urlInput) return;

        const allTypes = ['cmd', 'ssrf', 'xxe', 'ssti', 'sqli'];

        function setCategoryCheckboxes(enabledTypes) {
            if (!catContainer) return;
            const types = enabledTypes || allTypes;
            catContainer.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.checked = types.includes(cb.value);
            });
        }

        function getCheckedCategories() {
            if (!catContainer) return allTypes;
            return Array.from(catContainer.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
        }

        function loadOobSettings() {
            fetch(`${API}/settings/oob`)
                .then(r => r.json())
                .then(data => {
                    urlInput.value = data.oob_server_url || '';
                    setCategoryCheckboxes(data.oob_enabled_types);
                })
                .catch(() => {});
        }
        loadOobSettings();

        // Reload when workspace switches
        window._reloadOobSettings = loadOobSettings;

        saveBtn.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (!url) { statusLbl.textContent = 'URL is required'; statusLbl.style.color = 'var(--danger)'; return; }
            fetch(`${API}/settings/oob`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ oob_server_url: url, oob_enabled_types: getCheckedCategories() }),
            })
            .then(r => r.json())
            .then(() => { statusLbl.textContent = 'Saved'; statusLbl.style.color = 'var(--success)'; })
            .catch(() => { statusLbl.textContent = 'Save failed'; statusLbl.style.color = 'var(--danger)'; });
        });

        testBtn.addEventListener('click', () => {
            statusLbl.textContent = 'Testing...';
            statusLbl.style.color = 'var(--text-dim)';
            const url = urlInput.value.trim();
            fetch(`${API}/settings/oob/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ oob_server_url: url || undefined }),
            })
            .then(async r => {
                if (r.ok) {
                    statusLbl.textContent = 'Connected!';
                    statusLbl.style.color = 'var(--success)';
                } else {
                    const d = await r.json().catch(() => ({}));
                    statusLbl.textContent = d.error || 'Connection failed';
                    statusLbl.style.color = 'var(--danger)';
                }
            })
            .catch(() => { statusLbl.textContent = 'Connection failed'; statusLbl.style.color = 'var(--danger)'; });
        });
    }

    // ── Export Modal ────────────────────────────────────────────────

    function initExportModal() {
        const modal      = document.getElementById('export-modal');
        const fmtSel     = document.getElementById('export-format');
        const filterBar  = document.getElementById('export-site-filter');
        const filterLbl  = document.getElementById('export-site-label');
        let siteFilter   = null; // e.g. "dev.buildmybridges.com" or "dev.buildmybridges.com/api"

        function openModal()  { modal.classList.remove('hidden'); window.electronAPI.hideBrowser(); }
        function closeModal() { modal.classList.add('hidden'); siteFilter = null; filterBar.classList.add('hidden'); const wsId = Workspace.getActiveId(); const lastUrl = localStorage.getItem(`ws_lastUrl_${wsId}`) || ''; window.electronAPI.showBrowser(wsId, lastUrl); }

        // Expose globally so site-map can call it
        window.openExportForSite = function (prefix) {
            siteFilter = prefix || null;
            if (siteFilter) {
                filterLbl.textContent = siteFilter;
                filterBar.classList.remove('hidden');
                // Pre-select relevant data types
                modal.querySelectorAll('.checkbox-group input').forEach(cb => {
                    cb.checked = ['logs', 'scans', 'sitemap'].includes(cb.value);
                });
            } else {
                filterBar.classList.add('hidden');
            }
            openModal();
        };

        document.getElementById('btn-export-clear-filter').addEventListener('click', () => {
            siteFilter = null;
            filterBar.classList.add('hidden');
        });

        document.getElementById('btn-open-export').addEventListener('click', () => {
            siteFilter = null;
            filterBar.classList.add('hidden');
            openModal();
        });
        document.getElementById('btn-export-close').addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });

        function _matchesSite(rawUrl) {
            if (!siteFilter) return true;
            if (!rawUrl) return false;
            // Match against host+pathname  e.g. siteFilter = "dev.example.com" or "dev.example.com/api"
            try {
                const u = new URL(rawUrl);
                const hostPath = u.host + u.pathname;          // "dev.example.com/foo/bar"
                if (u.host === siteFilter) return true;        // host-level match
                if (hostPath === siteFilter) return true;      // exact match
                if (hostPath.startsWith(siteFilter + '/')) return true; // prefix match
                if (hostPath.startsWith(siteFilter)) return true;      // partial path match
                return false;
            } catch (_) {
                // Fallback: plain string contains
                return rawUrl.includes(siteFilter);
            }
        }

        document.getElementById('btn-export-run').addEventListener('click', async () => {
            const selected = new Set();
            modal.querySelectorAll('.checkbox-group input:checked').forEach(cb => selected.add(cb.value));
            const fmt = fmtSel.value;

            if (!selected.size) { alert('Select at least one data type'); return; }

            const active = siteFilter; // capture current filter before async calls
            console.log('[Export] site filter:', active);

            // Fetch selected data then filter by site if needed
            const data = {};
            if (selected.has('logs')) {
                let logs = await _fetchJson(`${API}/logs?limit=10000`);
                if (active) { const before = logs.length; logs = logs.filter(l => _matchesSite(l.url)); console.log(`[Export] logs ${before} → ${logs.length}`); }
                data.logs = logs;
            }
            if (selected.has('scans')) {
                let scans = await _fetchJson(`${API}/scan/history?limit=10000`);
                if (active) { const before = scans.length; scans = scans.filter(r => _matchesSite(r.target_url)); console.log(`[Export] scans ${before} → ${scans.length}`); }
                data.scans = scans;
            }
            if (selected.has('sitemap')) {
                let urls = await _fetchJson(`${API}/sitemap`);
                // sitemap returns plain strings
                if (active) { const before = urls.length; urls = urls.filter(u => _matchesSite(typeof u === 'string' ? u : u.url)); console.log(`[Export] sitemap ${before} → ${urls.length}`); }
                data.sitemap = urls;
            }
            if (selected.has('credentials')) data.credentials = await _fetchJson(`${API}/credentials`);
            if (selected.has('repeater')) {
                let rep = await _fetchJson(`${API}/repeater/history`);
                if (active) { const before = rep.length; rep = rep.filter(r => _matchesSite(r.url)); console.log(`[Export] repeater ${before} → ${rep.length}`); }
                data.repeater = rep;
            }

            let blob, filename;
            const tag = siteFilter ? siteFilter.replace(/[^a-zA-Z0-9]/g, '_') : '';

            if (fmt === 'postman') {
                const collection = _buildPostman(data.logs || []);
                blob = new Blob([JSON.stringify(collection, null, 2)], { type: 'application/json' });
                filename = `postman_${tag || 'collection'}_${Date.now()}.json`;
            } else if (fmt === 'csv') {
                const csv = _buildCsv(data);
                blob = new Blob([csv], { type: 'text/csv' });
                filename = `export_${tag || 'data'}_${Date.now()}.csv`;
            } else {
                blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                filename = `export_${tag || 'data'}_${Date.now()}.json`;
            }

            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = filename;
            a.click();
            URL.revokeObjectURL(a.href);
            closeModal();
        });
    }

    async function _fetchJson(url) {
        try { return await (await fetch(url)).json(); }
        catch (_) { return []; }
    }

    function _buildPostman(logs) {
        const seen = {};
        const items = [];
        (logs || []).forEach(l => {
            const key = `${l.method} ${_basePath(l.url)}`;
            if (seen[key]) return;
            seen[key] = true;
            let u; try { u = new URL(l.url); } catch (_) { return; }
            const item = {
                name: `${l.method} ${u.pathname}`,
                request: {
                    method: l.method,
                    header: Object.entries(l.request_headers || {})
                        .filter(([k]) => !['host','content-length','transfer-encoding','connection','accept-encoding'].includes(k.toLowerCase()))
                        .map(([k, v]) => ({ key: k, value: v })),
                    url: {
                        raw: l.url,
                        protocol: u.protocol.replace(':', ''),
                        host: u.hostname.split('.'),
                        port: u.port || '',
                        path: u.pathname.split('/').filter(Boolean),
                        query: [...u.searchParams].map(([k, v]) => ({ key: k, value: v })),
                    },
                },
            };
            if (l.request_body) {
                item.request.body = { mode: 'raw', raw: l.request_body, options: { raw: { language: 'json' } } };
            }
            items.push(item);
        });
        return {
            info: { name: `Endpoint Security — ${new Date().toLocaleDateString()}`, schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
            item: items,
        };
    }

    function _buildCsv(data) {
        const lines = [];
        if (data.logs?.length) {
            lines.push('=== REQUEST LOGS ===');
            lines.push('timestamp,method,url,status_code,duration_ms,content_type');
            data.logs.forEach(l => {
                lines.push([l.timestamp, l.method, `"${(l.url||'').replace(/"/g,'""')}"`, l.status_code, l.duration_ms, l.content_type].join(','));
            });
        }
        if (data.scans?.length) {
            lines.push('');
            lines.push('=== SCAN RESULTS ===');
            lines.push('timestamp,target_url,injector_type,injection_point,original_param,payload,response_code,response_time_ms,is_vulnerable,confidence,details');
            data.scans.forEach(r => {
                lines.push([r.timestamp, `"${(r.target_url||'').replace(/"/g,'""')}"`, r.injector_type, r.injection_point, r.original_param,
                    `"${(r.payload||'').replace(/"/g,'""')}"`, r.response_code, r.response_time_ms, r.is_vulnerable, r.confidence,
                    `"${(r.details||'').replace(/"/g,'""')}"`].join(','));
            });
        }
        return lines.join('\n');
    }

    function _basePath(url) {
        try { const u = new URL(url); return u.origin + u.pathname; } catch (_) { return url; }
    }
})();

