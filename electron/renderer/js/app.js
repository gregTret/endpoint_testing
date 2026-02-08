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
        { id: 'logs',     label: 'Logs' },
        { id: 'sitemap',  label: 'Site Map' },
        { id: 'injector', label: 'Injector' },
        { id: 'repeater', label: 'Repeater' },
        { id: 'settings', label: 'Settings' },
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
        Credentials.init();
        InjectorUI.init();
        Repeater.init();

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
        document.getElementById('btn-clear-injector-history').addEventListener('click', () => {
            if (!confirm('Clear all injector scan history?')) return;
            if (InjectorUI.clearHistory) InjectorUI.clearHistory();
        });
        document.getElementById('btn-clear-repeater-history').addEventListener('click', () => {
            if (!confirm('Clear all repeater history?')) return;
            if (Repeater.clearAll) Repeater.clearAll();
        });

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
        if (Repeater.loadHistory) Repeater.loadHistory();
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
                        tabConfig.push({ id: t.id, visible: true });
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
})();
