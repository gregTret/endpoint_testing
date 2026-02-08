/**
 * App — main orchestrator
 *
 * - Shows workspace launcher on startup
 * - After workspace selected: connects WebSocket, inits sub-modules
 * - Dispatches events to LogViewer / SiteMap / InjectorUI
 * - Handles tab switching + URL bar navigation
 */
(function () {
    const WS_URL = 'ws://127.0.0.1:8000/ws';
    const API    = 'http://127.0.0.1:8000/api';
    let ws = null;
    let statusDot;
    let mainInitialised = false;

    // ── Bootstrap ──────────────────────────────────────────────────

    document.addEventListener('DOMContentLoaded', () => {
        statusDot = document.getElementById('connection-status');

        // Show workspace launcher first — main UI stays hidden
        Workspace.init(onWorkspaceSelected);

        // "Switch Workspace" button
        document.getElementById('btn-switch-ws').addEventListener('click', () => {
            Workspace.show();
            // Close WS so we stop streaming old workspace data
            if (ws) { ws.onclose = null; ws.close(); ws = null; }
        });
    });

    /** Called by Workspace module after a workspace is selected */
    function onWorkspaceSelected(workspaceId, workspaceName) {
        if (!mainInitialised) {
            initMainUI();
            mainInitialised = true;
        }

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

        // Tab switching
        document.querySelectorAll('#tab-bar .tab').forEach(tab => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab));
        });

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
        });

        // Context menu: right-click a log entry to load into injector
        document.getElementById('log-list').addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const entry = LogViewer.getSelected();
            if (entry) {
                InjectorUI.loadFromLog(entry);
                switchTab('injector');
            }
        });
    }

    /** Clear current UI data and reload from the active workspace */
    function reloadWorkspaceData() {
        // Clear log viewer and site map
        if (LogViewer.clear) LogViewer.clear();
        if (SiteMap.clear) SiteMap.clear();
        loadExistingLogs();
        if (Credentials.loadCreds) Credentials.loadCreds();
        if (InjectorUI.loadHistory) InjectorUI.loadHistory();
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
        try {
            const res = await fetch(`${API}/logs?limit=500`);
            const logs = await res.json();
            // They come newest-first; add in reverse so oldest renders first
            for (let i = logs.length - 1; i >= 0; i--) {
                LogViewer.addEntry(logs[i]);
                SiteMap.addUrl(logs[i].url);
            }
        } catch (_) {
            // Backend might not be up yet — that's fine, WS will stream new ones
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
})();
