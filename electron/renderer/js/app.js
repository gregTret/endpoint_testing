/**
 * App — main orchestrator
 *
 * - Connects WebSocket to FastAPI backend
 * - Dispatches events to LogViewer / SiteMap / InjectorUI
 * - Handles tab switching + URL bar navigation
 */
(function () {
    const WS_URL = 'ws://127.0.0.1:8000/ws';
    const API    = 'http://127.0.0.1:8000/api';
    let ws = null;
    let statusDot;

    // ── Bootstrap ──────────────────────────────────────────────────

    document.addEventListener('DOMContentLoaded', () => {
        statusDot = document.getElementById('connection-status');

        // Initialise sub-modules
        LogViewer.init();
        SiteMap.init();
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

        // Connect WebSocket
        connectWS();

        // Load existing logs on startup
        loadExistingLogs();
    });

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
