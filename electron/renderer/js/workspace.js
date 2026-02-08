/**
 * Workspace — launcher screen for selecting / creating / deleting workspaces
 */
window.Workspace = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let launcherEl, listEl, nameInput, createBtn;
    let onSelectCallback = null;

    function init(onSelect) {
        onSelectCallback = onSelect;
        launcherEl = document.getElementById('workspace-launcher');
        listEl     = document.getElementById('ws-list');
        nameInput  = document.getElementById('ws-new-name');
        createBtn  = document.getElementById('btn-ws-create');

        createBtn.addEventListener('click', createWorkspace);
        nameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') createWorkspace();
        });

        loadList();
    }

    async function loadList() {
        try {
            const res = await fetch(`${API}/workspaces`);
            const workspaces = await res.json();
            renderList(workspaces);
        } catch (_) {
            listEl.innerHTML = '<p class="placeholder-text">Backend not ready — retrying...</p>';
            setTimeout(loadList, 2000);
        }
    }

    function renderList(workspaces) {
        if (!workspaces.length) {
            listEl.innerHTML = '<p class="placeholder-text">No workspaces yet — create one above</p>';
            return;
        }

        // Store workspace data in a lookup so we don't rely on data-name attributes
        const wsMap = {};
        workspaces.forEach(ws => { wsMap[ws.id] = ws; });

        listEl.innerHTML = workspaces.map(ws => `
            <div class="ws-entry" data-id="${esc(ws.id)}">
                <div class="ws-entry-main">
                    <span class="ws-name">${esc(ws.name)}</span>
                    <span class="ws-date">${formatDate(ws.last_opened_at)}</span>
                </div>
                <div class="ws-entry-actions">
                    <button class="ws-open" data-id="${esc(ws.id)}">Open</button>
                    <button class="ws-delete" data-id="${esc(ws.id)}">Delete</button>
                </div>
            </div>
        `).join('');

        listEl.querySelectorAll('.ws-open').forEach(btn => {
            btn.addEventListener('click', () => {
                const ws = wsMap[btn.dataset.id];
                if (ws) selectWorkspace(ws.id, ws.name);
            });
        });

        listEl.querySelectorAll('.ws-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                if (confirm('Delete this workspace and all its data? This cannot be undone.')) {
                    deleteWorkspace(btn.dataset.id);
                }
            });
        });
    }

    async function createWorkspace() {
        const name = nameInput.value.trim();
        if (!name) return;
        nameInput.value = '';

        try {
            const res = await fetch(`${API}/workspaces`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name }),
            });
            const ws = await res.json();
            // Auto-open the new workspace
            selectWorkspace(ws.id, ws.name);
        } catch (e) {
            listEl.innerHTML = `<p class="placeholder-text">Error: ${e.message}</p>`;
        }
    }

    async function selectWorkspace(id, name) {
        try {
            await fetch(`${API}/workspaces/active`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id }),
            });
        } catch (_) {}

        launcherEl.classList.add('hidden');
        document.getElementById('nav-bar').classList.remove('hidden');
        document.getElementById('tool-panel').classList.remove('hidden');
        document.getElementById('ws-active-name').textContent = name;

        // Create a new BrowserView with this workspace's session partition
        window.electronAPI.showBrowser(id);

        if (onSelectCallback) onSelectCallback(id, name);
    }

    async function deleteWorkspace(id) {
        try {
            await fetch(`${API}/workspaces/${id}`, { method: 'DELETE' });
        } catch (_) {}
        loadList();
    }

    /** Show the launcher again (called by "Switch Workspace" button) */
    function show() {
        // Detach the embedded browser so the launcher is fully visible
        window.electronAPI.hideBrowser();
        launcherEl.classList.remove('hidden');
        document.getElementById('nav-bar').classList.add('hidden');
        document.getElementById('tool-panel').classList.add('hidden');
        loadList();
    }

    function formatDate(iso) {
        if (!iso) return '';
        try {
            const d = new Date(iso);
            return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch (_) { return iso; }
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    return { init, show };
})();
