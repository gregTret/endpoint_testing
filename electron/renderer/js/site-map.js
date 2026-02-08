/**
 * SiteMap — builds a URL tree from logged requests + crawl results
 */
window.SiteMap = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let treeData = {};   // nested object: { host: { path: { ... } } }
    let treeEl, crawlBtn, stopBtn, statusEl;
    let pollTimer = null;

    function init() {
        treeEl    = document.getElementById('site-tree');
        crawlBtn  = document.getElementById('btn-start-crawl');
        stopBtn   = document.getElementById('btn-stop-crawl');
        statusEl  = document.getElementById('crawl-status');

        crawlBtn.addEventListener('click', startCrawl);
        stopBtn.addEventListener('click', stopCrawl);
    }

    /** Add a URL to the tree (called for every new request log) */
    function addUrl(urlStr) {
        _insertUrl(urlStr);
        renderTree();
    }

    function _insertUrl(urlStr) {
        try {
            const u = new URL(urlStr);
            const host = u.host;
            const parts = u.pathname.split('/').filter(Boolean);

            if (!treeData[host]) treeData[host] = { _children: {} };
            let node = treeData[host]._children;

            for (const part of parts) {
                if (!node[part]) node[part] = { _children: {} };
                node = node[part]._children;
            }
        } catch (_) {}
    }

    /** Batch-add URLs without re-rendering on each one */
    function addUrls(urls) {
        for (const u of urls) _insertUrl(u);
        renderTree();
    }

    function renderTree() {
        treeEl.innerHTML = '';
        for (const [host, data] of Object.entries(treeData)) {
            const hostNode = createTreeNode(host, data._children, 0, true, 'https://' + host);
            treeEl.appendChild(hostNode);
        }
    }

    function createTreeNode(label, children, depth, isHost, fullUrl) {
        const wrap = document.createElement('div');
        const childKeys = Object.keys(children);
        const hasChildren = childKeys.length > 0;

        const row = document.createElement('div');
        row.className = 'tree-node';
        row.style.paddingLeft = (depth * 16 + 10) + 'px';

        const toggle = document.createElement('span');
        toggle.className = 'tree-toggle';
        toggle.textContent = hasChildren ? '▸' : ' ';

        const icon = document.createElement('span');
        icon.className = 'tree-icon';
        icon.textContent = isHost ? '⬡' : '›';

        const lbl = document.createElement('span');
        lbl.className = 'tree-label';
        lbl.textContent = label;

        row.appendChild(toggle);
        row.appendChild(icon);
        row.appendChild(lbl);
        wrap.appendChild(row);

        // Left click → navigate browser + toggle children
        row.addEventListener('click', (e) => {
            e.stopPropagation();
            window.electronAPI.navigate(fullUrl);
            document.getElementById('url-input').value = fullUrl;
        });

        // Right click → context menu
        row.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            let hostName, pathParts;
            try {
                const u = new URL(fullUrl);
                hostName = u.host;
                pathParts = u.pathname.split('/').filter(Boolean);
            } catch (_) {
                hostName = isHost ? label : null;
                pathParts = [];
            }
            showContextMenu(e.clientX, e.clientY, fullUrl, hostName, isHost ? [] : pathParts);
        });

        const childContainer = document.createElement('div');
        childContainer.style.display = 'none';

        for (const key of childKeys) {
            const childUrl = fullUrl.replace(/\/+$/, '') + '/' + key;
            childContainer.appendChild(createTreeNode(key, children[key]._children, depth + 1, false, childUrl));
        }
        wrap.appendChild(childContainer);

        if (hasChildren) {
            toggle.addEventListener('click', (e) => {
                e.stopPropagation();
                const open = childContainer.style.display !== 'none';
                childContainer.style.display = open ? 'none' : 'block';
                toggle.textContent = open ? '▸' : '▾';
            });
        }

        return wrap;
    }

    // ── Crawling ──────────────────────

    async function startCrawl() {
        let targetUrl;
        try {
            targetUrl = await window.electronAPI.getCurrentUrl();
        } catch (_) {
            targetUrl = document.getElementById('url-input').value;
        }

        if (!targetUrl) { statusEl.textContent = 'No URL'; return; }

        crawlBtn.disabled = true;
        stopBtn.disabled = false;
        statusEl.textContent = 'Starting...';

        try {
            await fetch(`${API}/crawl?url=${encodeURIComponent(targetUrl)}&max_depth=5&max_pages=100`, {
                method: 'POST',
            });
            pollCrawlStatus();
        } catch (e) {
            statusEl.textContent = 'Error: ' + e.message;
            crawlBtn.disabled = false;
            stopBtn.disabled = true;
        }
    }

    async function stopCrawl() {
        try { await fetch(`${API}/crawl/stop`, { method: 'POST' }); } catch (_) {}
        stopBtn.disabled = true;
    }

    function pollCrawlStatus() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(async () => {
            try {
                const res = await fetch(`${API}/crawl/status`);
                const data = await res.json();
                statusEl.textContent = `${data.status} | ${data.pages_crawled || 0} pages | ${data.links_discovered || 0} links`;

                if (!data.running) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    crawlBtn.disabled = false;
                    stopBtn.disabled = true;
                    await loadCrawlResults();
                }
            } catch (_) {}
        }, 1000);
    }

    async function loadCrawlResults() {
        try {
            const res = await fetch(`${API}/crawl/results`);
            const data = await res.json();
            for (const url of [...(data.visited || []), ...(data.discovered || [])]) {
                addUrl(url);
            }
        } catch (_) {}
    }

    // ── Context Menu ──────────────────────

    let ctxMenu = null;

    function showContextMenu(x, y, url, host, pathParts) {
        hideContextMenu();

        ctxMenu = document.createElement('div');
        ctxMenu.className = 'ctx-menu';
        ctxMenu.style.left = x + 'px';
        ctxMenu.style.top = y + 'px';

        const items = [
            { label: 'Open in Browser', action: () => { window.electronAPI.navigate(url); document.getElementById('url-input').value = url; } },
            { label: 'Copy URL', action: () => navigator.clipboard.writeText(url) },
            { label: 'Scan with Injector', action: () => { InjectorUI.loadFromLog({ url, method: 'GET', request_headers: {}, request_body: '' }); switchTab('injector'); } },
            { label: 'Add Credentials for Site', action: () => { Credentials.openWithSite(host || new URL(url).host); switchTab('settings'); } },
            { label: 'Start Crawl from Here', action: () => { crawlBtn.disabled = true; stopBtn.disabled = false; statusEl.textContent = 'Starting...'; fetch(`${API}/crawl?url=${encodeURIComponent(url)}&max_depth=5&max_pages=100`, { method: 'POST' }).then(pollCrawlStatus); } },
            { label: 'Remove from Site Map', cls: 'ctx-menu-item--danger', action: () => { removeNode(host || new URL(url).host, pathParts); } },
        ];

        items.forEach(({ label, action, cls }) => {
            const item = document.createElement('div');
            item.className = cls ? `ctx-menu-item ${cls}` : 'ctx-menu-item';
            item.textContent = label;
            item.addEventListener('click', (e) => { e.stopPropagation(); action(); hideContextMenu(); });
            ctxMenu.appendChild(item);
        });

        document.body.appendChild(ctxMenu);

        // Close on any click elsewhere
        setTimeout(() => document.addEventListener('click', hideContextMenu, { once: true }), 0);
    }

    function removeNode(host, pathParts) {
        if (!pathParts || pathParts.length === 0) {
            // Removing an entire host
            delete treeData[host];
        } else {
            // Walk to the parent and delete the child key
            let node = treeData[host];
            if (!node) return;
            let parent = node._children;
            for (let i = 0; i < pathParts.length - 1; i++) {
                if (!parent[pathParts[i]]) return;
                parent = parent[pathParts[i]]._children;
            }
            delete parent[pathParts[pathParts.length - 1]];
        }
        renderTree();
    }

    function hideContextMenu() {
        if (ctxMenu && ctxMenu.parentNode) {
            ctxMenu.parentNode.removeChild(ctxMenu);
        }
        ctxMenu = null;
    }

    function switchTab(tabName) {
        document.querySelectorAll('#tab-bar .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.dataset.tab === tabName));
    }

    /** Reset the tree (used on workspace switch) */
    function clear() {
        treeData = {};
        renderTree();
    }

    return { init, addUrl, addUrls, clear };
})();
