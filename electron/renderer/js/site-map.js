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
        renderTree();
    }

    function renderTree() {
        treeEl.innerHTML = '';
        for (const [host, data] of Object.entries(treeData)) {
            const hostNode = createTreeNode(host, data._children, 0, true);
            treeEl.appendChild(hostNode);
        }
    }

    function createTreeNode(label, children, depth, isHost) {
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

        const childContainer = document.createElement('div');
        childContainer.style.display = 'none';

        for (const key of childKeys) {
            childContainer.appendChild(createTreeNode(key, children[key]._children, depth + 1, false));
        }
        wrap.appendChild(childContainer);

        if (hasChildren) {
            row.addEventListener('click', () => {
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

    return { init, addUrl };
})();
