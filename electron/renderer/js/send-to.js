/**
 * SendTo — central registry for cross-tab "Send to …" actions.
 *
 * Each tab registers itself as a target with a label and a receive function.
 * Context menus are built dynamically from this registry so adding a new tab
 * automatically makes it available everywhere without touching other tabs.
 */
window.SendTo = (() => {
    // { tabId: { label, receive(data) } }
    const _registry = {};

    /**
     * Register a tab as a send-to target.
     * @param {string} tabId   Tab identifier matching data-tab attribute
     * @param {object} config  { label: string, receive: function(data), tab?: string }
     *   - tab: optional override for the data-tab to switch to (useful for sub-tabs)
     */
    function register(tabId, config) {
        _registry[tabId] = {
            label: config.label || tabId,
            receive: config.receive,
            tab: config.tab || tabId,
        };
    }

    /** Remove a tab from the registry. */
    function unregister(tabId) {
        delete _registry[tabId];
    }

    /** Return all registered targets, optionally excluding one tab. */
    function getTargets(excludeTabId) {
        return Object.entries(_registry)
            .filter(([id]) => id !== excludeTabId)
            .map(([id, cfg]) => ({ id, label: cfg.label }));
    }

    /** Send data to a target tab and switch to it. */
    function sendTo(tabId, data) {
        const target = _registry[tabId];
        if (!target) return;
        target.receive(data);
        _switchTab(target.tab);
    }

    /**
     * Build and show a context menu with all available send-to targets.
     * @param {number} x              Screen X
     * @param {number} y              Screen Y
     * @param {object} requestData    Canonical request shape { method, url, headers, body, ... }
     * @param {string} excludeTabId   Tab to exclude from the menu (the source tab)
     */
    function showContextMenu(x, y, requestData, excludeTabId) {
        _closeAll();
        const targets = getTargets(excludeTabId);
        if (!targets.length) return;

        const menu = document.createElement('div');
        menu.className = 'ctx-menu';
        menu.style.left = x + 'px';
        menu.style.top  = y + 'px';

        targets.forEach(t => {
            const item = document.createElement('div');
            item.className = 'ctx-menu-item';
            item.textContent = 'Send to ' + t.label;
            item.addEventListener('click', () => {
                sendTo(t.id, requestData);
                _closeAll();
            });
            menu.appendChild(item);
        });

        document.body.appendChild(menu);
        const dismiss = () => { _closeAll(); document.removeEventListener('click', dismiss); };
        setTimeout(() => document.addEventListener('click', dismiss), 0);
    }

    function _switchTab(tabId) {
        document.querySelectorAll('#tab-bar .tab').forEach(t =>
            t.classList.toggle('active', t.dataset.tab === tabId));
        document.querySelectorAll('.tab-pane').forEach(p =>
            p.classList.toggle('active', p.dataset.tab === tabId));
    }

    function _closeAll() {
        document.querySelectorAll('.ctx-menu').forEach(m => m.remove());
    }

    return { register, unregister, getTargets, sendTo, showContextMenu };
})();
