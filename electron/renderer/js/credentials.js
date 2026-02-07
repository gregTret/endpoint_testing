/**
 * Credentials — site credential vault
 */
window.Credentials = (() => {
    const API = 'http://127.0.0.1:8000/api';
    let listEl, formEl, searchEl;
    let siteEl, authTypeEl, usernameEl, passwordEl, tokenEl, notesEl, editIdEl;

    function init() {
        listEl      = document.getElementById('cred-list');
        formEl      = document.getElementById('cred-form');
        searchEl    = document.getElementById('cred-search');
        siteEl      = document.getElementById('cred-site');
        authTypeEl  = document.getElementById('cred-auth-type');
        usernameEl  = document.getElementById('cred-username');
        passwordEl  = document.getElementById('cred-password');
        tokenEl     = document.getElementById('cred-token');
        notesEl     = document.getElementById('cred-notes');
        editIdEl    = document.getElementById('cred-edit-id');

        document.getElementById('btn-add-cred').addEventListener('click', showForm);
        document.getElementById('btn-save-cred').addEventListener('click', saveCred);
        document.getElementById('btn-cancel-cred').addEventListener('click', hideForm);
        searchEl.addEventListener('input', loadCreds);

        loadCreds();
    }

    function showForm() {
        editIdEl.value = '';
        siteEl.value = '';
        authTypeEl.value = 'basic';
        usernameEl.value = '';
        passwordEl.value = '';
        tokenEl.value = '';
        notesEl.value = '';
        formEl.classList.remove('hidden');
    }

    function hideForm() {
        formEl.classList.add('hidden');
    }

    async function saveCred() {
        const data = {
            site: siteEl.value,
            auth_type: authTypeEl.value,
            username: usernameEl.value,
            password: passwordEl.value,
            token: tokenEl.value,
            notes: notesEl.value,
        };

        const editId = editIdEl.value;
        try {
            if (editId) {
                await fetch(`${API}/credentials/${editId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
            } else {
                await fetch(`${API}/credentials`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data),
                });
            }
        } catch (_) {}

        hideForm();
        loadCreds();
    }

    async function loadCreds() {
        const filter = (searchEl.value || '').trim();
        const qs = filter ? `?site=${encodeURIComponent(filter)}` : '';
        try {
            const res = await fetch(`${API}/credentials${qs}`);
            const creds = await res.json();
            renderList(creds);
        } catch (_) {
            listEl.innerHTML = '<p class="placeholder-text" style="padding:10px">Could not load credentials</p>';
        }
    }

    function renderList(creds) {
        if (!creds.length) {
            listEl.innerHTML = '<p class="placeholder-text" style="padding:10px">No saved credentials</p>';
            return;
        }

        listEl.innerHTML = creds.map(c => `
            <div class="cred-entry" data-id="${c.id}">
                <div class="cred-entry-header">
                    <span class="cred-site">${esc(c.site)}</span>
                    <span class="cred-auth-type">${esc(c.auth_type)}</span>
                </div>
                <div class="cred-detail">
                    ${c.username ? 'user: ' + esc(c.username) : ''}
                    ${c.token ? ' token: ' + esc(c.token.substring(0, 20)) + '...' : ''}
                </div>
                ${c.notes ? '<div class="cred-detail">' + esc(c.notes) + '</div>' : ''}
                <div class="cred-actions">
                    <button class="cred-edit" data-id="${c.id}">Edit</button>
                    <button class="cred-use" data-id="${c.id}">Use in Injector</button>
                    <button class="cred-delete danger" data-id="${c.id}">Delete</button>
                </div>
            </div>
        `).join('');

        listEl.querySelectorAll('.cred-edit').forEach(btn => {
            btn.addEventListener('click', () => editCred(creds.find(c => c.id === Number(btn.dataset.id))));
        });

        listEl.querySelectorAll('.cred-use').forEach(btn => {
            btn.addEventListener('click', () => useCred(creds.find(c => c.id === Number(btn.dataset.id))));
        });

        listEl.querySelectorAll('.cred-delete').forEach(btn => {
            btn.addEventListener('click', () => deleteCred(Number(btn.dataset.id)));
        });
    }

    function editCred(cred) {
        if (!cred) return;
        editIdEl.value = cred.id;
        siteEl.value = cred.site || '';
        authTypeEl.value = cred.auth_type || 'basic';
        usernameEl.value = cred.username || '';
        passwordEl.value = cred.password || '';
        tokenEl.value = cred.token || '';
        notesEl.value = cred.notes || '';
        formEl.classList.remove('hidden');
    }

    function useCred(cred) {
        if (!cred) return;
        // Populate injector headers based on auth type
        const headersEl = document.getElementById('inject-headers');
        let headers = {};
        try { headers = headersEl.value ? JSON.parse(headersEl.value) : {}; } catch (_) {}

        if (cred.auth_type === 'bearer' && cred.token) {
            headers['Authorization'] = `Bearer ${cred.token}`;
        } else if (cred.auth_type === 'api_key' && cred.token) {
            headers['X-API-Key'] = cred.token;
        } else if (cred.auth_type === 'basic' && cred.username) {
            const encoded = btoa(`${cred.username}:${cred.password || ''}`);
            headers['Authorization'] = `Basic ${encoded}`;
        } else if (cred.auth_type === 'cookie' && cred.token) {
            headers['Cookie'] = cred.token;
        }

        headersEl.value = JSON.stringify(headers, null, 2);

        // Switch to injector tab
        document.querySelectorAll('#tab-bar .tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === 'injector');
        });
        document.querySelectorAll('.tab-pane').forEach(p => {
            p.classList.toggle('active', p.dataset.tab === 'injector');
        });
    }

    async function deleteCred(id) {
        try {
            await fetch(`${API}/credentials/${id}`, { method: 'DELETE' });
        } catch (_) {}
        loadCreds();
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    /** Open the form with a site pre-filled (called from site map context menu) */
    function openWithSite(site) {
        showForm();
        siteEl.value = site || '';
    }

    return { init, loadCreds, openWithSite };
})();
