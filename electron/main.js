const { app, BrowserWindow, BrowserView, ipcMain, Menu } = require('electron');
const path = require('path');
const { spawn, exec, execSync } = require('child_process');
const http = require('http');

// ── Configuration ──────────────────────────────────────────────────
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 8080;
const BACKEND_PORT = 8000;
let TOOL_PANEL_WIDTH = 620;
const NAV_BAR_HEIGHT = 52;
const IS_WIN = process.platform === 'win32';

let mainWindow;
let browserView;
let pythonProcess;

// ── Python detection ──────────────────────────────────────────────

/**
 * Find a working Python 3 executable on this system.
 * Tries python3 first (macOS / Linux default), then python.
 */
function findPython() {
    for (const cmd of ['python3', 'python']) {
        try {
            const ver = execSync(`${cmd} --version`, {
                encoding: 'utf-8',
                stdio: ['pipe', 'pipe', 'ignore'],
            }).trim();
            if (ver.startsWith('Python 3')) {
                console.log(`[Startup] Using ${cmd} (${ver})`);
                return cmd;
            }
        } catch (_) {}
    }
    console.error('[Startup] No Python 3 found — falling back to "python"');
    return 'python';
}

const PYTHON = findPython();

// ── Backend lifecycle ──────────────────────────────────────────────

/**
 * Kill anything bound to the given port (async, non-blocking).
 * Returns a Promise that resolves when cleanup is done.
 */
function freePort(port) {
    return new Promise((resolve) => {
        if (IS_WIN) {
            exec(
                `netstat -ano | findstr ":${port}" | findstr "LISTENING"`,
                { encoding: 'utf-8' },
                (err, stdout) => {
                    if (err || !stdout.trim()) return resolve();
                    const pids = new Set();
                    for (const line of stdout.trim().split('\n')) {
                        const pid = line.trim().split(/\s+/).pop();
                        if (pid && pid !== '0') pids.add(pid);
                    }
                    let remaining = pids.size;
                    if (remaining === 0) return resolve();
                    for (const pid of pids) {
                        console.log(`[Startup] killing stale process on port ${port} (PID ${pid})`);
                        exec(`taskkill /F /T /PID ${pid}`, { stdio: 'ignore' }, () => {
                            if (--remaining <= 0) resolve();
                        });
                    }
                },
            );
        } else {
            exec(
                `lsof -ti :${port}`,
                { encoding: 'utf-8' },
                (err, stdout) => {
                    if (err || !stdout.trim()) return resolve();
                    const pids = stdout.trim().split('\n').filter(Boolean);
                    let remaining = pids.length;
                    if (remaining === 0) return resolve();
                    for (const pid of pids) {
                        console.log(`[Startup] killing stale process on port ${port} (PID ${pid})`);
                        exec(`kill -9 ${pid}`, () => {
                            if (--remaining <= 0) resolve();
                        });
                    }
                },
            );
        }
    });
}

async function startBackend() {
    // Clean up both ports in parallel
    await Promise.all([freePort(BACKEND_PORT), freePort(PROXY_PORT)]);

    const backendDir = path.join(__dirname, '..', 'backend');
    pythonProcess = spawn(
        PYTHON,
        ['-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT)],
        { cwd: backendDir, env: { ...process.env, PYTHONUNBUFFERED: '1' }, detached: !IS_WIN },
    );
    pythonProcess.stdout.on('data', (d) => console.log(`[Backend] ${d.toString().trim()}`));
    pythonProcess.stderr.on('data', (d) => console.log(`[Backend] ${d.toString().trim()}`));
    pythonProcess.on('close', (code) => console.log(`[Backend] exited ${code}`));
}

// ── Window + BrowserView ───────────────────────────────────────────

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1600,
        height: 950,
        minWidth: 1200,
        minHeight: 700,
        show: false,
        backgroundColor: '#0d1117',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
        title: 'Endpoint Security Tool',
    });

    mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

    mainWindow.once('ready-to-show', () => {
        mainWindow.maximize();
        mainWindow.show();
    });

    mainWindow.on('resize', updateBounds);
    mainWindow.on('maximize', () => setTimeout(updateBounds, 80));
    mainWindow.on('unmaximize', () => setTimeout(updateBounds, 80));
}

/**
 * Create (or recreate) the BrowserView with a session partition
 * scoped to the given workspace ID.  Cookies, localStorage, cache
 * are all persisted separately per workspace.
 */
async function createBrowserView(workspaceId, initialUrl) {
    // Detach + destroy the previous view if any
    if (browserView) {
        mainWindow.setBrowserView(null);
        browserView.webContents.destroy();
        browserView = null;
    }

    const partition = `persist:ws_${workspaceId}`;
    browserView = new BrowserView({
        webPreferences: {
            contextIsolation: true,
            nodeIntegration: false,
            partition,
        },
    });

    // Route ALL traffic through mitmproxy — await to ensure proxy is
    // active before any requests fire.  Catch-all format ensures no
    // traffic (Azure Blob, CDN, etc.) slips through.
    await browserView.webContents.session.setProxy({
        proxyRules: `http://${PROXY_HOST}:${PROXY_PORT}`,
        proxyBypassRules: '',
    });

    // Trust mitmproxy's TLS certificates
    browserView.webContents.session.setCertificateVerifyProc((_req, cb) => cb(0));

    // Forward URL changes to the renderer
    browserView.webContents.on('did-navigate', (_e, url) => {
        mainWindow.webContents.send('url-changed', url);
    });
    browserView.webContents.on('did-navigate-in-page', (_e, url) => {
        mainWindow.webContents.send('url-changed', url);
    });

    // Right-click context menu with credential auto-fill
    browserView.webContents.on('context-menu', (e, params) => {
        const pageUrl = browserView.webContents.getURL();
        let host = '';
        try { host = new URL(pageUrl).host; } catch (_) {}

        const baseMenu = [
            { label: 'Copy', role: 'copy', enabled: params.selectionText.length > 0 },
            { label: 'Paste', role: 'paste', enabled: params.isEditable },
            { type: 'separator' },
        ];

        // Fetch credentials for this site and build the menu
        fetchCredentials(host).then(creds => {
            const credItems = [];
            if (creds.length > 0) {
                credItems.push({ label: 'Auto-fill Credentials', enabled: false });
                for (const cred of creds.slice(0, 10)) {
                    const label = cred.username
                        ? `${cred.auth_type}: ${cred.username} (${cred.site})`
                        : `${cred.auth_type}: ${cred.site}`;
                    credItems.push({
                        label,
                        click: () => autoFillCredential(cred),
                    });
                }
            } else {
                credItems.push({ label: 'No credentials for this site', enabled: false });
            }

            const menu = Menu.buildFromTemplate([...baseMenu, ...credItems]);
            menu.popup({ window: mainWindow });
        }).catch(() => {
            const menu = Menu.buildFromTemplate([...baseMenu, { label: 'Credentials unavailable', enabled: false }]);
            menu.popup({ window: mainWindow });
        });
    });

    mainWindow.setBrowserView(browserView);
    updateBounds();
    browserView.webContents.loadURL(initialUrl || 'https://example.com');
}

/**
 * Fetch credentials from the backend API for a given host.
 */
function fetchCredentials(host) {
    const qs = host ? `?site=${encodeURIComponent(host)}` : '';
    return new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${BACKEND_PORT}/api/credentials${qs}`, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch (_) { resolve([]); }
            });
        }).on('error', reject);
    });
}

/**
 * Inject credential values into form fields on the current page.
 */
function autoFillCredential(cred) {
    if (!browserView) return;

    const js = `
    (function() {
        // Find password and username fields
        const pwFields = document.querySelectorAll('input[type="password"]');
        const userFields = document.querySelectorAll(
            'input[type="email"], input[type="text"][name*="user"], input[type="text"][name*="email"], ' +
            'input[name*="login"], input[autocomplete="username"], input[autocomplete="email"]'
        );

        // If no specific user fields found, try the input right before the password field
        let userField = userFields[0] || null;
        if (!userField && pwFields.length > 0) {
            let prev = pwFields[0].previousElementSibling;
            while (prev) {
                if (prev.tagName === 'INPUT' && prev.type !== 'hidden') { userField = prev; break; }
                prev = prev.previousElementSibling;
            }
        }

        const username = ${JSON.stringify(cred.username || '')};
        const password = ${JSON.stringify(cred.password || '')};
        const token    = ${JSON.stringify(cred.token || '')};

        function fill(el, value) {
            if (!el || !value) return;
            el.focus();
            el.value = value;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        }

        if (userField) fill(userField, username);
        pwFields.forEach(f => fill(f, password));

        // For token/cookie auth — set via document.cookie or just fill any visible token input
        if (token && !password) {
            const tokenFields = document.querySelectorAll(
                'input[name*="token"], input[name*="key"], input[name*="api"], input[type="text"]'
            );
            if (tokenFields.length) fill(tokenFields[0], token);
        }

        return 'filled';
    })();
    `;

    browserView.webContents.executeJavaScript(js).catch(() => {});
}

const RESIZE_HANDLE_WIDTH = 6;

function updateBounds() {
    if (!mainWindow || !browserView) return;
    const [w, h] = mainWindow.getContentSize();
    const x = TOOL_PANEL_WIDTH + RESIZE_HANDLE_WIDTH;
    browserView.setBounds({
        x,
        y: NAV_BAR_HEIGHT,
        width: Math.max(w - x, 200),
        height: Math.max(h - NAV_BAR_HEIGHT, 200),
    });
}

// ── IPC handlers ───────────────────────────────────────────────────

ipcMain.on('navigate', (_e, url) => {
    if (!browserView) return;
    let target = url.trim();
    if (!/^https?:\/\//.test(target)) target = 'https://' + target;
    browserView.webContents.loadURL(target);
});

ipcMain.on('go-back', () => {
    if (browserView?.webContents.canGoBack()) browserView.webContents.goBack();
});

ipcMain.on('go-forward', () => {
    if (browserView?.webContents.canGoForward()) browserView.webContents.goForward();
});

ipcMain.on('refresh', () => {
    browserView?.webContents.reload();
});

ipcMain.handle('get-current-url', () => {
    return browserView ? browserView.webContents.getURL() : '';
});

ipcMain.on('show-browser', async (_e, workspaceId, lastUrl) => {
    if (!mainWindow) return;
    await createBrowserView(workspaceId || 'default', lastUrl);
});

ipcMain.on('set-panel-width', (_e, width) => {
    TOOL_PANEL_WIDTH = Math.max(200, Math.min(width, 1200));
    updateBounds();
});

ipcMain.on('hide-browser', () => {
    if (!mainWindow) return;
    mainWindow.setBrowserView(null);
});

// ── App lifecycle ──────────────────────────────────────────────────

app.commandLine.appendSwitch('ignore-certificate-errors');

app.whenReady().then(async () => {
    // Show window immediately (workspace launcher handles backend-not-ready gracefully)
    createWindow();
    await startBackend();
});

function killBackend() {
    if (!pythonProcess) return;
    try {
        if (IS_WIN) {
            // Windows needs taskkill to kill the entire process tree
            execSync(`taskkill /F /T /PID ${pythonProcess.pid}`, { stdio: 'ignore' });
        } else {
            // Unix: kill process group
            process.kill(-pythonProcess.pid, 'SIGTERM');
        }
    } catch (_) {
        pythonProcess.kill();
    }
    pythonProcess = null;
}

app.on('window-all-closed', () => {
    killBackend();
    app.quit();
});

app.on('will-quit', () => {
    killBackend();
});

// Catch every exit path on Windows
app.on('before-quit', () => killBackend());
process.on('exit', () => killBackend());
process.on('SIGINT', () => { killBackend(); process.exit(); });
process.on('SIGTERM', () => { killBackend(); process.exit(); });
