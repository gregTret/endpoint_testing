const { app, BrowserWindow, BrowserView, ipcMain } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');

// ── Configuration ──────────────────────────────────────────────────
const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 8080;
const BACKEND_PORT = 8000;
const TOOL_PANEL_WIDTH = 520;
const NAV_BAR_HEIGHT = 52;

let mainWindow;
let browserView;
let pythonProcess;

// ── Backend lifecycle ──────────────────────────────────────────────

function startBackend() {
    const backendDir = path.join(__dirname, '..', 'backend');
    pythonProcess = spawn(
        'python',
        ['-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT)],
        { cwd: backendDir, env: { ...process.env, PYTHONUNBUFFERED: '1' } },
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
        backgroundColor: '#0d1117',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
        title: 'Endpoint Security Tool',
    });

    mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

    // Embedded browser — routes through mitmproxy
    browserView = new BrowserView({
        webPreferences: { contextIsolation: true, nodeIntegration: false },
    });
    mainWindow.setBrowserView(browserView);

    browserView.webContents.session.setProxy({
        proxyRules: `http=${PROXY_HOST}:${PROXY_PORT};https=${PROXY_HOST}:${PROXY_PORT}`,
    });

    // Trust mitmproxy's TLS certificates
    browserView.webContents.session.setCertificateVerifyProc((_req, cb) => cb(0));

    updateBounds();
    mainWindow.on('resize', updateBounds);
    mainWindow.on('maximize', () => setTimeout(updateBounds, 80));
    mainWindow.on('unmaximize', () => setTimeout(updateBounds, 80));

    // Forward URL changes to the renderer
    browserView.webContents.on('did-navigate', (_e, url) => {
        mainWindow.webContents.send('url-changed', url);
    });
    browserView.webContents.on('did-navigate-in-page', (_e, url) => {
        mainWindow.webContents.send('url-changed', url);
    });

    browserView.webContents.loadURL('https://example.com');
}

function updateBounds() {
    if (!mainWindow || !browserView) return;
    const [w, h] = mainWindow.getContentSize();
    browserView.setBounds({
        x: TOOL_PANEL_WIDTH,
        y: NAV_BAR_HEIGHT,
        width: Math.max(w - TOOL_PANEL_WIDTH, 200),
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

// ── App lifecycle ──────────────────────────────────────────────────

app.commandLine.appendSwitch('ignore-certificate-errors');

app.whenReady().then(() => {
    startBackend();
    setTimeout(createWindow, 2000); // give backend a moment to boot
});

function killBackend() {
    if (!pythonProcess) return;
    try {
        // Windows needs taskkill to kill the entire process tree
        execSync(`taskkill /F /T /PID ${pythonProcess.pid}`, { stdio: 'ignore' });
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
