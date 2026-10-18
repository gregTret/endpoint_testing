const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    navigate:      (url) => ipcRenderer.send('navigate', url),
    goBack:        ()    => ipcRenderer.send('go-back'),
    goForward:     ()    => ipcRenderer.send('go-forward'),
    refresh:       ()    => ipcRenderer.send('refresh'),
    getCurrentUrl: ()    => ipcRenderer.invoke('get-current-url'),
    onUrlChanged:  (cb)  => ipcRenderer.on('url-changed', (_e, url) => cb(url)),
    showBrowser:   (wsId, lastUrl) => ipcRenderer.send('show-browser', wsId, lastUrl),
    hideBrowser:   ()    => ipcRenderer.send('hide-browser'),
    setPanelWidth: (w)   => ipcRenderer.send('set-panel-width', w),

    // Monitor pop-out
    popOutMonitor:          (cfg) => ipcRenderer.send('open-monitor-window', cfg),
    focusMonitorWindow:     ()    => ipcRenderer.send('focus-monitor-window'),
    sendMonitorConfig:      (cfg) => ipcRenderer.send('monitor-update-config', cfg),
    onMonitorWindowClosed:  (cb)  => ipcRenderer.on('monitor-window-closed', () => cb()),
});
