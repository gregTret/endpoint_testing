const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    navigate:      (url) => ipcRenderer.send('navigate', url),
    goBack:        ()    => ipcRenderer.send('go-back'),
    goForward:     ()    => ipcRenderer.send('go-forward'),
    refresh:       ()    => ipcRenderer.send('refresh'),
    getCurrentUrl: ()    => ipcRenderer.invoke('get-current-url'),
    onUrlChanged:  (cb)  => ipcRenderer.on('url-changed', (_e, url) => cb(url)),
});
