const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('monitorAPI', {
    onConfig:       (cb) => ipcRenderer.on('monitor-config', (_e, cfg) => cb(cfg)),
    onConfigUpdate: (cb) => ipcRenderer.on('monitor-update-config', (_e, cfg) => cb(cfg)),
});
