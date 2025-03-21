const { contextBridge, ipcRenderer } = require('electron');

console.log('Loading preload.js...');

contextBridge.exposeInMainWorld('electronAPI', {
  minimizeWindow: () => ipcRenderer.invoke('minimize-window'),
  maximizeWindow: () => ipcRenderer.invoke('maximize-window'),
  closeWindow: () => ipcRenderer.invoke('close-window'),
  onWindowRestored: (callback) => ipcRenderer.on('window-restored', callback),
});