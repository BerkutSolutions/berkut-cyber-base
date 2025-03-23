const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  minimizeWindow: () => ipcRenderer.invoke('minimize-window'),
  maximizeWindow: () => ipcRenderer.invoke('maximize-window'),
  closeWindow: () => ipcRenderer.invoke('close-window'),
  onWindowRestored: (callback) => ipcRenderer.on('window-restored', callback),
  onWindowMaximized: (callback) => ipcRenderer.on('window-maximized', callback),
  onWindowUnmaximized: (callback) => ipcRenderer.on('window-unmaximized', callback),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  onShowUpdatePrompt: (callback) => ipcRenderer.on('show-update-prompt', callback),
  onUpdateAvailable: (callback) => ipcRenderer.on('update-available', callback),
  setInitialUpdateSetting: (value) => ipcRenderer.send('set-initial-update-setting', value),
  openExternalLink: (url) => ipcRenderer.send('open-external-link', url), // Новый метод
});