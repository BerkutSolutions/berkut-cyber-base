const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');

let mainWindow;
const settingsPath = path.join(__dirname, 'assets', 'settings.json');
const currentVersion = '1.0.2';

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    frame: false,
    transparent: true,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      enableRemoteModule: false,
      nodeIntegration: false,
    },
  });

  mainWindow.setMinimumSize(1400, 900);

  mainWindow.loadFile('index.html');
  mainWindow.setMenu(null);
  mainWindow.setBackgroundColor('#00000000');

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.on('minimize', () => {
    console.log('Window minimized');
    mainWindow.setBackgroundColor('#00000000');
  });

  mainWindow.on('restore', () => {
    console.log('Window restored');
    mainWindow.setBackgroundColor('#00000000');
    mainWindow.webContents.send('window-restored');
  });

  mainWindow.on('maximize', () => {
    console.log('Window maximized');
    mainWindow.setBackgroundColor('#00000000');
    mainWindow.webContents.send('window-maximized');
  });

  mainWindow.on('unmaximize', () => {
    console.log('Window unmaximized');
    mainWindow.setBackgroundColor('#00000000');
    mainWindow.webContents.send('window-unmaximized');
  });

  ipcMain.handle('minimize-window', () => {
    mainWindow.minimize();
  });

  ipcMain.handle('maximize-window', () => {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  });

  ipcMain.handle('close-window', () => {
    mainWindow.close();
  });

  ipcMain.handle('get-settings', () => {
    if (!fs.existsSync(settingsPath)) {
      fs.writeFileSync(settingsPath, JSON.stringify({}));
      mainWindow.webContents.send('show-update-prompt');
      return { autoUpdate: false };
    }
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    return settings;
  });

  ipcMain.handle('save-settings', (event, settings) => {
    fs.writeFileSync(settingsPath, JSON.stringify(settings));
  });

  ipcMain.on('set-initial-update-setting', (event, value) => {
    const settings = { autoUpdate: value };
    fs.writeFileSync(settingsPath, JSON.stringify(settings));
  });

  ipcMain.handle('check-for-updates', async () => {
    try {
      const response = await fetch('https://api.github.com/repos/BerkutSolutions/berkut-cyber-base/releases/latest');
      const data = await response.json();
      const latestVersion = data.tag_name.replace('v', '');
      return { currentVersion, latestVersion };
    } catch (error) {
      console.error('Error checking updates:', error);
      return { currentVersion, latestVersion: null };
    }
  });

  ipcMain.on('open-external-link', (event, url) => {
    shell.openExternal(url);
  });
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  const settings = fs.existsSync(settingsPath) ? JSON.parse(fs.readFileSync(settingsPath, 'utf8')) : {};
  if (settings.autoUpdate) {
    checkForUpdates();
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

async function checkForUpdates() {
  try {
    const response = await fetch('https://api.github.com/repos/BerkutSolutions/berkut-cyber-base/releases/latest');
    const data = await response.json();
    const latestVersion = data.tag_name.replace('v', '');
    if (latestVersion && compareVersions(latestVersion, currentVersion) > 0) {
      mainWindow.webContents.send('update-available', latestVersion);
    }
  } catch (error) {
    console.error('Error checking updates in checkForUpdates:', error);
  }
}

function compareVersions(v1, v2) {
  const v1parts = v1.split('.').map(Number);
  const v2parts = v2.split('.').map(Number);
  for (let i = 0; i < v1parts.length; i++) {
    if (v2parts[i] === undefined) return 1;
    if (v1parts[i] > v2parts[i]) return 1;
    if (v1parts[i] < v2parts[i]) return -1;
  }
  return v1parts.length < v2parts.length ? -1 : 0;
}