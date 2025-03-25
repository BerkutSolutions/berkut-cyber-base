const { app, BrowserWindow, ipcMain, shell, globalShortcut } = require('electron');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');

let mainWindow;
const settingsPath = path.join(__dirname, 'assets', 'settings.json');
const currentVersion = '1.0.4';

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

  mainWindow.webContents.on('context-menu', (e) => {
    e.preventDefault();
  });

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
      const latestVersion = data.tag_name.replace(/^v\.?/, '');
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

  globalShortcut.register('CommandOrControl+Shift+I', () => {
    console.log('DevTools shortcut blocked (Ctrl+Shift+I or Cmd+Shift+I)');
    return false;
  });

  globalShortcut.register('F12', () => {
    console.log('DevTools shortcut blocked (F12)');
    return false;
  });

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

app.on('will-quit', () => {
  globalShortcut.unregisterAll();
});

async function checkForUpdates() {
  try {
    const response = await fetch('https://api.github.com/repos/BerkutSolutions/berkut-cyber-base/releases/latest');
    const data = await response.json();
    const latestVersion = data.tag_name.replace(/^v\.?/, '');
    console.log(`Current version: ${currentVersion}, Latest version: ${latestVersion}`);
    if (latestVersion && compareVersions(latestVersion, currentVersion) > 0) {
      console.log(`Update available: ${latestVersion}`);
      mainWindow.webContents.send('update-available', { version: latestVersion, downloadUrl: data.assets.length > 0 ? data.assets[0].browser_download_url : 'https://github.com/BerkutSolutions/berkut-cyber-base/releases/latest' });
    } else {
      console.log('No update available.');
    }
  } catch (error) {
    console.error('Error checking updates in checkForUpdates:', error);
  }
}

function compareVersions(v1, v2) {
  const parseVersion = (version) => {
    const [mainPart, suffix = ''] = version.split('-');
    const parts = mainPart.split('.').map(Number);
    return { parts, suffix };
  };

  const version1 = parseVersion(v1);
  const version2 = parseVersion(v2);

  const maxLength = Math.max(version1.parts.length, version2.parts.length);
  for (let i = 0; i < maxLength; i++) {
    const part1 = version1.parts[i] || 0;
    const part2 = version2.parts[i] || 0;
    if (part1 > part2) return 1;
    if (part1 < part2) return -1;
  }

  if (version1.suffix && !version2.suffix) return 1;
  if (!version1.suffix && version2.suffix) return -1;
  if (version1.suffix && version2.suffix) {
    return version1.suffix.localeCompare(version2.suffix);
  }
  return 0;
}