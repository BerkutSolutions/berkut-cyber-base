// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

const { app, BrowserWindow, ipcMain, shell, globalShortcut } = require('electron');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');

let mainWindow;
const settingsPath = path.join(__dirname, 'assets', 'settings.json');
const logFilePath = path.join(__dirname, 'app-logs.log');
const currentVersion = '1.1.0';
let previousBounds = null;

// Функция для логирования с отправкой в рендер и записью в файл
function logToRenderer(level, message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${level}] ${message}`;
  
  // Отправка в рендер
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('log-message', { level, message: logMessage });
  }
  
  // Запись в файл
  try {
    fs.appendFileSync(logFilePath, `${logMessage}\n`);
  } catch (error) {
    console.error(`Failed to write to log file: ${error.stack}`);
  }
}

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

  mainWindow.on('will-resize', () => {
    if (!mainWindow.isMaximized()) {
      previousBounds = mainWindow.getBounds();
    }
  });

  mainWindow.on('will-move', () => {
    if (!mainWindow.isMaximized()) {
      previousBounds = mainWindow.getBounds();
    }
  });

  mainWindow.on('moved', () => {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
      if (previousBounds) {
        mainWindow.setBounds(previousBounds);
      }
    }
  });

  mainWindow.on('maximize', () => {
    mainWindow.setBackgroundColor('#00000000');
    mainWindow.webContents.send('window-maximized');
    mainWindow.setResizable(false);
  });

  mainWindow.on('unmaximize', () => {
    mainWindow.setBackgroundColor('#00000000');
    mainWindow.webContents.send('window-unmaximized');
    if (previousBounds) {
      mainWindow.setBounds(previousBounds);
    }
    mainWindow.setResizable(true);
  });

  mainWindow.on('minimize', () => {
    mainWindow.setBackgroundColor('#00000000');
  });

  mainWindow.on('restore', () => {
    mainWindow.setBackgroundColor('#00000000');
    mainWindow.webContents.send('window-restored');
    mainWindow.setResizable(true);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  ipcMain.handle('minimize-window', () => {
    mainWindow.minimize();
  });

  ipcMain.handle('maximize-window', () => {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      previousBounds = mainWindow.getBounds();
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
    try {
      const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      return settings;
    } catch (error) {
      return { autoUpdate: false };
    }
  });

  ipcMain.handle('save-settings', (event, settings) => {
    try {
      fs.writeFileSync(settingsPath, JSON.stringify(settings));
    } catch (error) {
    }
  });

  ipcMain.on('set-initial-update-setting', (event, value) => {
    try {
      const settings = { autoUpdate: value };
      fs.writeFileSync(settingsPath, JSON.stringify(settings));
    } catch (error) {
    }
  });

  ipcMain.handle('check-for-updates', async () => {
    try {
      const response = await fetch('https://api.github.com/repos/BerkutSolutions/berkut-cyber-base/releases/latest');
      logToRenderer('INFO', `Fetch response status: ${response.status}`);
      const data = await response.json();
      logToRenderer('INFO', `GitHub API response data: ${JSON.stringify(data)}`);
      const latestVersion = data.tag_name.replace(/^v\.?/, '');
      logToRenderer('INFO', `Parsed latest version: ${latestVersion}`);
      return { currentVersion, latestVersion };
    } catch (error) {
      logToRenderer('ERROR', `Error in check-for-updates: ${error.stack}`);
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
    return false;
  });

  globalShortcut.register('F12', () => {
    return false;
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  logToRenderer('INFO', `Checking for settings file at: ${settingsPath}`);
  const settings = fs.existsSync(settingsPath) ? JSON.parse(fs.readFileSync(settingsPath, 'utf8')) : {};
  logToRenderer('INFO', `Settings loaded at startup: ${JSON.stringify(settings)}`);
  if (settings.autoUpdate) {
    logToRenderer('INFO', 'Auto-update is enabled, calling checkForUpdates...');
    checkForUpdates();
  } else {
    logToRenderer('INFO', 'Auto-update is disabled, skipping update check.');
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('will-quit', () => {
  globalShortcut.unregisterAll();
});

async function checkForUpdates() {
  logToRenderer('INFO', 'Starting checkForUpdates...');
  try {
    const testResponse = await fetch('https://api.github.com');
    const testData = await testResponse.json();
    const response = await fetch('https://api.github.com/repos/BerkutSolutions/berkut-cyber-base/releases/latest');
    const data = await response.json();

    const latestVersion = data.tag_name.replace(/^v\.?/, '');
    logToRenderer('INFO', `Current version: ${currentVersion}, Latest version: ${latestVersion}`);

    const versionComparison = compareVersions(latestVersion, currentVersion);

    if (latestVersion && versionComparison > 0) {
      logToRenderer('INFO', `Update available: ${latestVersion}`);
      const downloadUrl = data.assets.length > 0 ? data.assets[0].browser_download_url : 'https://github.com/BerkutSolutions/berkut-cyber-base/releases/latest';
      logToRenderer('INFO', `Sending update-available event with: ${JSON.stringify({ version: latestVersion, downloadUrl })}`);
      mainWindow.webContents.send('update-available', { version: latestVersion, downloadUrl });
    } else {
    }
  } catch (error) {
    logToRenderer('ERROR', `Error in checkForUpdates: ${error.stack}`);
  }
}

function compareVersions(v1, v2) {
  logToRenderer('INFO', `Comparing versions: ${v1} vs ${v2}`);
  const parseVersion = (version) => {
    const [mainPart, suffix = ''] = version.split('-');
    const parts = mainPart.split('.').map(Number);
    logToRenderer('INFO', `Parsed version: ${version} -> parts: ${parts}, suffix: ${suffix}`);
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

  if (version1.suffix && !version2.suffix) {
    return 1;
  }
  if (!version1.suffix && version2.suffix) {
    return -1;
  }
  if (version1.suffix && version2.suffix) {
    return version1.suffix.localeCompare(version2.suffix);
  }
  return 0;
}
