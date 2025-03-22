const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

let mainWindow;

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

  mainWindow.loadFile('index.html');
  mainWindow.setMenu(null);
  mainWindow.webContents.openDevTools();
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
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
