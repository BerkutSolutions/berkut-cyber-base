function loadSettingsContent(contentArea, setActiveSidebarButton, updateTabHeader, loadPage) {
  contentArea.innerHTML = `
    <h1>Настройки</h1>
    <div class="settings-container">
      <label>
        <input type="checkbox" id="auto-update-check">
        Проверять обновления с Github автоматически
      </label>
      <div class="settings-buttons">
        <button id="save-settings" class="osi-btn">Сохранить</button>
        <button id="cancel-settings" class="osi-btn">Отмена</button>
      </div>
    </div>
    <div id="modal" class="modal" style="display: none;">
      <div class="modal-content">
        <p>Хотите автоматически проверять обновления с Github?</p>
        <button id="modal-yes" class="osi-btn">Да</button>
        <button id="modal-no" class="osi-btn">Нет</button>
      </div>
    </div>
  `;

  const autoUpdateCheck = document.getElementById('auto-update-check');
  const saveBtn = document.getElementById('save-settings');
  const cancelBtn = document.getElementById('cancel-settings');
  const modal = document.getElementById('modal');
  const modalYes = document.getElementById('modal-yes');
  const modalNo = document.getElementById('modal-no');

  saveBtn.addEventListener('click', () => {
    window.electronAPI.saveSettings({ autoUpdate: autoUpdateCheck.checked });
    alert('Настройки сохранены');
  });

  cancelBtn.addEventListener('click', () => {
    loadPage('home');
    setActiveSidebarButton('home');
    updateTabHeader('Главная');
  });

  window.electronAPI.onShowUpdatePrompt(() => {
    modal.style.display = 'block';
  });

  modalYes.addEventListener('click', () => {
    window.electronAPI.setInitialUpdateSetting(true);
    autoUpdateCheck.checked = true;
    modal.style.display = 'none';
  });

  modalNo.addEventListener('click', () => {
    window.electronAPI.setInitialUpdateSetting(false);
    autoUpdateCheck.checked = false;
    modal.style.display = 'none';
  });

  window.electronAPI.getSettings().then(settings => {
    if (settings.autoUpdate) {
      window.electronAPI.checkForUpdates().then(({ currentVersion, latestVersion, downloadUrl }) => {
        if (latestVersion && compareVersions(latestVersion, currentVersion) > 0) {
          const updateModal = document.getElementById('update-modal');
          const updateMessage = document.getElementById('update-message');
          const updateYes = document.getElementById('update-yes');
          const updateNo = document.getElementById('update-no');
  
          updateMessage.textContent = `Вышла новая версия ${latestVersion}, хотите обновить?`;
          updateModal.style.display = 'block';
  
          updateYes.addEventListener('click', () => {
            window.electronAPI.openExternalLink(downloadUrl || 'https://github.com/BerkutSolutions/berkut-cyber-base/releases/latest');
            updateModal.style.display = 'none';
          });
  
          updateNo.addEventListener('click', () => {
            updateModal.style.display = 'none';
          });
        }
      });
    }
  });
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

  if (version1.suffix && !version2.suffix) return -1;
  if (!version1.suffix && version2.suffix) return 1;
  if (version1.suffix && version2.suffix) {
    return version1.suffix.localeCompare(version2.suffix);
  }
  return 0;
}