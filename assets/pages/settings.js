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

  // Загрузка текущих настроек
  window.electronAPI.getSettings().then(settings => {
    autoUpdateCheck.checked = settings.autoUpdate || false;
  });

  saveBtn.addEventListener('click', () => {
    window.electronAPI.saveSettings({ autoUpdate: autoUpdateCheck.checked });
    alert('Настройки сохранены');
  });

  cancelBtn.addEventListener('click', () => {
    loadPage('home');
    setActiveSidebarButton('home');
    updateTabHeader('Главная');
  });

  // Показ модального окна при первом запуске
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

  // Проверка обновлений при загрузке настроек, если включено
  window.electronAPI.getSettings().then(settings => {
    if (settings.autoUpdate) {
      window.electronAPI.checkForUpdates().then(({ currentVersion, latestVersion }) => {
        if (latestVersion && compareVersions(latestVersion, currentVersion) > 0) {
          const updateModal = document.getElementById('update-modal');
          const updateMessage = document.getElementById('update-message');
          const updateYes = document.getElementById('update-yes');
          const updateNo = document.getElementById('update-no');

          updateMessage.textContent = `Вышла новая версия ${latestVersion}, хотите обновить?`;
          updateModal.style.display = 'block';

          updateYes.addEventListener('click', () => {
            window.electronAPI.openExternalLink('https://github.com/BerkutSolutions/berkut-cyber-base');
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
  const v1parts = v1.split('.').map(Number);
  const v2parts = v2.split('.').map(Number);
  for (let i = 0; i < v1parts.length; i++) {
    if (v2parts[i] === undefined) return 1;
    if (v1parts[i] > v2parts[i]) return 1;
    if (v1parts[i] < v2parts[i]) return -1;
  }
  return v1parts.length < v2parts.length ? -1 : 0;
}