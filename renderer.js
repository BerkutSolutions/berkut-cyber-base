document.addEventListener('DOMContentLoaded', () => {
  console.log('DOMContentLoaded event fired');
  const windowContainer = document.getElementById('window-container');
  const contentArea = document.getElementById('content-area');

  if (!windowContainer) {
    console.error('Element with id "window-container" not found. Check your index.html structure.');
    console.log('Current DOM:', document.body.innerHTML);
    return;
  }

  windowContainer.style.display = 'block';

  if (!window.electronAPI) {
    console.error('electronAPI is not available. Check if preload.js is loaded correctly.');
    return;
  }

  document.getElementById('minimize-btn').addEventListener('click', () => {
    windowContainer.classList.add('minimize-animation');
    setTimeout(() => {
      window.electronAPI.minimizeWindow();
      windowContainer.classList.remove('minimize-animation');
    }, 400);
  });

  document.getElementById('maximize-btn').addEventListener('click', () => {
    const isMaximized = windowContainer.classList.contains('maximized');
    if (isMaximized) {
      windowContainer.classList.add('unmaximize-animation');
      setTimeout(() => {
        window.electronAPI.maximizeWindow();
        windowContainer.classList.remove('unmaximize-animation', 'maximized');
      }, 500);
    } else {
      windowContainer.classList.add('maximize-animation');
      setTimeout(() => {
        window.electronAPI.maximizeWindow();
        windowContainer.classList.remove('maximize-animation');
        windowContainer.classList.add('maximized');
      }, 500);
    }
  });

  document.getElementById('close-btn').addEventListener('click', () => {
    windowContainer.classList.add('close-animation');
    setTimeout(() => {
      window.electronAPI.closeWindow();
    }, 200);
  });

  window.electronAPI.onWindowRestored(() => {
    windowContainer.classList.add('restore-animation');
    setTimeout(() => {
      windowContainer.classList.remove('restore-animation');
    }, 400);
  });

  function setActiveSidebarButton(section) {
    document.querySelectorAll('.sidebar-btn').forEach((btn) => {
      btn.classList.remove('active');
    });
    const activeBtn = document.querySelector(`[data-section="${section}"]`);
    if (activeBtn) activeBtn.classList.add('active');
  }

  function updateTabHeader(title) {
    const tabHeader = document.getElementById('tab-header');
    if (tabHeader) {
      tabHeader.textContent = title;
    } else {
      console.error('Element with id "tab-header" not found.');
    }
  }

  function loadPage(section) {
    if (section === 'osi') {
      if (typeof loadOsiContent === 'function') {
        loadOsiContent(contentArea);
      } else {
        console.error('loadOsiContent is not defined. Check if osi.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Модель OSI".</p>`;
      }
    } else if (section === 'vulnerabilities') {
      if (typeof loadVulnerabilitiesContent === 'function') {
        loadVulnerabilitiesContent(contentArea);
      } else {
        console.error('loadVulnerabilitiesContent is not defined. Check if vulnerabilities.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Уязвимости".</p>`;
      }
    } else if (section === 'network-building') {
      if (typeof loadNetworkBuildingContent === 'function') {
        loadNetworkBuildingContent(contentArea);
      } else {
        console.error('loadNetworkBuildingContent is not defined. Check if networkBuilding.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Построение сетей".</p>`;
      }
    } else if (section === 'cryptography') {
      if (typeof loadCryptographyContent === 'function') {
        loadCryptographyContent(contentArea);
      } else {
        console.error('loadCryptographyContent is not defined. Check if cryptography.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Криптография".</p>`;
      }
    } else if (section === 'ep-pki') {
      if (typeof loadEpPkiContent === 'function') {
        loadEpPkiContent(contentArea);
      } else {
        console.error('loadEpPkiContent is not defined. Check if epPki.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "ЭП и PKI".</p>`;
      }
    } else if (section === 'ib-tools') {
      if (typeof loadSecurityToolsContent === 'function') {
        loadSecurityToolsContent(contentArea);
      } else {
        console.error('loadSecurityToolsContent is not defined. Check if ibTools.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Инструменты ИБ".</p>`;
      }
    } else if (section === 'structure-security') {
      if (typeof loadStructureSecurityContent === 'function') {
        loadStructureSecurityContent(contentArea);
      } else {
        console.error('loadStructureSecurityContent is not defined. Check if structureSecurity.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Защита структур".</p>`;
      }
    } else if (section === 'legal-regulations') {
      if (typeof loadLegalRegulationsContent === 'function') {
        loadLegalRegulationsContent(contentArea);
      } else {
        console.error('loadLegalRegulationsContent is not defined. Check if legalRegulations.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Правовые нормы".</p>`;
      }
    } else if (section === 'training') {
      if (typeof loadTrainingContent === 'function') {
        loadTrainingContent(contentArea);
      } else {
        console.error('loadTrainingContent is not defined. Check if training.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Обучение и тестирование".</p>`;
      }
    } else {
      const tabHeader = document.getElementById('tab-header');
      if (tabHeader) {
        contentArea.innerHTML = `<h1>${tabHeader.textContent}</h1>`;
      } else {
        console.error('Element with id "tab-header" not found.');
        contentArea.innerHTML = `<h1>Главная</h1>`;
      }
    }
  }

  document.querySelectorAll('.sidebar-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const section = btn.getAttribute('data-section');
      setActiveSidebarButton(section);
      updateTabHeader(btn.textContent.trim());
      loadPage(section);
    });
  });

  setActiveSidebarButton('home');
  updateTabHeader('Главная');
  loadPage('home');
});