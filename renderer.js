// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

document.addEventListener('DOMContentLoaded', () => {
  const windowContainer = document.getElementById('window-container');
  const contentArea = document.getElementById('content-area');
  const searchInput = document.getElementById('search-input');
  const clearSearchBtn = document.getElementById('clear-search');
  const maximizeBtn = document.getElementById('maximize-btn');

  if (!windowContainer) {
    console.error('Element with id "window-container" not found. Check your index.html structure.');
    return;
  }

  windowContainer.style.display = 'block';

  if (!window.electronAPI) {
    console.error('electronAPI is not available. Check if preload.js is loaded correctly.');
    return;
  }

  const originalConsoleWarn = console.warn;
  console.warn = (...args) => {
    if (args.some(arg => typeof arg === 'string' && arg.includes('Scheme frame not found'))) {
      return;
    }
    originalConsoleWarn.apply(console, args);
  };

  window.onerror = (message, source, lineno, colno, error) => {
    if (message.includes('Scheme frame not found')) {
      return true;
    }
    return false;
  };

  document.getElementById('minimize-btn').addEventListener('click', () => {
    windowContainer.classList.add('minimize-animation');
    setTimeout(() => {
      window.electronAPI.minimizeWindow();
      windowContainer.classList.remove('minimize-animation');
    }, 400);
  });

  maximizeBtn.addEventListener('click', () => {
    window.electronAPI.maximizeWindow();
  });

  window.electronAPI.onWindowMaximized(() => {
    windowContainer.classList.add('maximized');
    maximizeBtn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path>
      </svg>
    `;
  });

  window.electronAPI.onWindowUnmaximized(() => {
    windowContainer.classList.remove('maximized');
    maximizeBtn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect>
      </svg>
    `;
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

  const updateModal = document.getElementById('update-modal');
  const updateMessage = document.getElementById('update-message');
  const updateYes = document.getElementById('update-yes');
  const updateNo = document.getElementById('update-no');

  window.electronAPI.onUpdateAvailable((event, { version, downloadUrl }) => {
    updateMessage.textContent = `Вышла новая версия ${version}, хотите обновить?`;
    updateModal.style.display = 'block';
  
    updateYes.addEventListener('click', () => {
      window.electronAPI.openExternalLink(downloadUrl);
      updateModal.style.display = 'none';
    });
  
    updateNo.addEventListener('click', () => {
      updateModal.style.display = 'none';
    });
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

  window.loadPage = function(section, targetArea = contentArea) {
    if (targetArea === contentArea && searchInput.value.trim() !== '') return;
  
    try {
      if (section === 'home') {
        loadHomeContent(targetArea);
      } else if (section === 'osi') {
        if (typeof loadOsiContent === 'function') {
          loadOsiContent(targetArea);
        } else {
          console.error('loadOsiContent is not defined. Check if osi.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Модель OSI".</p>`;
        }
      } else if (section === 'vulnerabilities') {
        if (typeof loadVulnerabilitiesContent === 'function') {
          loadVulnerabilitiesContent(targetArea);
        } else {
          console.error('loadVulnerabilitiesContent is not defined. Check if vulnerabilities.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Уязвимостей".</p>`;
        }
      } else if (section === 'malware-analysis') {
        if (typeof loadMalwareAnalysisContent === 'function') {
          loadMalwareAnalysisContent(targetArea);
        } else {
          console.error('loadMalwareAnalysisContent is not defined. Check if malwareAnalysis.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Анализ ВПО".</p>`;
        }
      } else if (section === 'pentesting') {
        if (typeof loadPentestingContent === 'function') {
          loadPentestingContent(targetArea);
        } else {
          console.error('loadPentestingContent is not defined. Check if pentesting.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Пентестинг".</p>`;
        }
      } else if (section === 'social-engineering') {
        if (typeof loadSocialEngineeringContent === 'function') {
          loadSocialEngineeringContent(targetArea);
        } else {
          console.error('loadSocialEngineeringContent is not defined. Check if socialEngineering.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Социальная инженерия".</p>`;
        }
      } else if (section === 'forensics') {
        if (typeof loadForensicsContent === 'function') {
          loadForensicsContent(targetArea);
        } else {
          console.error('loadForensicsContent is not defined. Check if forensics.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Форензика".</p>`;
        }
      } else if (section === 'network-building') {
        if (typeof loadNetworkBuildingContent === 'function') {
          loadNetworkBuildingContent(targetArea);
        } else {
          console.error('loadNetworkBuildingContent is not defined. Check if networkBuilding.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Построение сетей".</p>`;
        }
      } else if (section === 'cryptography') {
        if (typeof loadCryptographyContent === 'function') {
          loadCryptographyContent(targetArea);
        } else {
          console.error('loadCryptographyContent is not defined. Check if cryptography.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Криптография".</p>`;
        }
      } else if (section === 'ep-pki') {
        if (typeof loadEpPkiContent === 'function') {
          loadEpPkiContent(targetArea);
        } else {
          console.error('loadEpPkiContent is not defined. Check if epPki.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "ЭП и PKI".</p>`;
        }
      } else if (section === 'ib-tools') {
        if (typeof loadSecurityToolsContent === 'function') {
          loadSecurityToolsContent(targetArea);
        } else {
          console.error('loadSecurityToolsContent is not defined. Check if ibTools.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Инструменты ИБ".</p>`;
        }
      } else if (section === 'structure-security') {
        if (typeof loadStructureSecurityContent === 'function') {
          loadStructureSecurityContent(targetArea);
        } else {
          console.error('loadStructureSecurityContent is not defined. Check if structureSecurity.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Защита структур".</p>`;
        }
      } else if (section === 'legal-regulations') {
        if (typeof loadLegalRegulationsContent === 'function') {
          loadLegalRegulationsContent(targetArea);
        } else {
          console.error('loadLegalRegulationsContent is not defined. Check if legalRegulations.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Правовые нормы".</p>`;
        }
      } else if (section === 'lna-lnd') {
        if (typeof loadLnaLndContent === 'function') {
          loadLnaLndContent(targetArea);
        } else {
          console.error('loadLnaLndContent is not defined. Check if lnaLnd.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "ЛНА и ЛНД".</p>`;
        }
      } else if (section === 'threat-model') {
        if (typeof loadThreatModelContent === 'function') {
          loadThreatModelContent(targetArea);
        } else {
          console.error('loadThreatModelContent is not defined. Check if threatModel.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Модель угроз".</p>`;
        }
      } else if (section === 'training') {
        if (typeof loadTrainingContent === 'function') {
          loadTrainingContent(targetArea);
        } else {
          console.error('loadTrainingContent is not defined. Check if training.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Обучение и тестирование".</p>`;
        }
      } else if (section === 'russian-szi') {
        if (typeof loadRussianSziContent === 'function') {
          loadRussianSziContent(targetArea);
        } else {
          console.error('loadRussianSziContent is not defined. Check if russianSzi.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Российские СЗИ".</p>`;
        }
      } else if (section === 'osint') {
        if (typeof loadOsintContent === 'function') {
          loadOsintContent(targetArea);
        } else {
          console.error('loadOsintContent is not defined. Check if osint.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "OSINT".</p>`;
        }
      } else if (section === 'certificates') {
        if (typeof loadCertificatesContent === 'function') {
          loadCertificatesContent(targetArea);
        } else {
          console.error('loadCertificatesContent is not defined. Check if certificates.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Сертификаты".</p>`;
        }
      } else if (section === 'teams-threat-intel') {
        if (typeof loadTeamsThreatIntelContent === 'function') {
          loadTeamsThreatIntelContent(targetArea);
        } else {
          console.error('loadTeamsThreatIntelContent is not defined. Check if teamsThreatIntel.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Команды ИБ".</p>`;
        }
      } else if (section === 'ai-security') {
        if (typeof loadAiSecurityContent === 'function') {
          loadAiSecurityContent(targetArea);
        } else {
          console.error('loadAiSecurityContent is not defined. Check if aiSecurity.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Искусственный интеллект".</p>`;
        }
      } else if (section === 'cyber-wars') {
        if (typeof loadCyberWarsContent === 'function') {
          loadCyberWarsContent(targetArea);
        } else {
          console.error('loadCyberWarsContent is not defined. Check if cyberWars.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Кибервойны".</p>`;
        }
      } else if (section === 'settings') {
        if (typeof loadSettingsContent === 'function') {
          loadSettingsContent(targetArea, setActiveSidebarButton, updateTabHeader, window.loadPage);
        } else {
          console.error('loadSettingsContent is not defined. Check if settings.js is loaded correctly.');
          targetArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Настройки".</p>`;
        }
      } else {
        const tabHeader = document.getElementById('tab-header');
        if (tabHeader) {
          targetArea.innerHTML = `<h1>${tabHeader.textContent}</h1>`;
        } else {
          console.error('Element with id "tab-header" not found.');
          targetArea.innerHTML = `<h1>Главная</h1>`;
        }
      }
    } catch (error) {
      if (!error.message.includes('Scheme frame not found')) {
        console.error(`Error loading section ${section}:`, error);
      }
    }
  };

  document.querySelectorAll('.sidebar-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const section = btn.getAttribute('data-section');
      searchInput.value = '';
      clearSearchBtn.style.display = 'none';
      contentArea.innerHTML = '';
      setActiveSidebarButton(section);
      updateTabHeader(btn.textContent.trim());
      window.loadPage(section);
    });
  });

  searchInput.addEventListener('input', () => {
    const query = searchInput.value.trim();
    clearSearchBtn.style.display = query ? 'block' : 'none';
    performSearch(query, contentArea, setActiveSidebarButton, updateTabHeader, window.loadPage, searchInput, clearSearchBtn);
  });

  searchInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      const query = searchInput.value.trim();
      clearSearchBtn.style.display = query ? 'block' : 'none';
      performSearch(query, contentArea, setActiveSidebarButton, updateTabHeader, window.loadPage, searchInput, clearSearchBtn);
    }
  });

  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    clearSearchBtn.style.display = 'none';
    setActiveSidebarButton('home');
    updateTabHeader('Главная');
    window.loadPage('home');
  });

  setActiveSidebarButton('home');
  updateTabHeader('Главная');
  window.loadPage('home');
});
