document.addEventListener('DOMContentLoaded', () => {
  const windowContainer = document.getElementById('window-container');
  const contentArea = document.getElementById('content-area');

  if (!windowContainer) {
    console.error('Element with id "window-container" not found. Check your index.html structure.');
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
    windowContainer.classList.add('maximize-animation');
    setTimeout(() => {
      window.electronAPI.maximizeWindow();
      windowContainer.classList.remove('maximize-animation');
    }, 350);
  });

  window.electronAPI.onWindowMaximized(() => {
    windowContainer.classList.add('maximized');
  });

  window.electronAPI.onWindowUnmaximized(() => {
    windowContainer.classList.remove('maximized');
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
    } else if (section === 'malware-analysis') {
      if (typeof loadMalwareAnalysisContent === 'function') {
        loadMalwareAnalysisContent(contentArea);
      } else {
        console.error('loadMalwareAnalysisContent is not defined. Check if malwareAnalysis.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Анализ ВПО".</p>`;
      }
    } else if (section === 'pentesting') {
      if (typeof loadPentestingContent === 'function') {
        loadPentestingContent(contentArea);
      } else {
        console.error('loadPentestingContent is not defined. Check if pentesting.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Пентестинг".</p>`;
      }
    } else if (section === 'social-engineering') {
      if (typeof loadSocialEngineeringContent === 'function') {
        loadSocialEngineeringContent(contentArea);
      } else {
        console.error('loadSocialEngineeringContent is not defined. Check if socialEngineering.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Социальная инженерия".</p>`;
      }
    } else if (section === 'forensics') {
      if (typeof loadForensicsContent === 'function') {
        loadForensicsContent(contentArea);
      } else {
        console.error('loadForensicsContent is not defined. Check if forensics.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Форензика".</p>`;
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
    } else if (section === 'lna-lnd') {
      if (typeof loadLnaLndContent === 'function') {
        loadLnaLndContent(contentArea);
      } else {
        console.error('loadLnaLndContent is not defined. Check if lnaLnd.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "ЛНА и ЛНД".</p>`;
      }
    } else if (section === 'threat-model') {
      if (typeof loadThreatModelContent === 'function') {
        loadThreatModelContent(contentArea);
      } else {
        console.error('loadThreatModelContent is not defined. Check if threatModel.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Модель угроз".</p>`;
      }
    } else if (section === 'training') {
      if (typeof loadTrainingContent === 'function') {
        loadTrainingContent(contentArea);
      } else {
        console.error('loadTrainingContent is not defined. Check if training.js is loaded correctly.');
        contentArea.innerHTML = `<h1>Ошибка</h1><p>Не удалось загрузить содержимое вкладки "Обучение и тестирование".</p>`;
      }
    } else if (section === 'home') {
      contentArea.innerHTML = `
        <h1>Главная</h1>
        <div class="description">
          <p><strong>Berkut Cyber Base</strong> — это локальная библиотека знаний, разработанная специально для специалистов по информационной безопасности и защите информации. Программа представляет собой удобный инструмент для изучения, анализа и применения ключевых концепций в области кибербезопасности.</p>
          <p>Приложение объединяет в себе обширный набор тем, включая модель OSI, уязвимости, построение сетей, криптографию, электронные подписи и инфраструктуру открытых ключей (PKI), инструменты информационной безопасности, защиту структур, правовые нормы, локальные нормативные акты, моделирование угроз, а также модули обучения и тестирования.</p>
          <p><strong>Для чего нужна программа?</strong></p>
          <ul>
            <li><strong>Обучение и повышение квалификации:</strong> предоставляет структурированные материалы для освоения основ и углубленного изучения тем ИБ.</li>
            <li><strong>Практическое применение:</strong> помогает специалистам быстро находить информацию и применять её в реальных задачах.</li>
            <li><strong>Локальность и безопасность:</strong> работает оффлайн, обеспечивая конфиденциальность данных и независимость от интернета.</li>
            <li><strong>Удобство:</strong> интуитивно понятный интерфейс и быстрый доступ к нужным разделам.</li>
          </ul>
          <p>Berkut Cyber Base — это ваш надёжный помощник в мире информационной безопасности, созданный для поддержки специалистов в их профессиональной деятельности.</p>
        </div>
      `;
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
