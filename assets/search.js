function extractTextFromElement(element, maxLength = 10000) {
  let text = '';
  if (element.nodeType === Node.TEXT_NODE) {
    text = element.textContent.trim();
  } else if (element.nodeType === Node.ELEMENT_NODE) {
    if (element.classList.contains('back-btn') || element.classList.contains('sidebar-btn')) {
      return '';
    }
    if (element.tagName.toLowerCase() === 'button') {
      text = element.textContent.trim() + ' ';
    }
    for (const child of element.childNodes) {
      if (text.length > maxLength) break;
      text += extractTextFromElement(child, maxLength) + ' ';
    }
  }
  return text.trim().substring(0, maxLength);
}

function highlightElement(element) {
  if (!element) return;
  const originalStyle = element.style.cssText;
  element.style.border = '3px solid #42a5f5';
  element.style.borderRadius = '8px';
  element.style.transition = 'border-color 0.5s ease-in-out';
  element.scrollIntoView({ behavior: 'smooth', block: 'center' });

  let blinkCount = 0;
  const blinkInterval = setInterval(() => {
    element.style.borderColor = element.style.borderColor === 'transparent' ? '#42a5f5' : 'transparent';
    blinkCount++;
    if (blinkCount >= 8) {
      clearInterval(blinkInterval);
      element.style.cssText = originalStyle;
    }
  }, 250);
}

function searchInSubPages(tempDiv, section, query, textResults, buttonResults, setActiveSidebarButton, updateTabHeader, loadPage, buttonPath = [], visitedButtons = new Set(), maxDepth = 3) {
  if (buttonPath.length >= maxDepth) return;

  const buttons = tempDiv.querySelectorAll('button:not(.back-btn)');
  buttons.forEach(btn => {
    const btnId = btn.id;
    const btnText = btn.textContent.trim();
    if (!btnId || visitedButtons.has(btnId)) return;

    visitedButtons.add(btnId);

    if (btnText.toLowerCase().includes(query)) {
      const sectionTitle = document.querySelector(`.sidebar-btn[data-section="${section}"]`)?.textContent.trim() || section;
      const pathText = buttonPath.map(p => `"${p.btnText}"`).join(', в окне ');
      const displayText = buttonPath.length > 0
        ? `Найдена кнопка на вкладке "${sectionTitle}", в окне ${pathText}, кнопка "${btnText}"`
        : `Найдена кнопка на вкладке "${sectionTitle}", кнопка "${btnText}"`;
      buttonResults.push({
        type: 'button',
        text: displayText,
        section: section,
        buttonPath: [...buttonPath, { btnId, btnText }],
        action: () => {
          setActiveSidebarButton(section);
          updateTabHeader(sectionTitle);
          loadPage(section);
          let delay = 100;
          buttonPath.forEach((pathBtn, idx) => {
            setTimeout(() => {
              const targetBtn = document.getElementById(pathBtn.btnId);
              if (targetBtn) targetBtn.click();
            }, delay);
            delay += 100;
          });
          setTimeout(() => {
            const targetBtn = document.getElementById(btnId);
            if (targetBtn) {
              targetBtn.click();
              highlightElement(targetBtn);
            }
          }, delay);
          const searchInput = document.getElementById('search-input');
          const clearSearchBtn = document.getElementById('clear-search');
          searchInput.value = '';
          clearSearchBtn.style.display = 'none';
          tempDiv.innerHTML = '';
          loadPage(section);
        }
      });
    }

    const subTempDiv = document.createElement('div');
    subTempDiv.style.display = 'none';
    document.body.appendChild(subTempDiv);

    try {
      const originalContent = tempDiv.innerHTML;
      btn.click();
      subTempDiv.innerHTML = tempDiv.innerHTML;
      tempDiv.innerHTML = originalContent;

      subTempDiv.querySelectorAll('h2, li, p, td').forEach(element => {
        const elementText = element.textContent.trim().toLowerCase();
        if (elementText.includes(query)) {
          const sectionTitle = document.querySelector(`.sidebar-btn[data-section="${section}"]`)?.textContent.trim() || section;
          const pathText = buttonPath.map(p => `"${p.btnText}"`).join(', в окне ');
          const displayText = buttonPath.length > 0
            ? `Найдено на вкладке "${sectionTitle}", в окне ${pathText}, в окне "${btnText}" (подраздел: "${element.textContent.trim().substring(0, 50)}${element.textContent.length > 50 ? '...' : ''}")`
            : `Найдено на вкладке "${sectionTitle}", в окне "${btnText}" (подраздел: "${element.textContent.trim().substring(0, 50)}${element.textContent.length > 50 ? '...' : ''}")`;
          textResults.push({
            type: 'text',
            text: displayText,
            section: section,
            buttonPath: [...buttonPath, { btnId, btnText }],
            targetText: element.textContent.trim()
          });
        }
      });

      searchInSubPages(subTempDiv, section, query, textResults, buttonResults, setActiveSidebarButton, updateTabHeader, loadPage, [...buttonPath, { btnId, btnText }], visitedButtons, maxDepth);

    } catch (error) {
      console.error(`Error loading sub-page for button ${btnId} in section ${section}:`, error);
    } finally {
      subTempDiv.remove();
    }
  });
}

function performSearch(query, contentArea, setActiveSidebarButton, updateTabHeader, loadPage) {
  query = query.trim().toLowerCase();
  const buttonResults = [];
  const textResults = [];

  document.querySelectorAll('button:not(.sidebar-btn):not(.back-btn)').forEach(btn => {
    const btnText = btn.textContent.trim().toLowerCase();
    const section = btn.getAttribute('data-section') || btn.closest('[data-section]')?.getAttribute('data-section');
    const btnId = btn.id;

    if (btnText.includes(query)) {
      let action;
      if (section) {
        action = () => {
          setActiveSidebarButton(section);
          updateTabHeader(document.querySelector(`.sidebar-btn[data-section="${section}"]`)?.textContent.trim() || section);
          loadPage(section);
          setTimeout(() => {
            const targetBtn = document.getElementById(btnId);
            if (targetBtn) {
              targetBtn.click();
              highlightElement(targetBtn);
            }
          }, 100);
          const searchInput = document.getElementById('search-input');
          const clearSearchBtn = document.getElementById('clear-search');
          searchInput.value = '';
          clearSearchBtn.style.display = 'none';
          contentArea.innerHTML = '';
          loadPage(section);
        };

        buttonResults.push({
          type: 'button',
          text: btn.textContent.trim(),
          section: section,
          buttonPath: [],
          action: action
        });
      }
    }
  });

  const sections = [
    'osi', 'vulnerabilities', 'malware-analysis', 'pentesting',
    'social-engineering', 'forensics', 'network-building', 'cryptography',
    'ep-pki', 'ib-tools', 'structure-security', 'legal-regulations',
    'lna-lnd', 'threat-model', 'training', 'russian-szi', 'osint'
  ];

  sections.forEach(section => {
    const tempDiv = document.createElement('div');
    tempDiv.style.display = 'none';
    document.body.appendChild(tempDiv);

    try {
      loadPage(section, tempDiv);

      tempDiv.querySelectorAll('button:not(.back-btn)').forEach(btn => {
        const btnText = btn.textContent.trim().toLowerCase();
        if (btnText.includes(query)) {
          const btnId = btn.id;
          if (btnId && section) {
            const sectionTitle = document.querySelector(`.sidebar-btn[data-section="${section}"]`)?.textContent.trim() || section;
            buttonResults.push({
              type: 'button',
              text: `Найдена кнопка на вкладке "${sectionTitle}", кнопка "${btn.textContent.trim()}"`,
              section: section,
              buttonPath: [],
              action: () => {
                setActiveSidebarButton(section);
                updateTabHeader(sectionTitle);
                loadPage(section);
                setTimeout(() => {
                  const targetBtn = document.getElementById(btnId);
                  if (targetBtn) {
                    targetBtn.click();
                    highlightElement(targetBtn);
                  }
                }, 100);
                const searchInput = document.getElementById('search-input');
                const clearSearchBtn = document.getElementById('clear-search');
                searchInput.value = '';
                clearSearchBtn.style.display = 'none';
                contentArea.innerHTML = '';
                loadPage(section);
              }
            });
          }
        }
      });

      tempDiv.querySelectorAll('h2, li, p, td').forEach(element => {
        const elementText = element.textContent.trim().toLowerCase();
        if (elementText.includes(query)) {
          const sectionTitle = document.querySelector(`.sidebar-btn[data-section="${section}"]`)?.textContent.trim() || section;
          textResults.push({
            type: 'text',
            text: `Найдено на вкладке "${sectionTitle}" (подраздел: "${element.textContent.trim().substring(0, 50)}${element.textContent.length > 50 ? '...' : ''}")`,
            section: section,
            buttonPath: [],
            targetText: element.textContent.trim()
          });
        }
      });

      searchInSubPages(tempDiv, section, query, textResults, buttonResults, setActiveSidebarButton, updateTabHeader, loadPage);

    } catch (error) {
      if (!error.message.includes('Scheme frame not found')) {
        console.error(`Error loading section ${section}:`, error);
      }
    } finally {
      tempDiv.remove();
    }
  });

  const results = [...buttonResults, ...textResults];

  if (!contentArea) {
    console.error('contentArea is not defined or not found in DOM');
    return;
  }

  contentArea.innerHTML = '';

  if (query && results.length > 0) {
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'search-results';
    contentArea.appendChild(resultsContainer);

    results.forEach((result, index) => {
      const div = document.createElement('div');
      div.className = 'search-result-text';
      div.textContent = result.text;
      div.addEventListener('click', () => {
        setActiveSidebarButton(result.section);
        updateTabHeader(document.querySelector(`.sidebar-btn[data-section="${result.section}"]`)?.textContent.trim() || result.section);
        loadPage(result.section);
        let delay = 100;
        result.buttonPath.forEach((btn, idx) => {
          setTimeout(() => {
            const targetBtn = document.getElementById(btn.btnId);
            if (targetBtn) {
              targetBtn.click();
            }
            if (idx === result.buttonPath.length - 1) {
              setTimeout(() => {
                if (result.type === 'button') {
                  const targetBtn = document.getElementById(result.buttonPath[result.buttonPath.length - 1]?.btnId);
                  if (targetBtn) {
                    highlightElement(targetBtn);
                  }
                } else {
                  const elements = document.querySelectorAll('#content-area h2, #content-area li, #content-area p, #content-area td');
                  let targetElement = null;
                  elements.forEach(el => {
                    if (el.textContent.trim() === result.targetText) {
                      targetElement = el;
                    }
                  });
                  if (targetElement) {
                    highlightElement(targetElement);
                  }
                }
              }, 100);
            }
          }, delay);
          delay += 100;
        });
        const searchInput = document.getElementById('search-input');
        const clearSearchBtn = document.getElementById('clear-search');
        searchInput.value = '';
        clearSearchBtn.style.display = 'none';
        contentArea.innerHTML = '';
        loadPage(result.section);
      });
      resultsContainer.appendChild(div);
    });
  } else if (query) {
    contentArea.innerHTML = `<p>Ничего не найдено по запросу "${query}"</p>`;
  } else {
    setActiveSidebarButton('home');
    updateTabHeader('Главная');
    loadPage('home');
  }
}