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
  if (!element) {
    console.warn('highlightElement: Element is null or undefined');
    return;
  }
  console.log('Highlighting element with text:', element.textContent.trim());
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

function findTextWithRetry(targetText, maxAttempts = 5, interval = 300) {
  return new Promise((resolve) => {
    let attempts = 0;
    const normalizedTargetText = targetText.replace(/\s+/g, ' ').trim();

    const tryFindText = () => {
      console.log(`Attempt ${attempts + 1}: Searching for text: "${normalizedTargetText}"`);
      const elements = document.querySelectorAll('#content-area h2, #content-area h3, #content-area li, #content-area p, #content-area td, #content-area .accordion-header');
      let targetElement = null;

      elements.forEach(el => {
        const normalizedElementText = el.textContent.replace(/\s+/g, ' ').trim();
        if (normalizedElementText === normalizedTargetText) {
          targetElement = el;
        }
      });

      if (targetElement) {
        console.log(`Text found after ${attempts + 1} attempts`);
        resolve(targetElement);
      } else {
        attempts++;
        if (attempts < maxAttempts) {
          console.warn(`Text "${normalizedTargetText}" not found, retrying... Available texts:`, 
            Array.from(elements).map(el => el.textContent.replace(/\s+/g, ' ').trim()));
          setTimeout(tryFindText, interval);
        } else {
          console.warn(`Text "${normalizedTargetText}" not found after ${maxAttempts} attempts. Available texts:`, 
            Array.from(elements).map(el => el.textContent.replace(/\s+/g, ' ').trim()));
          resolve(null);
        }
      }
    };

    tryFindText();
  });
}

function searchInSubPages(tempDiv, section, query, results, setActiveSidebarButton, updateTabHeader, loadPage, buttonPath = [], visitedButtons = new Set(), visitedButtonIds, maxDepth = 3) {
  if (buttonPath.length >= maxDepth) return;

  const buttons = tempDiv.querySelectorAll('button:not(.back-btn)');
  buttons.forEach(btn => {
    const btnId = btn.id;
    const btnText = btn.textContent.trim();
    if (!btnId || visitedButtons.has(btnId)) return;

    visitedButtons.add(btnId);

    const subTempDiv = document.createElement('div');
    subTempDiv.style.display = 'none';
    document.body.appendChild(subTempDiv);

    try {
      const originalContent = tempDiv.innerHTML;
      btn.click();
      subTempDiv.innerHTML = tempDiv.innerHTML;
      tempDiv.innerHTML = originalContent;

      if (btnText.toLowerCase().includes(query) && !visitedButtonIds.has(btnId)) {
        visitedButtonIds.add(btnId);
        results.push({
          type: 'button',
          text: `Найдено окно "${btnText}"`,
          section: section,
          buttonPath: [...buttonPath, { btnId, btnText }],
          targetText: btnText
        });
      }

      const elementsToSearch = subTempDiv.querySelectorAll('h2, h3, li, p, td, .accordion-header');
      elementsToSearch.forEach(element => {
        const elementText = element.textContent.trim().toLowerCase();
        if (elementText.includes(query)) {
          const isAccordionHeader = element.classList.contains('accordion-header');
          results.push({
            type: 'text',
            text: element.textContent.trim().substring(0, 100) + (element.textContent.length > 100 ? '...' : ''),
            section: section,
            buttonPath: [...buttonPath, { btnId, btnText }],
            targetText: element.textContent.trim(),
            isAccordionHeader: isAccordionHeader
          });
        }
      });

      const accordionContents = subTempDiv.querySelectorAll('.accordion-content');
      accordionContents.forEach(content => {
        const originalDisplay = content.style.display;
        content.style.display = 'block';

        content.querySelectorAll('h3, p, li').forEach(element => {
          const elementText = element.textContent.trim().toLowerCase();
          if (elementText.includes(query)) {
            const accordionHeader = content.previousElementSibling?.textContent.trim() || 'Неизвестный аккордеон';
            results.push({
              type: 'text',
              text: element.textContent.trim().substring(0, 100) + (element.textContent.length > 100 ? '...' : ''),
              section: section,
              buttonPath: [...buttonPath, { btnId, btnText }],
              targetText: element.textContent.trim(),
              accordionHeaderText: accordionHeader
            });
          }
        });

        content.style.display = originalDisplay;
      });

      searchInSubPages(subTempDiv, section, query, results, setActiveSidebarButton, updateTabHeader, loadPage, [...buttonPath, { btnId, btnText }], visitedButtons, visitedButtonIds, maxDepth);

    } catch (error) {
      console.error(`Error loading sub-page for button ${btnId} in section ${section}:`, error);
    } finally {
      subTempDiv.remove();
    }
  });
}

function performSearch(query, contentArea, setActiveSidebarButton, updateTabHeader, loadPage, searchInput, clearSearchBtn) {
  query = query.trim().toLowerCase();
  const buttonResults = [];
  const textResults = [];
  const visitedButtonIds = new Set();

  if (!query) {
    contentArea.innerHTML = '';
    setActiveSidebarButton('home');
    updateTabHeader('Главная');
    loadPage('home');
    return;
  }

  const sections = [
    'osi', 'vulnerabilities', 'malware-analysis', 'pentesting',
    'social-engineering', 'forensics', 'network-building', 'cryptography',
    'ep-pki', 'ib-tools', 'structure-security', 'legal-regulations',
    'lna-lnd', 'threat-model', 'training', 'russian-szi', 'osint',
    'certificates', 'teams-threat-intel', 'ai-security', 'cyber-wars'
  ];

  sections.forEach(section => {
    const tempDiv = document.createElement('div');
    tempDiv.style.display = 'none';
    document.body.appendChild(tempDiv);

    try {
      loadPage(section, tempDiv);

      tempDiv.querySelectorAll('button:not(.back-btn)').forEach(btn => {
        const btnText = btn.textContent.trim().toLowerCase();
        const btnId = btn.id;
        if (btnText.includes(query) && btnId && !visitedButtonIds.has(btnId)) {
          visitedButtonIds.add(btnId);
          buttonResults.push({
            type: 'button',
            text: `Найдено окно "${btn.textContent.trim()}"`,
            section: section,
            buttonPath: [{ btnId, btnText: btn.textContent.trim() }],
            targetText: btn.textContent.trim()
          });
        }
      });

      const elementsToSearch = tempDiv.querySelectorAll('h2, h3, li, p, td, .accordion-header');
      elementsToSearch.forEach(element => {
        const elementText = element.textContent.trim().toLowerCase();
        if (elementText.includes(query)) {
          const isAccordionHeader = element.classList.contains('accordion-header');
          textResults.push({
            type: 'text',
            text: element.textContent.trim().substring(0, 100) + (element.textContent.length > 100 ? '...' : ''),
            section: section,
            buttonPath: [],
            targetText: element.textContent.trim(),
            isAccordionHeader: isAccordionHeader
          });
        }
      });

      const accordionContents = tempDiv.querySelectorAll('.accordion-content');
      accordionContents.forEach(content => {
        const originalDisplay = content.style.display;
        content.style.display = 'block';

        content.querySelectorAll('h3, p, li').forEach(element => {
          const elementText = element.textContent.trim().toLowerCase();
          if (elementText.includes(query)) {
            const accordionHeader = content.previousElementSibling?.textContent.trim() || 'Неизвестный аккордеон';
            textResults.push({
              type: 'text',
              text: element.textContent.trim().substring(0, 100) + (element.textContent.length > 100 ? '...' : ''),
              section: section,
              buttonPath: [],
              targetText: element.textContent.trim(),
              accordionHeaderText: accordionHeader
            });
          }
        });

        content.style.display = originalDisplay;
      });

      searchInSubPages(tempDiv, section, query, textResults, setActiveSidebarButton, updateTabHeader, loadPage, [], new Set(), visitedButtonIds);

    } catch (error) {
      if (!error.message.includes('Scheme frame not found')) {
        console.error(`Error loading section ${section}:`, error);
      }
    } finally {
      tempDiv.remove();
    }
  });

  contentArea.innerHTML = '';
  if (buttonResults.length > 0 || textResults.length > 0) {
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'search-results';
    contentArea.appendChild(resultsContainer);

    buttonResults.forEach(result => {
      const div = document.createElement('div');
      div.className = 'search-result-btn';
      div.textContent = result.text;
      div.addEventListener('click', async () => {
        searchInput.value = '';
        clearSearchBtn.style.display = 'none';
        contentArea.innerHTML = '';

        const sectionTitle = document.querySelector(`.sidebar-btn[data-section="${result.section}"]`)?.textContent.trim() || result.section;
        setActiveSidebarButton(result.section);
        updateTabHeader(sectionTitle);
        loadPage(result.section);

        await new Promise(resolve => setTimeout(resolve, 500));

        if (result.buttonPath.length > 0) {
          const btn = result.buttonPath[0];
          let attempts = 0;
          const maxAttempts = 10;
          let targetBtn = null;

          while (attempts < maxAttempts) {
            targetBtn = document.getElementById(btn.btnId);
            if (targetBtn) {
              console.log(`Clicking button in path: ${btn.btnId} (${btn.btnText})`);
              targetBtn.click();
              break;
            }
            console.warn(`Button ${btn.btnId} not found in DOM, retrying... (${attempts + 1}/${maxAttempts})`);
            const availableButtons = Array.from(document.querySelectorAll('button:not(.back-btn)')).map(b => b.id);
            console.log('Available buttons in DOM:', availableButtons);
            await new Promise(resolve => setTimeout(resolve, 150));
            attempts++;
          }

          if (!targetBtn) {
            console.error(`Failed to find button ${btn.btnId} after ${maxAttempts} attempts`);
          }

          await new Promise(resolve => setTimeout(resolve, 150));
        }

      });
      resultsContainer.appendChild(div);
    });

    textResults.forEach(result => {
      const div = document.createElement('div');
      div.className = 'search-result-text';
      div.textContent = result.text;
      div.addEventListener('click', async () => {
        searchInput.value = '';
        clearSearchBtn.style.display = 'none';
        contentArea.innerHTML = '';

        const sectionTitle = document.querySelector(`.sidebar-btn[data-section="${result.section}"]`)?.textContent.trim() || result.section;
        setActiveSidebarButton(result.section);
        updateTabHeader(sectionTitle);
        loadPage(result.section);

        await new Promise(resolve => setTimeout(resolve, 500));

        let textFound = false;
        if (result.buttonPath.length > 0) {
          for (const btn of result.buttonPath) {
            let attempts = 0;
            const maxAttempts = 10;
            let targetBtn = null;

            while (attempts < maxAttempts) {
              targetBtn = document.getElementById(btn.btnId);
              if (targetBtn) {
                console.log(`Clicking button in path: ${btn.btnId} (${btn.btnText})`);
                targetBtn.click();
                break;
              }
              console.warn(`Button ${btn.btnId} not found in DOM, retrying... (${attempts + 1}/${maxAttempts})`);
              const availableButtons = Array.from(document.querySelectorAll('button:not(.back-btn)')).map(b => b.id);
              console.log('Available buttons in DOM:', availableButtons);
              await new Promise(resolve => setTimeout(resolve, 150));
              attempts++;
            }

            if (!targetBtn) {
              console.error(`Failed to find button ${btn.btnId} after ${maxAttempts} attempts`);
            }

            await new Promise(resolve => setTimeout(resolve, 150));

            const targetElement = await findTextWithRetry(result.targetText, 3, 150);
            if (targetElement) {
              textFound = true;
              if (result.accordionHeaderText) {
                const accordionHeaders = document.querySelectorAll('.accordion-header');
                for (const header of accordionHeaders) {
                  if (header.textContent.trim() === result.accordionHeaderText) {
                    const content = header.nextElementSibling;
                    if (content && content.classList.contains('accordion-content')) {
                      document.querySelectorAll('.accordion-content').forEach(item => {
                        item.style.display = 'none';
                      });
                      content.style.display = 'block';
                      break;
                    }
                  }
                }
              }
              if (result.isAccordionHeader) {
                const accordionHeaders = document.querySelectorAll('.accordion-header');
                for (const header of accordionHeaders) {
                  if (header.textContent.trim() === result.targetText) {
                    const content = header.nextElementSibling;
                    if (content && content.classList.contains('accordion-content')) {
                      document.querySelectorAll('.accordion-content').forEach(item => {
                        item.style.display = 'none';
                      });
                      content.style.display = 'block';
                      highlightElement(header);
                      break;
                    }
                  }
                }
              } else {
                highlightElement(targetElement);
              }
              break;
            }
          }
        }

        if (!textFound) {
          const targetElement = await findTextWithRetry(result.targetText);
          if (targetElement) {
            if (result.accordionHeaderText) {
              const accordionHeaders = document.querySelectorAll('.accordion-header');
              for (const header of accordionHeaders) {
                if (header.textContent.trim() === result.accordionHeaderText) {
                  const content = header.nextElementSibling;
                  if (content && content.classList.contains('accordion-content')) {
                    document.querySelectorAll('.accordion-content').forEach(item => {
                      item.style.display = 'none';
                    });
                    content.style.display = 'block';
                    break;
                  }
                }
              }
            }
            if (result.isAccordionHeader) {
              const accordionHeaders = document.querySelectorAll('.accordion-header');
              for (const header of accordionHeaders) {
                if (header.textContent.trim() === result.targetText) {
                  const content = header.nextElementSibling;
                  if (content && content.classList.contains('accordion-content')) {
                    document.querySelectorAll('.accordion-content').forEach(item => {
                      item.style.display = 'none';
                    });
                    content.style.display = 'block';
                    highlightElement(header);
                    break;
                  }
                }
              }
            } else {
              highlightElement(targetElement);
            }
          } else {
            console.error(`Failed to find text "${result.targetText}" after all attempts`);
          }
        }
      });
      resultsContainer.appendChild(div);
    });
  } else {
    contentArea.innerHTML = `<p>Ничего не найдено по запросу "${query}"</p>`;
  }
}