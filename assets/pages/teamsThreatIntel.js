function loadTeamsThreatIntelContent(contentArea) {
    const initialContent = `
      <div class="teams-threat-container">
        <h1>Команды ИБ и Threat Intelligence</h1>
        <div class="teams-threat-description">
          <p>В области информационной безопасности ключевую роль играют специализированные команды и процессы, направленные на защиту, тестирование и анализ киберугроз. Этот раздел охватывает основные подходы: <strong>Blue Team</strong> (защита), <strong>Red Team</strong> (атака), <strong>Purple Team</strong> (сотрудничество), а также <strong>Threat Hunting</strong> (поиск угроз) и <strong>Threat Intelligence</strong> (анализ угроз).</p>
        </div>
  
        <!-- Теория про команды -->
        <div class="teams-description">
          <h2>Команды информационной безопасности</h2>
          
          <h3>Blue Team (Синяя команда)</h3>
          <p><strong>Blue Team</strong> — это группа специалистов, отвечающая за защиту информационной инфраструктуры организации от кибератак. Их работа направлена на обеспечение устойчивости систем, предотвращение инцидентов и минимизацию ущерба от угроз.</p>
          <ul>
            <li><strong>Роли и состав:</strong> Включает аналитиков SOC (Security Operations Center), администраторов безопасности, инженеров по мониторингу и реагированию на инциденты. Часто работают в тесной связке с IT-отделом.</li>
            <li><strong>Основные задачи:</strong>
              <ul>
                <li>Настройка и поддержка защитных систем (брандмауэры, WAF, антивирусы).</li>
                <li>Мониторинг сетевого трафика и системных событий в реальном времени.</li>
                <li>Обнаружение и классификация инцидентов (DDoS, утечки данных, malware).</li>
                <li>Реагирование на инциденты: изоляция угроз, восстановление систем.</li>
                <li>Разработка процедур реагирования и планов восстановления (DRP, BCP).</li>
              </ul>
            </li>
            <li><strong>Инструменты:</strong> SIEM-системы (Splunk, QRadar), IDS/IPS (Snort, Suricata), системы управления логами (ELK Stack), антивирусы (Kaspersky, CrowdStrike).</li>
            <li><strong>Пример работы:</strong> Анализ всплеска трафика через SIEM, выявление DDoS-атаки, блокировка IP-адресов через брандмауэр, восстановление сервисов из бэкапов.</li>
          </ul>
  
          <h3>Red Team (Красная команда)</h3>
          <p><strong>Red Team</strong> — это специалисты, которые имитируют действия злоумышленников, чтобы проверить защищённость систем и выявить уязвимости. Их подход основан на моделировании реальных атак с использованием техник хакеров.</p>
          <ul>
            <li><strong>Роли и состав:</strong> Пентестеры, эксперты по эксплуатации уязвимостей, специалисты по социальной инженерии.</li>
            <li><strong>Основные задачи:</strong>
              <ul>
                <li>Сбор информации о целях (OSINT, активное сканирование).</li>
                <li>Проведение атак: эксплуатация уязвимостей, перехват трафика, фишинг.</li>
                <li>Эскалация привилегий для получения полного контроля над системой.</li>
                <li>Пост-эксплуатация: закрепление в системе, сбор конфиденциальных данных.</li>
                <li>Документирование результатов для передачи Blue Team.</li>
              </ul>
            </li>
            <li><strong>Инструменты:</strong> Metasploit, Cobalt Strike, Burp Suite, Nmap, Aircrack-ng, Mimikatz.</li>
            <li><strong>Пример работы:</strong> Использование SQL-инъекции для доступа к базе данных, эскалация через уязвимость ядра (Dirty COW), установка бэкдора для дальнейшего доступа.</li>
          </ul>
  
          <h3>Purple Team (Фиолетовая команда)</h3>
          <p><strong>Purple Team</strong> — это подход, объединяющий Blue Team и Red Team для совместной работы. Он направлен на улучшение защиты через обмен опытом и оптимизацию процессов.</p>
          <ul>
            <li><strong>Роли и состав:</strong> Координаторы между Blue и Red Team, аналитики для оценки эффективности защиты и атак.</li>
            <li><strong>Основные задачи:</strong>
              <ul>
                <li>Планирование совместных упражнений (Red Team атакует, Blue Team защищает).</li>
                <li>Анализ результатов атак и реакции защиты.</li>
                <li>Улучшение процедур мониторинга и реагирования на основе выявленных слабостей.</li>
                <li>Обучение обеих команд новым техникам и методам.</li>
                <li>Создание общей базы знаний (например, по MITRE ATT&CK).</li>
              </ul>
            </li>
            <li><strong>Инструменты:</strong> MITRE ATT&CK Navigator, совместные платформы для анализа, системы управления инцидентами.</li>
            <li><strong>Пример работы:</strong> Red Team проводит атаку через XSS, Blue Team фиксирует попытку в SIEM, Purple Team анализирует, почему WAF не сработал, и обновляет правила фильтрации.</li>
          </ul>
        </div>
  
        <!-- Схемы команд -->
        <div class="teams-schemes">
          <h2>Схемы процессов команд</h2>
          <p>Ниже представлены детализированные схемы процессов для каждой команды, показывающие этапы их работы и взаимодействия:</p>
          <div class="scheme-frame" style="border: 2px solid #000; border-radius: 8px; background-color: #05060a; padding: 20px; display: flex; justify-content: flex-start; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
            <!-- Blue Team -->
            <div class="blue-team-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Blue Team</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #1976d2; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Настройка защиты
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Установка IDS/IPS, WAF, правил фильтрации.</p>
                </div>
                <div style="background-color: #2196f3; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сбор логов в SIEM, анализ трафика в реальном времени.</p>
                </div>
                <div style="background-color: #42a5f5; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обнаружение
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выявление аномалий, сигнатур атак через IDS.</p>
                </div>
                <div style="border: 2px solid #64b5f6; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #64b5f6; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Реагирование
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Блокировка IP, изоляция заражённых узлов.</p>
                  </div>
                  <div style="background-color: #90caf9; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Анализ инцидента
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Определение источника, сбор доказательств.</p>
                  </div>
                </div>
                <div style="background-color: #bbdefb; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                  Восстановление
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Установка патчей, восстановление из бэкапов.</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Система защищена, уроки извлечены.</p>
                </div>
              </div>
            </div>
  
            <!-- Red Team -->
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
                <div style="background-color: #ef5350; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Поиск уязвимостей
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Burp Suite, Nessus, ручной анализ.</p>
                </div>
                <div style="border: 2px solid #e57373; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #e57373; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Эксплуатация
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Запуск эксплойтов (Metasploit), SQLi.</p>
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
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Отчёт с уязвимостями для Blue Team.</p>
                </div>
              </div>
            </div>
  
            <!-- Purple Team -->
            <div class="purple-team-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Purple Team</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #8e24aa; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Планирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Согласование сценариев атак и защиты.</p>
                </div>
                <div style="background-color: #ab47bc; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Тестирование Red Team
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Запуск атак (XSS, фишинг).</p>
                </div>
                <div style="background-color: #ba68c8; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Реакция Blue Team
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обнаружение и блокировка в SIEM.</p>
                </div>
                <div style="border: 2px solid #ce93d8; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #ce93d8; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Анализ результатов
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сравнение действий команд, поиск пробелов.</p>
                  </div>
                  <div style="background-color: #e1bee7; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word; color: #000;">
                    Оптимизация
                    <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Обновление правил WAF, обучение.</p>
                  </div>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Улучшенная защита и готовность.</p>
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
          <p>Схемы показывают, как Blue Team защищает систему, Red Team атакует её, а Purple Team координирует усилия для повышения безопасности.</p>
        </div>
  
        <!-- Теория про Threat Hunting и Threat Intelligence -->
        <div class="threat-description">
          <h2>Процессы анализа угроз</h2>
          
          <h3>Threat Hunting (Охота за угрозами)</h3>
          <p><strong>Threat Hunting</strong> — это проактивный подход к поиску скрытых угроз, которые не были обнаружены автоматизированными системами защиты. Он основан на предположениях и анализе данных для выявления сложных атак, таких как APT (Advanced Persistent Threats).</p>
          <ul>
            <li><strong>Цели:</strong> Обнаружение следов активности злоумышленников, предотвращение ущерба до активации угрозы.</li>
            <li><strong>Основные задачи:</strong>
              <ul>
                <li>Формирование гипотез на основе известных угроз или аномалий.</li>
                <li>Сбор данных из логов, трафика, системных событий.</li>
                <li>Анализ с использованием сигнатур (YARA) и поведенческого анализа.</li>
                <li>Подтверждение наличия угрозы и определение её масштаба.</li>
                <li>Передача данных Blue Team для реагирования.</li>
              </ul>
            </li>
            <li><strong>Инструменты:</strong> ELK Stack, Zeek, YARA, Sysmon, Volatility.</li>
            <li><strong>Пример работы:</strong> Обнаружение подозрительного процесса через Sysmon, анализ сетевого трафика в Zeek, подтверждение командного сервера APT.</li>
          </ul>
  
          <h3>Threat Intelligence (Анализ угроз)</h3>
          <p><strong>Threat Intelligence</strong> — это процесс сбора, анализа и распространения информации об актуальных киберугрозах для повышения осведомлённости и подготовки к атакам.</p>
          <ul>
            <li><strong>Цели:</strong> Предоставление данных для принятия решений, улучшение защиты, прогнозирование угроз.</li>
            <li><strong>Основные задачи:</strong>
              <ul>
                <li>Сбор данных из открытых источников (OSINT), даркнета, форумов.</li>
                <li>Анализ индикаторов компрометации (IOC: хэши, IP) и тактик (TTPs).</li>
                <li>Обогащение данных контекстом (кто атакует, почему, как).</li>
                <li>Создание отчётов и правил для SIEM/IDS.</li>
                <li>Интеграция данных в защитные системы.</li>
              </ul>
            </li>
            <li><strong>Инструменты:</strong> ThreatConnect, Recorded Future, VirusTotal, MISP.</li>
            <li><strong>Пример работы:</strong> Обнаружение новой кампании в даркнете, анализ IOC (хэш малвари), создание правила для SIEM, предупреждение Blue Team.</li>
          </ul>
        </div>
  
        <!-- Схемы Threat Hunting и Threat Intelligence -->
        <div class="threat-schemes">
          <h2>Схемы процессов анализа угроз</h2>
          <p>Ниже представлены схемы для Threat Hunting и Threat Intelligence с детальным описанием этапов:</p>
          <div class="scheme-frame" style="border: 2px solid #000; border-radius: 8px; background-color: #05060a; padding: 20px; display: flex; justify-content: flex-start; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
            <!-- Threat Hunting -->
            <div class="threat-hunting-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Threat Hunting</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #388e3c; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Формирование гипотезы
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аномалия в логах, данные Threat Intel.</p>
                </div>
                <div style="background-color: #4caf50; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Sysmon, Zeek, дампы памяти.</p>
                </div>
                <div style="background-color: #66bb6a; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Проверка сигнатур (YARA), аномалий.</p>
                </div>
                <div style="border: 2px solid #81c784; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #81c784; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Подтверждение угрозы
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обнаружение C2-сервера, следов APT.</p>
                  </div>
                  <div style="background-color: #a5d6a7; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Документирование
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Создание отчёта для Blue Team.</p>
                  </div>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выявленные скрытые угрозы.</p>
                </div>
              </div>
            </div>
  
            <!-- Threat Intelligence -->
            <div class="threat-intel-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Threat Intelligence</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #ff9800; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">OSINT, даркнет, базы IOC.</p>
                </div>
                <div style="background-color: #ffb300; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Анализ
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изучение хэшей, IP, TTPs.</p>
                </div>
                <div style="background-color: #ffca28; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обогащение
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Добавление контекста (группы, мотивы).</p>
                </div>
                <div style="border: 2px solid #ffcc80; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #ffcc80; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Создание отчётов
                    <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Подробные данные для команд.</p>
                  </div>
                  <div style="background-color: #ffe082; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word; color: #000;">
                    Интеграция
                    <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Правила для SIEM, IDS.</p>
                  </div>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Повышенная осведомлённость.</p>
                </div>
              </div>
            </div>
  
            <svg id="threat-arrows-svg" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;">
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="0" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
                </marker>
              </defs>
              <path id="threat-arrow1" stroke="#666" stroke-width="2" fill="none" marker-end="url(#arrowhead)" />
            </svg>
          </div>
          <p>Схемы показывают, как Threat Hunting ищет скрытые угрозы, а Threat Intelligence собирает и распространяет данные для защиты.</p>
        </div>
      </div>
    `;
    contentArea.innerHTML = initialContent;
  
    function drawTeamArrows() {
      const schemeFrame = document.querySelector('.teams-schemes .scheme-frame');
      if (!schemeFrame) return;
  
      const blueMonitor = document.querySelector('.blue-team-diagram div:nth-child(2)'); // Мониторинг
      const redAttack = document.querySelector('.red-team-diagram div:nth-child(3)'); // Поиск уязвимостей
      const purpleAnalyze = document.querySelector('.purple-team-diagram div:nth-child(4) div:first-child'); // Анализ
  
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
  
    function drawThreatArrows() {
      const schemeFrame = document.querySelector('.threat-schemes .scheme-frame');
      if (!schemeFrame) return;
  
      const huntingAnalyze = document.querySelector('.threat-hunting-diagram div:nth-child(3)'); // Анализ
      const intelCollect = document.querySelector('.threat-intel-diagram div:nth-child(1)'); // Сбор данных
  
      if (!huntingAnalyze || !intelCollect) return;
  
      const frameRect = schemeFrame.getBoundingClientRect();
      const huntingRect = huntingAnalyze.getBoundingClientRect();
      const intelRect = intelCollect.getBoundingClientRect();
  
      const startX1 = huntingRect.right - frameRect.left;
      const startY1 = (huntingRect.top + huntingRect.bottom) / 2 - frameRect.top;
      const endX1 = intelRect.left - frameRect.left;
      const endY1 = (intelRect.top + intelRect.bottom) / 2 - frameRect.top;
  
      const arrow1 = document.getElementById('threat-arrow1');
      arrow1.setAttribute('d', `M${startX1},${startY1} C${startX1 + (endX1 - startX1) / 2},${startY1} ${startX1 + (endX1 - startX1) / 2},${endY1} ${endX1},${endY1}`);
    }
  
    function debounce(func, wait) {
      let timeout;
      return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
      };
    }
  
    const debouncedDrawTeamArrows = debounce(drawTeamArrows, 100);
    const debouncedDrawThreatArrows = debounce(drawThreatArrows, 100);
  
    setTimeout(() => {
      drawTeamArrows();
      drawThreatArrows();
    }, 100);
  
    window.addEventListener('resize', () => {
      debouncedDrawTeamArrows();
      debouncedDrawThreatArrows();
    });
  
    document.querySelector('.teams-schemes .scheme-frame').addEventListener('scroll', debouncedDrawTeamArrows);
    document.querySelector('.threat-schemes .scheme-frame').addEventListener('scroll', debouncedDrawThreatArrows);
  }