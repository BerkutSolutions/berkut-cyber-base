// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

function loadForensicsContent(contentArea) {
    const initialContent = `
      <div class="forensics-container">
        <h1>Форензика</h1>
        <div class="forensics-description">
          <p><strong>Цифровая форензика</strong> (или компьютерная криминалистика) — это дисциплина, которая занимается сбором, анализом и сохранением цифровых доказательств для расследования инцидентов информационной безопасности, киберпреступлений или нарушений корпоративных политик. Форензика помогает выявить, как произошел инцидент, кто за ним стоит, какие данные были скомпрометированы, и как предотвратить подобные случаи в будущем.</p>
          <p>Этот раздел объясняет, зачем нужна форензика, как она применяется в ИБ, и какие этапы включает процесс расследования.</p>
        </div>

        <div class="forensics-description">
          <h2>Зачем нужна форензика</h2>
          <p>Форензика играет ключевую роль в современном мире, где киберпреступления становятся всё более сложными. Она помогает:</p>
          <ul>
            <li><strong>Расследовать инциденты:</strong> Определить, как злоумышленник получил доступ к системе, какие действия он совершил, и какие данные были затронуты (например, утечка персональных данных, установка вредоносного ПО).</li>
            <li><strong>Собирать доказательства:</strong> Обеспечить юридически значимые доказательства для судебных разбирательств, которые могут быть использованы в суде (например, в делах о кибермошенничестве или краже данных).</li>
            <li><strong>Восстанавливать данные:</strong> Извлечь удалённые или повреждённые файлы, которые могут быть важны для расследования или восстановления работы системы.</li>
            <li><strong>Укреплять безопасность:</strong> Выявить уязвимости, которые привели к инциденту, и разработать меры для их устранения (например, обновление политик ИБ, внедрение новых инструментов).</li>
            <li><strong>Соблюдать законодательство:</strong> Выполнить требования законов, таких как ФЗ-152 "О персональных данных", которые обязывают организации расследовать утечки данных и уведомлять о них.</li>
          </ul>

          <h2>Как форензика помогает</h2>
          <p>Форензика предоставляет структурированный подход к расследованию инцидентов, что позволяет:</p>
          <ul>
            <li><strong>Идентифицировать источник атаки:</strong> Определить, был ли инцидент вызван внешним злоумышленником, инсайдером или техническим сбоем.</li>
            <li><strong>Восстановить хронологию событий:</strong> Установить точную последовательность действий (например, когда злоумышленник вошел в систему, какие файлы были изменены).</li>
            <li><strong>Снизить ущерб:</strong> Быстро локализовать проблему и минимизировать последствия (например, заблокировать скомпрометированные учетные записи).</li>
            <li><strong>Обучить сотрудников:</strong> Использовать результаты расследования для проведения тренингов по ИБ, чтобы предотвратить повторение инцидентов.</li>
            <li><strong>Улучшить репутацию:</strong> Показать клиентам и партнерам, что организация серьёзно относится к безопасности и способна эффективно реагировать на угрозы.</li>
          </ul>

          <h2>Этапы цифровой форензики</h2>
          <p>Процесс цифровой форензики включает несколько этапов, каждый из которых критически важен для успешного расследования. Ниже представлены схемы, иллюстрирующие эти этапы:</p>

          <div class="scheme-frame" style="border: 2px solid #444; border-radius: 8px; padding: 20px; background-color: #05060a; display: flex; justify-content: space-around; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
            <div class="forensics-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Подготовка и идентификация</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Подготовка
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Создание плана, сбор инструментов.</p>
                </div>
                <div style="border: 2px solid #42a5f5; padding: 10px; border-radius: 5px; width: 250px;">
                  <div id="forensics-identify" style="background-color: #42a5f5; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Идентификация
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Определение инцидента, источников данных.</p>
                  </div>
                  <div style="background-color: #2196f3; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Изоляция
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изолировать систему, чтобы сохранить данные.</p>
                  </div>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Готовность к сбору доказательств.</p>
                </div>
              </div>
            </div>
            <div class="forensics-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Сбор и анализ</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div id="forensics-collect" style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Создание копий дисков, логов, памяти.</p>
                </div>
                <div style="border: 2px solid #42a5f5; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #42a5f5; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Сохранение целостности
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Использование хэшей (MD5, SHA).</p>
                  </div>
                  <div style="background-color: #2196f3; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Анализ
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Поиск следов, восстановление данных.</p>
                  </div>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Хронология событий, улики.</p>
                </div>
              </div>
            </div>
            <div class="forensics-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Отчет и восстановление</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div id="forensics-report" style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Документирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Составление отчета с доказательствами.</p>
                </div>
                <div style="border: 2px solid #42a5f5; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #42a5f5; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Представление
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Передача отчета в суд или руководству.</p>
                  </div>
                  <div style="background-color: #2196f3; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Восстановление
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Устранение уязвимостей, восстановление систем.</p>
                  </div>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Закрытие инцидента, уроки.</p>
                </div>
              </div>
            </div>
            <svg id="arrows-svg" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;">
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="0" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
                </marker>
              </defs>
              <path id="arrow1" stroke="#666" stroke-width="2" fill="none" marker-end="url(#arrowhead)" />
              <path id="arrow2" stroke="#666" stroke-width="2" fill="none" marker-end="url(#arrowhead)" />
            </svg>
          </div>
          <p>Эти схемы показывают основные этапы цифровой форензики: от подготовки до восстановления системы после инцидента.</p>

          <h2>Инструменты цифровой форензики</h2>
          <p>Для проведения расследований используются специализированные инструменты. Вот таблица с примерами:</p>
          <div class="osi-table-container">
            <table class="osi-table">
              <thead>
                <tr>
                  <th>Инструмент</th>
                  <th>Назначение</th>
                  <th>Пример использования</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Autopsy</td>
                  <td>Анализ дисков и файловых систем</td>
                  <td>Восстановление удалённых файлов после атаки</td>
                </tr>
                <tr>
                  <td>Wireshark</td>
                  <td>Анализ сетевого трафика</td>
                  <td>Выявление подозрительных соединений</td>
                </tr>
                <tr>
                  <td>Volatility</td>
                  <td>Анализ оперативной памяти</td>
                  <td>Поиск следов вредоносного ПО</td>
                </tr>
                <tr>
                  <td>EnCase</td>
                  <td>Комплексный анализ и документирование</td>
                  <td>Подготовка отчета для суда</td>
                </tr>
                <tr>
                  <td>FTK Imager</td>
                  <td>Создание forensic-образов дисков</td>
                  <td>Сохранение копии диска для анализа</td>
                </tr>
              </tbody>
            </table>
          </div>

          <h2>Плюсы и минусы цифровой форензики</h2>
          <h3>Преимущества</h3>
          <ul>
            <li><strong>Точность расследования:</strong> Форензика позволяет восстановить детальную картину инцидента, включая хронологию и действия злоумышленника.</li>
            <li><strong>Юридическая значимость:</strong> Доказательства, собранные с соблюдением процедур, могут быть использованы в суде.</li>
            <li><strong>Профилактика:</strong> Выявление уязвимостей помогает предотвратить будущие инциденты.</li>
            <li><strong>Восстановление данных:</strong> Возможность вернуть удалённые или повреждённые файлы, важные для бизнеса.</li>
            <li><strong>Универсальность:</strong> Применима для расследования не только кибератак, но и внутренних нарушений (например, утечек данных сотрудниками).</li>
          </ul>
          <h3>Недостатки</h3>
          <ul>
            <li><strong>Высокая сложность:</strong> Требует высокой квалификации специалистов и глубоких знаний в ИБ, ОС, сетях.</li>
            <li><strong>Затраты времени:</strong> Полный цикл расследования может занять недели или месяцы, особенно при большом объеме данных.</li>
            <li><strong>Риски потери данных:</strong> Неправильное обращение с доказательствами (например, изменение метаданных) может сделать их недействительными в суде.</li>
            <li><strong>Ограничения технологий:</strong> Некоторые данные могут быть зашифрованы или удалены без возможности восстановления.</li>
            <li><strong>Юридические ограничения:</strong> В некоторых юрисдикциях могут быть строгие требования к сбору и хранению доказательств, что усложняет процесс.</li>
          </ul>

          <h2>Рекомендации по внедрению форензики</h2>
          <ul>
            <li><strong>Создайте команду:</strong> Нанимайте или обучите специалистов по цифровой форензике, либо привлекайте внешних экспертов.</li>
            <li><strong>Разработайте процедуры:</strong> Включите форензику в план реагирования на инциденты (IR), определите, кто и как будет собирать доказательства.</li>
            <li><strong>Используйте инструменты:</strong> Внедрите специализированные решения (Autopsy, Wireshark) и обеспечьте их регулярное обновление.</li>
            <li><strong>Обучайте сотрудников:</strong> Научите персонал не трогать системы после инцидента (например, не перезагружать сервер), чтобы сохранить доказательства.</li>
            <li><strong>Соблюдайте законы:</strong> Убедитесь, что процесс сбора доказательств соответствует местному законодательству (например, ФЗ-152, GDPR).</li>
          </ul>
        </div>
      </div>
    `;
    contentArea.innerHTML = initialContent;

    function drawArrows() {
      const schemeFrame = document.querySelector('.scheme-frame');
      if (!schemeFrame) {
        console.warn('Scheme frame not found.');
        return;
      }

      const forensicsIdentify = document.getElementById('forensics-identify');
      const forensicsCollect = document.getElementById('forensics-collect');
      const forensicsReport = document.getElementById('forensics-report');

      if (!forensicsIdentify || !forensicsCollect || !forensicsReport) {
        console.warn('One or more elements for arrows not found.');
        return;
      }

      const frameRect = schemeFrame.getBoundingClientRect();
      const identifyRect = forensicsIdentify.getBoundingClientRect();
      const collectRect = forensicsCollect.getBoundingClientRect();
      const reportRect = forensicsReport.getBoundingClientRect();

      const startX1 = identifyRect.right - frameRect.left;
      const startY1 = (identifyRect.top + identifyRect.bottom) / 2 - frameRect.top;
      const endX1 = collectRect.left - frameRect.left;
      const endY1 = (collectRect.top + collectRect.bottom) / 2 - frameRect.top;

      const startX2 = collectRect.right - frameRect.left;
      const startY2 = (collectRect.top + collectRect.bottom) / 2 - frameRect.top;
      const endX2 = reportRect.left - frameRect.left;
      const endY2 = (reportRect.top + reportRect.bottom) / 2 - frameRect.top;

      const arrow1 = document.getElementById('arrow1');
      const controlX1 = startX1 + (endX1 - startX1) / 2;
      const controlY1 = startY1;
      const controlX2 = controlX1;
      const controlY2 = endY1;
      arrow1.setAttribute('d', `M${startX1},${startY1} C${controlX1},${controlY1} ${controlX2},${controlY2} ${endX1},${endY1}`);

      const arrow2 = document.getElementById('arrow2');
      const controlX3 = startX2 + (endX2 - startX2) / 2;
      const controlY3 = startY2;
      const controlX4 = controlX3;
      const controlY4 = endY2;
      arrow2.setAttribute('d', `M${startX2},${startY2} C${controlX3},${controlY3} ${controlX4},${controlY4} ${endX2},${endY2}`);
    }

    function debounce(func, wait) {
      let timeout;
      return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
      };
    }

    const debouncedDrawArrows = debounce(drawArrows, 100);

    setTimeout(drawArrows, 100);

    window.addEventListener('resize', debouncedDrawArrows);

    document.querySelector('.scheme-frame').addEventListener('scroll', debouncedDrawArrows);
}
