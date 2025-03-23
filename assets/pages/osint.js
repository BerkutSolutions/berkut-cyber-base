function loadOsintContent(contentArea) {
  const osintContent = `
    <div class="osint-container">
      <h1>OSINT (Open-Source Intelligence)</h1>
      <div class="osint-description">
        <p><strong>OSINT (Open-Source Intelligence)</strong> — это разведка на основе открытых источников, методология сбора и анализа информации из общедоступных данных. К таким источникам относятся социальные сети, публичные базы данных, новостные сайты, форумы, блоги, государственные реестры и даже спутниковые снимки. OSINT используется как в легальных целях (например, журналистами, аналитиками, правоохранительными органами), так и злоумышленниками для подготовки атак, социальной инженерии или шпионажа.</p>
      </div>

      <h2>История появления и развитие OSINT</h2>
      <div class="osint-description">
        <p>Концепция OSINT зародилась задолго до появления интернета. Её корни уходут в эпоху Второй мировой войны, когда разведывательные службы, такие как Управление стратегических служб США (OSS, предшественник ЦРУ), собирали информацию из газет, радиопередач и других открытых источников для анализа действий противника. Например, OSS анализировало немецкие газеты, чтобы понять, какие города подвергались бомбардировкам, и оценивать эффективность союзнических операций.</p>
        <p>С развитием интернета в 1990-х годах OSINT получил новый импульс. Появление поисковых систем, таких как Google, и социальных сетей, таких как Facebook и Twitter (ныне X), сделало огромные объёмы данных доступными для анализа. В 2000-х годах OSINT стал ключевым инструментом для борьбы с терроризмом: спецслужбы использовали открытые данные для отслеживания активности экстремистских групп. Например, после терактов 11 сентября 2001 года американские агентства активно применяли OSINT для анализа публичных заявлений "Аль-Каиды".</p>
        <p>В 2010-х годах OSINT стал ещё более популярным благодаря развитию технологий анализа больших данных и машинного обучения. Появились специализированные инструменты, такие как Maltego, SpiderFoot и Bellingcat, которые позволяют автоматизировать сбор и анализ данных. Сегодня OSINT применяется в самых разных областях: от кибербезопасности и конкурентной разведки до расследований Bellingcat, которые используют открытые данные для разоблачения военных преступлений.</p>
        <p>В России OSINT также активно развивается. Например, в 2020-х годах российские исследователи использовали открытые данные для анализа перемещений войск и техники в контексте конфликта на Украине, опираясь на спутниковые снимки, посты в социальных сетях и геолокационные данные. Однако OSINT в России часто сталкивается с ограничениями из-за цензуры интернета и законов, таких как "Суверенный интернет" (2019), которые усложняют доступ к некоторым данным.</p>
      </div>

      <h2>Схемы: процесс атаки и противодействие</h2>
      <div class="osint-description">
        <p>Ниже представлены две схемы: первая показывает, как злоумышленник использует OSINT для проведения атаки, вторая — как противодействовать таким атакам. Каждая схема сопровождается рекомендациями по защите.</p>
      </div>
      <div class="scheme-frame" style="border: 2px solid #444; border-radius: 8px; padding: 20px; background-color: #05060a; display: flex; justify-content: space-around; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
        <div class="osint-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
          <h3>Процесс атаки</h3>
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
              Сбор информации о цели
              <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">OSINT: соцсети, сайты, утечки данных.</p>
              <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: ограничьте публичный доступ к данным.</p>
            </div>
            <div style="border: 2px solid #03a9f4; padding: 10px; border-radius: 5px; width: 250px;">
              <div id="osint-contact" style="background-color: #03a9f4; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                Анализ данных
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Поиск уязвимостей и точек входа.</p>
                <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: минимизируйте цифровой след.</p>
              </div>
              <div style="background-color: #0288d1; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                Подготовка атаки
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Создание фишинговых писем, сценариев.</p>
                <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: обучайте сотрудников.</p>
              </div>
            </div>
            <div style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
              Атака
              <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фишинг, социальная инженерия.</p>
              <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: используйте MFA, фильтры.</p>
            </div>
            <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
              <span style="font-size: 16px;">Результат</span>
              <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Доступ к системам, утечка данных.</p>
            </div>
          </div>
        </div>
        <div class="osint-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
          <h3>Противодействие</h3>
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div id="osint-counter" style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
              Оценка цифрового следа
              <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аудит данных в интернете.</p>
              <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Действие: удалите лишние данные.</p>
            </div>
            <div style="border: 2px solid #03a9f4; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #03a9f4; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                Минимизация утечек
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Настройка приватности.</p>
                <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Действие: используйте псевдонимы.</p>
              </div>
              <div style="background-color: #0288d1; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                Обучение сотрудников
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Тренинги по кибербезопасности.</p>
                <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Действие: симуляции атак.</p>
              </div>
            </div>
            <div style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
              Мониторинг и защита
              <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Системы мониторинга, 2FA.</p>
              <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Действие: внедрите SIEM.</p>
            </div>
            <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
              <span style="font-size: 16px;">Итог</span>
              <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Снижение рисков, защита данных.</p>
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
        </svg>
      </div>
      <div class="osint-description">
        <p>Схемы показывают, как злоумышленник использует OSINT для атаки и как можно противодействовать таким угрозам. На каждом этапе указаны меры защиты.</p>
      </div>

      <h2>Популярные инструменты OSINT</h2>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Инструмент</th>
              <th>Описание</th>
              <th>Применение</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Maltego</td>
              <td>Платформа для анализа связей между данными из открытых источников.</td>
              <td>Построение графов связей между людьми, организациями, доменами и IP-адресами.</td>
            </tr>
            <tr>
              <td>SpiderFoot</td>
              <td>Автоматизированный инструмент для сбора данных из сотен источников.</td>
              <td>Сбор информации о доменах, email, утечках данных для пентестинга.</td>
            </tr>
            <tr>
              <td>Shodan</td>
              <td>Поисковая система для устройств, подключённых к интернету.</td>
              <td>Поиск уязвимых устройств, серверов, камер, IoT-устройств.</td>
            </tr>
            <tr>
              <td>Have I Been Pwned</td>
              <td>Сервис для проверки утечек email-адресов и паролей.</td>
              <td>Проверка, не попали ли ваши данные в утечки.</td>
            </tr>
            <tr>
              <td>OSINT Framework</td>
              <td>Коллекция ссылок на OSINT-инструменты, организованная по категориям.</td>
              <td>Удобный доступ к инструментам для сбора данных.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="osint-description">
        <h2>Примечания</h2>
        <ul>
          <li>OSINT — это мощный инструмент, который может быть использован как для защиты, так и для атак. Важно понимать, как злоумышленники могут использовать открытые данные, чтобы эффективно противодействовать.</li>
          <li>В России доступ к некоторым OSINT-инструментам может быть ограничен из-за блокировок, автор не рекомендует использование средств по обходу данных блокировок</li>
          <li>Этика в OSINT крайне важна: сбор данных должен соответствовать законодательству, особенно в части защиты персональных данных (например, ФЗ-152 в России).</li>
        </ul>
      </div>
    </div>

    <style>
      .osint-container {
        padding: 20px;
        color: #ffffff;
      }
      .osint-description {
        margin-bottom: 20px;
        line-height: 1.6;
      }
      .osi-table-container {
        overflow-x: auto;
        margin: 20px 0;
      }
      .osi-table {
        width: 100%;
        border-collapse: collapse;
        background-color: #0e121b; /* Указанный цвет фона таблицы */
        color: #ffffff;
      }
      .osi-table th,
      .osi-table td {
        padding: 10px;
        text-align: left;
        border-bottom: 1px solid #2a2f3b; /* Указанный цвет границы */
      }
      .osi-table th {
        background-color: #1a1f2b; /* Указанный цвет фона заголовков */
        font-weight: bold;
      }
      .osi-table td {
        background-color: #0e121b; /* Указанный цвет фона ячеек */
      }
    </style>
  `;
  contentArea.innerHTML = osintContent;

  function drawArrows() {
    const schemeFrame = document.querySelector('.scheme-frame');
    if (!schemeFrame) {
      console.warn('Scheme frame not found.');
      return;
    }

    const osintContact = document.getElementById('osint-contact');
    const osintCounter = document.getElementById('osint-counter');

    if (!osintContact || !osintCounter) {
      console.warn('One or more elements for arrows not found.');
      return;
    }

    const frameRect = schemeFrame.getBoundingClientRect();
    const contactRect = osintContact.getBoundingClientRect();
    const counterRect = osintCounter.getBoundingClientRect();

    const startX1 = contactRect.right - frameRect.left;
    const startY1 = (contactRect.top + contactRect.bottom) / 2 - frameRect.top;
    const endX1 = counterRect.left - frameRect.left;
    const endY1 = (counterRect.top + counterRect.bottom) / 2 - frameRect.top;

    const arrow1 = document.getElementById('arrow1');
    const controlX1 = startX1 + (endX1 - startX1) / 2;
    const controlY1 = startY1;
    const controlX2 = controlX1;
    const controlY2 = endY1;
    arrow1.setAttribute('d', `M${startX1},${startY1} C${controlX1},${controlY1} ${controlX2},${controlY2} ${endX1},${endY1}`);
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