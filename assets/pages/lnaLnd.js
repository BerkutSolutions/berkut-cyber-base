function loadLnaLndContent(contentArea) {
  const initialContent = `
    <div class="lna-lnd-container">
      <h1>ЛНА и ЛНД</h1>
      <div class="lna-lnd-description">
        <p><strong>Локально-нормативные акты (ЛНА)</strong> и <strong>локально-нормативные документы (ЛНД)</strong> — это ключевые элементы системы управления информационной безопасностью (ИБ) в организации. ЛНА задают стратегические рамки и обязательные правила, обеспечивая соответствие законодательству и защиту активов компании. ЛНД детализируют эти правила, предоставляя практические рекомендации и процедуры для реализации политики ИБ на уровне процессов, технологий и персонала.</p>
        <p>Документы ориентированы на выполнение требований российских законов (ФЗ-152 "О персональных данных", ФЗ-187 "О безопасности КИИ", Приказ ФСТЭК № 21) и международных стандартов (ISO/IEC 27001, NIST SP 800-53). Они необходимы для предотвращения инцидентов ИБ, таких как утечки данных, кибератаки или сбои инфраструктуры, а также для минимизации юридических и репутационных рисков.</p>
      </div>
      <div class="osi-buttons">
        <button class="osi-btn" id="lna-btn">Примеры ЛНА</button>
        <button class="osi-btn" id="lnd-btn">Примеры ЛНД</button>
      </div>
      <div class="lna-lnd-description">
        <h2>Теория составления ЛНА</h2>
        <p>ЛНА — это нормативные акты, формирующие общую политику ИБ. Они должны быть:</p>
        <ul>
          <li><strong>Соответствующими:</strong> учитывать ФЗ-152, ФЗ-187, ГОСТ Р 57580 и корпоративные цели.</li>
          <li><strong>Структурированными:</strong> содержать четкие разделы для удобства восприятия и контроля.</li>
          <li><strong>Обязательными:</strong> утверждаться руководством и иметь юридическую силу в компании.</li>
          <li><strong>Актуальными:</strong> пересматриваться ежегодно или при изменении угроз и нормативов.</li>
        </ul>
        <p>Структура ЛНА:</p>
        <ol>
          <li>Титульный лист (название, номер, дата, подпись).</li>
          <li>Введение (цели, область применения).</li>
          <li>Термины и определения.</li>
          <li>Положения (правила и требования).</li>
          <li>Ответственность сторон.</li>
          <li>Порядок внедрения и пересмотра.</li>
          <li>Приложения (дополнительные материалы).</li>
        </ol>

        <h2>Теория составления ЛНД</h2>
        <p>ЛНД — это практические документы, обеспечивающие реализацию ЛНА. Они должны:</p>
        <ul>
          <li><strong>Быть конкретными:</strong> учитывать особенности технологий (ОС, ПО, оборудование).</li>
          <li><strong>Практическими:</strong> содержать пошаговые рекомендации и процедуры.</li>
          <li><strong>Связанными:</strong> опираться на положения соответствующего ЛНА.</li>
          <li><strong>Проверяемыми:</strong> включать критерии оценки выполнения.</li>
        </ul>
        <p>Структура ЛНД:</p>
        <ol>
          <li>Название и ссылка на ЛНА.</li>
          <li>Цель и задачи.</li>
          <li>Область применения (системы, сотрудники).</li>
          <li>Рекомендации или процедуры.</li>
          <li>Ответственные лица и сроки.</li>
          <li>Контроль выполнения.</li>
          <li>Приложения (чек-листы, схемы).</li>
        </ol>
      </div>
      <div class="lna-lnd-schemes">
        <h2>Схемы создания документов</h2>
        <p>Ниже представлены схемы процессов разработки ЛНА и ЛНД с указанием их взаимосвязи:</p>
        <div class="scheme-frame" style="border: 2px solid #444; border-radius: 8px; padding: 20px; background-color: #05060a; display: flex; justify-content: space-around; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
          <div class="threat-model-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Схема создания ЛНА</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Анализ требований
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изучение законодательства, стандартов и рисков ИБ.</p>
              </div>
              <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #388e3c; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Разработка проекта
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Формирование структуры и положений ЛНА.</p>
                </div>
                <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Согласование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обсуждение с отделами ИБ, ИТ и юр. службой.</p>
                </div>
              </div>
              <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
                <div id="lna-approve" style="background-color: #ffeb3b; color: #000; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Утверждение
                  <p style="font-size: 12px; margin: 5px 0 0;">Подписание руководством, придание юридической силы.</p>
                </div>
                <div id="lna-distribute" style="background-color: #fff176; color: #000; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Распространение
                  <p style="font-size: 12px; margin: 5px 0 0;">Ознакомление сотрудников через портал.</p>
                </div>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Контроль</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг выполнения, аудит.</p>
              </div>
            </div>
          </div>
          <div class="threat-model-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Схема создания ЛНД</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div id="lnd-task" style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Определение задачи
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">На основе утвержденного ЛНА.</p>
              </div>
              <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
                <div id="lnd-collect" style="background-color: #388e3c; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Анализ систем, ПО, оборудования.</p>
                </div>
                <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Разработка
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Создание рекомендаций и процедур.</p>
                </div>
              </div>
              <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
                <div style="background-color: #ffeb3b; color: #000; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Тестирование
                  <p style="font-size: 12px; margin: 5px 0 0;">Проверка процедур на практике.</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Утверждение
                  <p style="font-size: 12px; margin: 5px 0 0;">Согласование с ответственными лицами.</p>
                </div>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                <span style="font-size: 16px;">Обучение</span>
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Инструктаж сотрудников.</p>
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
        <p>На схеме видно, что утвержденный ЛНА становится основой для определения задач ЛНД, а процесс распространения ЛНА предоставляет данные для этапа сбора информации при разработке ЛНД.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = initialContent;

  // Функция для рисования SVG-стрелок
  function drawArrows() {
    const schemeFrame = document.querySelector('.scheme-frame');
    if (!schemeFrame) {
      console.warn('Scheme frame not found.');
      return;
    }

    // Получаем элементы
    const lnaApprove = document.getElementById('lna-approve');
    const lnaDistribute = document.getElementById('lna-distribute');
    const lndTask = document.getElementById('lnd-task');
    const lndCollect = document.getElementById('lnd-collect');

    if (!lnaApprove || !lnaDistribute || !lndTask || !lndCollect) {
      console.warn('One or more elements for arrows not found.');
      return;
    }

    // Получаем координаты относительно scheme-frame
    const frameRect = schemeFrame.getBoundingClientRect();
    const approveRect = lnaApprove.getBoundingClientRect();
    const distributeRect = lnaDistribute.getBoundingClientRect();
    const taskRect = lndTask.getBoundingClientRect();
    const collectRect = lndCollect.getBoundingClientRect();

    // Координаты начала и конца стрелок (относительно scheme-frame)
    const startX1 = approveRect.right - frameRect.left;
    const startY1 = (approveRect.top + approveRect.bottom) / 2 - frameRect.top;
    const endX1 = taskRect.left - frameRect.left;
    const endY1 = (taskRect.top + taskRect.bottom) / 2 - frameRect.top;

    const startX2 = distributeRect.right - frameRect.left;
    const startY2 = (distributeRect.top + distributeRect.bottom) / 2 - frameRect.top;
    const endX2 = collectRect.left - frameRect.left;
    const endY2 = (collectRect.top + collectRect.bottom) / 2 - frameRect.top;

    // Рисуем первую стрелку (Утверждение -> Определение задачи)
    const arrow1 = document.getElementById('arrow1');
    const controlX1 = startX1 + (endX1 - startX1) / 2;
    const controlY1 = startY1;
    const controlX2 = controlX1;
    const controlY2 = endY1;
    arrow1.setAttribute('d', `M${startX1},${startY1} C${controlX1},${controlY1} ${controlX2},${controlY2} ${endX1},${endY1}`);

    // Рисуем вторую стрелку (Распространение -> Сбор данных)
    const arrow2 = document.getElementById('arrow2');
    const controlX3 = startX2 + (endX2 - startX2) / 2;
    const controlY3 = startY2;
    const controlX4 = controlX3;
    const controlY4 = endY2;
    arrow2.setAttribute('d', `M${startX2},${startY2} C${controlX3},${controlY3} ${controlX4},${controlY4} ${endX2},${endY2}`);
  }

  // Функция debounce для ограничения частоты вызовов
  function debounce(func, wait) {
    let timeout;
    return function (...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Создаём debounced версию drawArrows
  const debouncedDrawArrows = debounce(drawArrows, 100);

  // Вызываем функцию рисования стрелок после загрузки DOM
  setTimeout(drawArrows, 100);

  // Обновляем стрелки при изменении размеров окна с debounce
  window.addEventListener('resize', debouncedDrawArrows);

  // Добавляем скролл для scheme-frame
  document.querySelector('.scheme-frame').addEventListener('scroll', debouncedDrawArrows);

  document.getElementById('lna-btn').addEventListener('click', () => {
    loadLnaExamples(contentArea);
  });

  document.getElementById('lnd-btn').addEventListener('click', () => {
    loadLndExamples(contentArea);
  });
}

function loadLnaExamples(contentArea) {
  const lnaContent = `
    <div class="lna-lnd-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Примеры ЛНА</h1>
      <div class="lna-example">
        <h2>Политика обеспечения информационной безопасности корпоративной сети</h2>
        <p><strong>Локально-нормативный акт № 01-ИБ/2025</strong></p>
        <p><strong>Дата утверждения:</strong> 15 марта 2025</p>
        <p><strong>Утверждено:</strong> Генеральный директор ООО "Беркут Кибер" Иванов И.И.</p>
        <p><strong>Цель:</strong> Установление единых требований для обеспечения безопасности корпоративной сети, включая защиту данных, предотвращение кибератак и обеспечение непрерывности бизнес-процессов.</p>
        <p><strong>Область применения:</strong> Все элементы корпоративной сети ООО "Беркут Кибер", включая серверы, рабочие станции, сетевое оборудование (роутеры, коммутаторы), VPN, а также удаленные подключения сотрудников.</p>
        <p><strong>Термины и определения:</strong></p>
        <ul>
          <li><strong>Корпоративная сеть:</strong> Совокупность ИТ-ресурсов (серверы, рабочие станции, сетевые устройства), объединенных для выполнения бизнес-функций.</li>
          <li><strong>Инцидент ИБ:</strong> Любое событие, нарушающее конфиденциальность, целостность или доступность данных и систем.</li>
          <li><strong>Критические данные:</strong> Персональные данные сотрудников, финансовая информация, коммерческая тайна.</li>
        </ul>
        <p><strong>Положения:</strong></p>
        <ul>
          <li>Все устройства в сети должны быть зарегистрированы в реестре ИТ-активов (ведение в системе ITSM).</li>
          <li>Доступ к сети предоставляется только через защищенные каналы (VPN с IPsec или SSL, шифрование по ГОСТ).</li>
          <li>На всех серверах и рабочих станциях устанавливается антивирусное ПО (Kaspersky, ESET) с централизованным управлением.</li>
          <li>Обновления ОС, ПО и прошивок сетевых устройств проводятся ежемесячно или при выходе критических патчей.</li>
          <li>Сетевой трафик мониторится с помощью SIEM-системы (например, Splunk) для выявления аномалий.</li>
          <li>Использование съемных носителей запрещено без предварительного сканирования и разрешения отдела ИБ.</li>
          <li>Сотрудники обязаны использовать сложные пароли (мин. 12 символов, с ротацией каждые 90 дней) и двухфакторную аутентификацию (2FA) для доступа к критическим системам.</li>
          <li>Запрещается подключение личных устройств (BYOD) к корпоративной сети без проверки соответствия требованиям ИБ.</li>
          <li>Регулярное резервное копирование данных проводится на защищенные серверы (ежедневно для критичных данных, еженедельно для остальных).</li>
          <li>В случае инцидента ИБ сотрудники обязаны уведомить отдел ИБ в течение 1 часа через email или горячую линию.</li>
        </ul>
        <p><strong>Ответственность:</strong></p>
        <ul>
          <li><strong>Сотрудники:</strong> Выполнение требований, сообщение об инцидентах, участие в обучении по ИБ (раз в полгода).</li>
          <li><strong>Отдел ИБ:</strong> Разработка и контроль ЛНА/ЛНД, проведение аудита сети (ежеквартально), реагирование на инциденты.</li>
          <li><strong>ИТ-отдел:</strong> Техническая реализация мер защиты, ведение реестра активов.</li>
          <li><strong>Руководство:</strong> Утверждение политики, выделение бюджета на ИБ.</li>
        </ul>
        <p><strong>Порядок внедрения:</strong></p>
        <ul>
          <li>Ознакомление сотрудников с ЛНА через корпоративный портал (до 20 марта 2025).</li>
          <li>Проведение аудита текущего состояния сети (до 30 марта 2025).</li>
          <li>Внедрение технических мер (до 15 апреля 2025).</li>
        </ul>
        <p><strong>Порядок пересмотра:</strong> Ежегодно (до 31 декабря) или при изменении законодательства, структуры сети или выявлении новых угроз.</p>
        <p><strong>Приложения:</strong> Реестр ИТ-активов, список утвержденного ПО, чек-лист аудита сети.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = lnaContent;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadLnaLndContent(contentArea);
  });
}

function loadLndExamples(contentArea) {
  const lndContent = `
    <div class="lna-lnd-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Примеры ЛНД</h1>
      <div class="lnd-example">
        <h2>Рекомендации по обеспечению безопасности корпоративной сети</h2>
        <p><strong>Локально-нормативный документ № 02-ИБ/2025</strong></p>
        <p><strong>Ссылка на ЛНА:</strong> Политика обеспечения ИБ корпоративной сети № 01-ИБ/2025</p>
        <p><strong>Цель:</strong> Обеспечение практической реализации политики ИБ через детальные рекомендации по настройке, мониторингу и защите корпоративной сети.</p>
        <p><strong>Область применения:</strong> Серверы (Windows Server, Linux), рабочие станции (Windows 10/11), сетевое оборудование (Cisco, MikroTik), VPN, сотрудники ООО "Беркут Кибер".</p>
        <p><strong>Рекомендации:</strong></p>
        <ul>
          <li><strong>Регистрация устройств:</strong>
            <ul>
              <li>Добавьте все устройства в реестр ITSM (ServiceNow) с указанием IP, MAC-адреса, ОС и владельца.</li>
              <li>Проверяйте актуальность реестра ежемесячно (ответственный — ИТ-отдел).</li>
            </ul>
          </li>
          <li><strong>Настройка VPN:</strong>
            <ul>
              <li>Используйте OpenVPN или IPsec с шифрованием AES-256 (настройка через pfSense).</li>
              <li>Генерируйте сертификаты через внутренний CA (OpenSSL) с сроком действия 1 год.</li>
              <li>Ограничьте доступ по IP (whitelist) для удаленных подключений.</li>
              <li>Логируйте все подключения в SIEM (Splunk) с уведомлением при аномалиях.</li>
            </ul>
          </li>
          <li><strong>Антивирусная защита:</strong>
            <ul>
              <li>Установите Kaspersky Endpoint Security на все устройства (сервер управления — Kaspersky Security Center).</li>
              <li>Настройте ежедневное обновление баз (12:00) и еженедельное полное сканирование (пятница, 18:00).</li>
              <li>Включите проверку съемных носителей и блокировку подозрительных процессов (Behavior Detection).</li>
            </ul>
          </li>
          <li><strong>Обновления:</strong>
            <ul>
              <li>Настройте WSUS для Windows-устройств с ежемесячным развертыванием обновлений (вторник патчей).</li>
              <li>Обновляйте Linux-серверы через yum/apt (cron-задание: "0 3 * * 1 apt update && apt upgrade -y").</li>
              <li>Проверяйте прошивки сетевых устройств (Cisco IOS, MikroTik RouterOS) на сайте вендора ежемесячно.</li>
            </ul>
          </li>
          <li><strong>Мониторинг сети:</strong>
            <ul>
              <li>Разверните Splunk с агентами на серверах и рабочих станциях (порт 9997).</li>
              <li>Настройте правила для выявления аномалий: >1000 запросов/мин с одного IP, подозрительные порты (445, 3389).</li>
              <li>Используйте Zabbix для мониторинга uptime серверов и нагрузки (уведомления в Telegram).</li>
            </ul>
          </li>
          <li><strong>Контроль съемных носителей:</strong>
            <ul>
              <li>Включите запрет автозапуска: реестр Windows → HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer → "NoDriveTypeAutoRun" = 255.</li>
              <li>Настройте DLP (Symantec) для блокировки копирования критичных данных на USB.</li>
              <li>Разрешайте использование только корпоративных носителей с серийными номерами.</li>
            </ul>
          </li>
          <li><strong>Управление доступом:</strong>
            <ul>
              <li>Внедрите 2FA через Duo Security для доступа к VPN и критическим системам.</li>
              <li>Настройте политику паролей в AD: мин. 12 символов, смена раз в 90 дней, запрет повторения.</li>
              <li>Используйте RBAC для ограничения прав (администраторы — полный доступ, пользователи — только чтение).</li>
            </ul>
          </li>
          <li><strong>Резервное копирование:</strong>
            <ul>
              <li>Настройте Veeam Backup для ежедневного копирования критичных данных (23:00) на NAS с шифрованием AES-256.</li>
              <li>Проводите еженедельный полный бэкап серверов (воскресенье, 02:00).</li>
              <li>Храните копии в оффлайн-хранилище (ленты LTO) с ротацией раз в месяц.</li>
              <li>Тестируйте восстановление данных ежеквартально.</li>
            </ul>
          </li>
          <li><strong>Реагирование на инциденты:</strong>
            <ul>
              <li>Создайте шаблон уведомления: "Тип инцидента, время, устройство, описание".</li>
              <li>Отправляйте уведомления на security@berkutcyber.ru или звоните на горячую линию +7-XXX-XXX-XX-XX.</li>
              <li>Ведите журнал инцидентов в ITSM с указанием мер реагирования.</li>
            </ul>
          </li>
        </ul>
        <p><strong>Ответственные лица:</strong> Системный администратор Петров П.П., отдел ИБ (Иванов А.А.), ИТ-отдел (Сидоров В.В.).</p>
        <p><strong>Контроль выполнения:</strong> Ежемесячный аудит отделом ИБ с отчетом руководству.</p>
        <p><strong>Приложения:</strong> Чек-лист настройки VPN, шаблон журнала инцидентов, список IP для whitelist.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = lndContent;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadLnaLndContent(contentArea);
  });
}