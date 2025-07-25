// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

function loadThreatModelContent(contentArea) {
  const initialContent = `
    <div class="threat-model-container">
      <h1>Модель угроз</h1>
      <div class="threat-model-description">
        <p><strong>Модель угроз</strong> — это структурированный подход к анализу и описанию потенциальных угроз информационной безопасности (ИБ) для конкретной системы, приложения или объекта. Она представляет собой документ или схему, которая помогает выявить риски, определить уязвимости, оценить возможные последствия и разработать эффективные меры защиты. Моделирование угроз является обязательным этапом при проектировании безопасных систем и используется как в коммерческих, так и в государственных структурах. В России этот процесс регулируется нормативными актами, такими как Приказ ФСТЭК № 21 от 18 февраля 2013 г., Федеральный закон № 187-ФЗ "О безопасности КИИ", а также ГОСТ Р 56939-2016 "Защита информации". На международном уровне применяются стандарты ISO/IEC 27005, NIST SP 800-30 и OWASP Threat Modeling.</p>
        <p>Цель модели угроз — не просто перечислить возможные атаки, а создать целостную картину рисков, учитывающую специфику системы, её архитектуру, используемые технологии и бизнес-контекст. Это позволяет организациям минимизировать вероятность инцидентов ИБ, таких как утечка данных, компрометация систем или нарушение работы критической инфраструктуры. Модель угроз применяется на всех этапах жизненного цикла системы: от проектирования до эксплуатации и модернизации.</p>
        
        <div class="threat-model-buttons">
          <button class="osi-btn" id="threat-example-btn">Пример модели угроз</button>
        </div>

        <h2>Зачем нужна модель угроз</h2>
        <p>Модель угроз выполняет следующие задачи:</p>
        <ul>
          <li><strong>Выявление рисков:</strong> Определение, какие угрозы актуальны для системы (например, хакерские атаки, инсайдерские утечки, сбои оборудования).</li>
          <li><strong>Планирование защиты:</strong> Формирование стратегии защиты на основе приоритетности угроз и уязвимостей.</li>
          <li><strong>Соответствие требованиям:</strong> Обеспечение выполнения нормативных актов (например, ФЗ-152 "О персональных данных", ФЗ-187 "О КИИ") и стандартов (ISO 27001).</li>
          <li><strong>Оптимизация ресурсов:</strong> Фокус на наиболее критичных угрозах, что снижает затраты на безопасность.</li>
          <li><strong>Обучение и осведомленность:</strong> Повышение понимания угроз среди разработчиков, администраторов и руководства.</li>
        </ul>
        
        <h2>Ключевые элементы модели угроз</h2>
        <p>Модель угроз включает следующие компоненты:</p>
        <ul>
          <li><strong>Активы:</strong> Ценные ресурсы системы (данные, серверы, ПО), которые нужно защитить.</li>
          <li><strong>Угрозы:</strong> Потенциальные сценарии атак или сбоев (взлом, DDoS, утечка).</li>
          <li><strong>Уязвимости:</strong> Слабые места, которые могут быть использованы для реализации угроз (например, отсутствие шифрования).</li>
          <li><strong>Источники угроз:</strong> Субъекты или факторы, создающие угрозы (хакеры, сотрудники, стихийные бедствия).</li>
          <li><strong>Последствия:</strong> Возможный ущерб (финансовый, репутационный, юридический).</li>
          <li><strong>Вероятность:</strong> Оценка шансов реализации угрозы с учетом текущих мер защиты.</li>
          <li><strong>Меры защиты:</strong> Технические и организационные действия для предотвращения или смягчения угроз.</li>
        </ul>
        
        <h2>Принципы создания модели угроз</h2>
        <p>Создание модели угроз — это многоэтапный процесс, который требует системного подхода и глубокого анализа. Основные принципы включают:</p>
        <ul>
          <li><strong>Полнота анализа:</strong> Учет всех возможных угроз, включая редкие или сложные сценарии (например, атаки через цепочку поставок).</li>
          <li><strong>Контекстуальность:</strong> Адаптация модели под конкретную систему, её назначение и среду эксплуатации (например, веб-приложение или АСУ ТП).</li>
          <li><strong>Итеративность:</strong> Постоянное обновление модели при изменении системы, появлении новых угроз или уязвимостей.</li>
          <li><strong>Количественная и качественная оценка:</strong> Использование метрик (например, CVSS для уязвимостей) и экспертных оценок для определения рисков.</li>
          <li><strong>Интеграция с разработкой:</strong> Внедрение моделирования угроз на этапе проектирования (DevSecOps) для предотвращения уязвимостей "по умолчанию".</li>
          <li><strong>Соответствие стандартам:</strong> Учет требований регуляторов (ФСТЭК, ФСБ) и международных практик (NIST, OWASP).</li>
          <li><strong>Прозрачность:</strong> Документирование всех шагов и выводов для возможности проверки и повторного использования.</li>
        </ul>
        
        <h2>Этапы разработки модели угроз</h2>
        <p>Процесс создания модели угроз включает следующие шаги:</p>
        <ol>
          <li><strong>Сбор данных:</strong> Анализ архитектуры системы (схемы сети, используемые технологии, точки входа), активов (базы данных, API, оборудование) и пользователей (администраторы, клиенты).</li>
          <li><strong>Идентификация активов:</strong> Определение ключевых объектов защиты, их ценности и критичности (например, персональные данные — высокий приоритет).</li>
          <li><strong>Определение источников угроз:</strong> Классификация субъектов (внешние хакеры, инсайдеры, конкуренты) и факторов (технические сбои, человеческий фактор).</li>
          <li><strong>Перечисление угроз:</strong> Составление списка потенциальных атак с использованием методологий, таких как STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) или PASTA (Process for Attack Simulation and Threat Analysis).</li>
          <li><strong>Анализ уязвимостей:</strong> Проверка системы на слабые места с помощью инструментов (Burp Suite, Nessus) и баз данных уязвимостей (CVE, ФСТЭК БДУ).</li>
          <li><strong>Оценка рисков:</strong> Расчет вероятности и последствий по формуле Риск = Вероятность × Ущерб, с учетом текущих мер защиты.</li>
          <li><strong>Разработка мер защиты:</strong> Выбор решений (фаерволы, IDS/IPS, шифрование) и их приоритизация на основе анализа рисков.</li>
          <li><strong>Визуализация:</strong> Создание схем, таблиц или диаграмм (например, Data Flow Diagram, DFD) для наглядного представления модели.</li>
          <li><strong>Тестирование модели:</strong> Проведение тестов на проникновение (penetration testing) для проверки актуальности выявленных угроз.</li>
          <li><strong>Документирование:</strong> Оформление модели в виде отчета или таблицы в соответствии с требованиями (например, формат ФСТЭК).</li>
          <li><strong>Обновление:</strong> Регулярный пересмотр модели (раз в год или при изменении системы) для учета новых угроз и технологий.</li>
        </ol>
        
        <h3>Схемы модели угроз</h3>
        <p>Ниже представлены схемы принципов создания и этапов разработки модели угроз:</p>
        <div class="scheme-frame" style="border: 2px solid #000; border-radius: 8px; background-color: #05060a; padding: 20px; display: flex; justify-content: flex-start; align-items: stretch; gap: 40px; position: relative;">
          <div class="threat-model-diagram" style="flex: 1; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Принципы создания модели угроз</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Полнота анализа
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Учет всех угроз, включая редкие</p>
              </div>
              <div style="background-color: #388e3c; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Контекстуальность
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Адаптация под систему (веб, АСУ ТП)</p>
              </div>
              <div style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Итеративность
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обновление при изменениях</p>
              </div>
              <div style="background-color: #039be5; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Количественная и качественная оценка
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Метрики (CVSS), экспертные оценки</p>
              </div>
              <div style="background-color: #ff8f00; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Интеграция с разработкой
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">DevSecOps, проектирование</p>
              </div>
              <div style="background-color: #ffa726; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Соответствие стандартам
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ФСТЭК, ФСБ, NIST, OWASP</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Прозрачность
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Документирование шагов</p>
              </div>
            </div>
          </div>
          <div class="threat-model-diagram" style="flex: 1; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Этапы разработки модели угроз</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
              <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #2e7d32; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Сбор данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Архитектура, активы, пользователи</p>
                </div>
                <div style="background-color: #388e3c; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Идентификация активов
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Ценность, критичность (ПДн)</p>
                </div>
              </div>
              <div style="border: 2px solid #039be5; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #0288d1; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Определение источников угроз
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Хакеры, инсайдеры, сбои</p>
                </div>
                <div style="background-color: #039be5; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Перечисление угроз
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">STRIDE, PASTA</p>
                </div>
              </div>
              <div style="background-color: #ff8f00; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Анализ уязвимостей
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Burp Suite, Nessus, CVE, ФСТЭК БДУ</p>
              </div>
              <div style="background-color: #ffa726; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Оценка рисков
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Риск = Вероятность × Ущерб</p>
              </div>
              <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
                <div style="background-color: #2e7d32; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                  Разработка мер защиты
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фаерволы, IDS/IPS, шифрование</p>
                </div>
                <div style="background-color: #388e3c; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                  Визуализация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Схемы, таблицы, DFD</p>
                </div>
              </div>
              <div style="background-color: #0288d1; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Тестирование модели
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Пентест для проверки</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Документирование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Отчет, формат ФСТЭК</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Обновление
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Раз в год, при изменениях</p>
              </div>
            </div>
          </div>
        </div>
        
        <h2>На что ориентироваться при создании модели угроз</h2>
        <p>При разработке модели угроз важно учитывать:</p>
        <ul>
          <li><strong>Нормативные акты:</strong> В России — ФЗ-152 "О персональных данных", ФЗ-187 "О КИИ", Приказ ФСТЭК № 21, ГОСТ Р 57580.1-2017. На международном уровне — ISO/IEC 27001, NIST SP 800-53, GDPR.</li>
          <li><strong>Тип системы:</strong> Угрозы для веб-приложений (XSS, SQL-инъекции) отличаются от угроз для IoT (физический доступ) или АСУ ТП (вмешательство в процессы).</li>
          <li><strong>Бизнес-контекст:</strong> В банках важны финансовые транзакции, в медицине — конфиденциальность данных, в промышленности — непрерывность процессов.</li>
          <li><strong>Исторические инциденты:</strong> Анализ прошлых атак (например, WannaCry, SolarWinds) для учета реальных сценариев.</li>
          <li><strong>Технологии:</strong> Уязвимости зависят от ОС (Windows, Linux), протоколов (HTTP, Modbus), оборудования (Cisco, Siemens).</li>
          <li><strong>Методологии:</strong> STRIDE, DREAD, PASTA, CVSS для классификации и оценки угроз.</li>
          <li><strong>Заинтересованные стороны:</strong> Учет требований заказчиков, регуляторов и пользователей системы.</li>
          <li><strong>Текущие тренды:</strong> Рост атак с использованием ИИ, шифровальщиков и цепочек поставок (supply chain attacks).</li>
        </ul>
        
        <h2>Источники угроз</h2>
        <p>Угрозы могут исходить от различных источников:</p>
        <ul>
          <li><strong>Внешние злоумышленники:</strong> Хакеры, использующие эксплойты, фишинг, ransomware, DDoS.</li>
          <li><strong>Инсайдеры:</strong> Сотрудники или подрядчики, которые случайно или умышленно нарушают безопасность (утечка, саботаж).</li>
          <li><strong>Государственные акторы:</strong> APT-группы (например, Fancy Bear, Lazarus), проводящие целенаправленные атаки.</li>
          <li><strong>Технические сбои:</strong> Отказ оборудования, ошибки ПО, сбои в энергоснабжении.</li>
          <li><strong>Социальная инженерия:</strong> Обман пользователей для получения доступа (фишинг, подмена SIM-карт).</li>
          <li><strong>Сторонние поставщики:</strong> Уязвимости в ПО или оборудовании от вендоров (например, Log4j).</li>
          <li><strong>Стихийные бедствия:</strong> Наводнения, пожары, влияющие на физическую инфраструктуру.</li>
        </ul>
        
        <h2>Инструменты и подходы</h2>
        <p>Для создания модели угроз используются следующие инструменты и методы:</p>
        <ul>
          <li><strong>Microsoft Threat Modeling Tool:</strong> Инструмент для построения моделей по STRIDE с визуализацией DFD.</li>
          <li><strong>OWASP Threat Dragon:</strong> Бесплатный инструмент для создания моделей угроз с открытым исходным кодом.</li>
          <li><strong>Nessus/OpenVAS:</strong> Сканеры уязвимостей для выявления слабых мест.</li>
          <li><strong>ФСТЭК БДУ:</strong> База данных угроз ФСТЭК с актуальными сценариями для российских систем.</li>
          <li><strong>Burp Suite:</strong> Инструмент для анализа веб-приложений и поиска уязвимостей.</li>
          <li><strong>Mitre ATT&CK:</strong> Фреймворк для классификации тактик и техник атак.</li>
          <li><strong>Penetration Testing:</strong> Тестирование на проникновение для проверки модели в реальных условиях.</li>
        </ul>
        
        <p>Модель угроз — это живой документ, который должен регулярно обновляться для отражения новых рисков, изменений в системе и появления новых технологий защиты.</p>
      </div>
    </div>
  `;
  contentArea.innerHTML = initialContent;

  document.getElementById('threat-example-btn').addEventListener('click', () => {
    loadThreatExampleContent(contentArea);
  });
}
  
  function loadThreatExampleContent(contentArea) {
    const exampleContent = `
      <div class="threat-model-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Пример модели угроз</h1>
        <div class="threat-model-description">
          <p>Ниже представлен пример модели угроз для корпоративной информационной системы (КИС), включающей веб-портал для сотрудников, базу данных с конфиденциальной информацией и интеграцию с внешними сервисами (например, платежной системой). Модель разработана с учетом требований ФСТЭК (Приказ № 21) и методологии STRIDE.</p>
          
          <h2>Описание системы</h2>
          <p>Корпоративная информационная система включает:</p>
          <ul>
            <li><strong>Веб-портал:</strong> Работает на Apache/Nginx, доступен через HTTPS, используется сотрудниками для работы с задачами и документами.</li>
            <li><strong>База данных:</strong> MySQL/PostgreSQL, содержит персональные данные сотрудников, финансовую информацию и коммерческую тайну.</li>
            <li><strong>API:</strong> Интеграция с платежной системой для обработки транзакций.</li>
            <li><strong>Сеть:</strong> Локальная сеть (LAN) с доступом через VPN для удаленных сотрудников.</li>
            <li><strong>Пользователи:</strong> Сотрудники (100 человек), администраторы (5 человек), внешние подрядчики (10 человек).</li>
          </ul>
          <p>Активы: персональные данные (ФИО, паспортные данные), финансовая информация (счета, транзакции), доступ к системе управления.</p>
          
          <h2>Модель угроз</h2>
          <p>Таблица ниже описывает угрозы, их источники, уязвимости и меры защиты:</p>
        </div>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>№</th>
                <th>Угроза</th>
                <th>Источник</th>
                <th>Уязвимость</th>
                <th>Метод реализации</th>
                <th>Последствия</th>
                <th>Вероятность</th>
                <th>CVSS</th>
                <th>Меры защиты</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>1</td>
                <td>Несанкционированный доступ к веб-порталу</td>
                <td>Внешний злоумышленник</td>
                <td>Слабые пароли, отсутствие 2FA</td>
                <td>Брутфорс, фишинг</td>
                <td>Утечка данных, компрометация системы</td>
                <td>Высокая</td>
                <td>7.5</td>
                <td>Двухфакторная аутентификация (2FA), ограничение попыток входа, обучение сотрудников</td>
              </tr>
              <tr>
                <td>2</td>
                <td>SQL-инъекция через веб-формы</td>
                <td>Хакер</td>
                <td>Непроверенные входные данные</td>
                <td>Внедрение SQL-кода через поля ввода</td>
                <td>Утечка базы данных, изменение данных</td>
                <td>Средняя</td>
                <td>8.0</td>
                <td>Параметризованные запросы, WAF, регулярное сканирование уязвимостей</td>
              </tr>
              <tr>
                <td>3</td>
                <td>DDoS-атака на веб-портал</td>
                <td>Ботнет</td>
                <td>Отсутствие защиты от перегрузки</td>
                <td>Массовые запросы к серверу</td>
                <td>Недоступность портала, простой работы</td>
                <td>Средняя</td>
                <td>6.5</td>
                <td>CDN (Cloudflare), лимит запросов, анти-DDoS сервисы (Qrator)</td>
              </tr>
              <tr>
                <td>4</td>
                <td>Утечка данных инсайдером</td>
                <td>Сотрудник/подрядчик</td>
                <td>Недостаточный контроль доступа</td>
                <td>Копирование данных на USB или облако</td>
                <td>Утечка ПДн, репутационный ущерб</td>
                <td>Низкая</td>
                <td>5.0</td>
                <td>DLP-системы (Symantec), аудит действий, RBAC</td>
              </tr>
              <tr>
                <td>5</td>
                <td>XSS-атака через веб-портал</td>
                <td>Хакер</td>
                <td>Непроверенный ввод JS-кода</td>
                <td>Внедрение скриптов через формы</td>
                <td>Кража сессий, выполнение кода</td>
                <td>Средняя</td>
                <td>6.1</td>
                <td>Экранирование ввода, CSP, OWASP ZAP для тестирования</td>
              </tr>
              <tr>
                <td>6</td>
                <td>Компрометация VPN</td>
                <td>Внешний злоумышленник</td>
                <td>Уязвимости в VPN-протоколах</td>
                <td>Эксплойт уязвимостей (например, CVE-2021-20016)</td>
                <td>Доступ к внутренней сети</td>
                <td>Средняя</td>
                <td>7.8</td>
                <td>Обновление VPN-серверов, использование IPsec, мониторинг трафика</td>
              </tr>
              <tr>
                <td>7</td>
                <td>Шифровальщик (ransomware)</td>
                <td>Хакерская группа</td>
                <td>Устаревшее ПО, фишинг</td>
                <td>Доставка через email или эксплойт</td>
                <td>Шифрование данных, вымогательство</td>
                <td>Высокая</td>
                <td>9.1</td>
                <td>Антивирус (Kaspersky), резервное копирование, песочницы</td>
              </tr>
              <tr>
                <td>8</td>
                <td>Сбой сервера</td>
                <td>Технический сбой</td>
                <td>Отсутствие резервирования</td>
                <td>Перегрузка или отказ оборудования</td>
                <td>Остановка работы системы</td>
                <td>Низкая</td>
                <td>4.0</td>
                <td>Резервные серверы, мониторинг (Zabbix), UPS</td>
              </tr>
              <tr>
                <td>9</td>
                <td>MITM-атака на API</td>
                <td>Хакер</td>
                <td>Отсутствие шифрования TLS</td>
                <td>Перехват трафика</td>
                <td>Утечка финансовых данных</td>
                <td>Средняя</td>
                <td>7.4</td>
                <td>TLS 1.3, проверка сертификатов, HSTS</td>
              </tr>
              <tr>
                <td>10</td>
                <td>Социальная инженерия</td>
                <td>Злоумышленник</td>
                <td>Низкая осведомленность сотрудников</td>
                <td>Фишинговые письма, звонки</td>
                <td>Раскрытие учетных данных</td>
                <td>Высокая</td>
                <td>6.8</td>
                <td>Обучение персонала, фильтрация email (DMARC)</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="threat-model-description">
          <h2>Анализ примера</h2>
          <p>Этот пример демонстрирует модель угроз для корпоративной системы с учетом российских требований (ФСТЭК) и международных практик (STRIDE). Каждая угроза оценена по шкале CVSS (Common Vulnerability Scoring System) для определения критичности. Например, шифровальщик получил оценку 9.1 из-за высокого ущерба и распространенности таких атак (см. инциденты WannaCry, NotPetya).</p>
          <p>Меры защиты включают как технические решения (WAF, TLS), так и организационные (обучение, аудит). Модель адаптирована к системе с веб-порталом и API, но может быть расширена для других сценариев (например, IoT или АСУ ТП).</p>
          
          <h2>Рекомендации по улучшению</h2>
          <ul>
            <li><strong>Автоматизация:</strong> Использование SIEM (например, Splunk) для мониторинга и реагирования на угрозы в реальном времени.</li>
            <li><strong>Тестирование:</strong> Проведение регулярных пентестов для проверки актуальности модели.</li>
            <li><strong>Шифрование:</strong> Внедрение ГОСТ-шифрования для соответствия требованиям ФСБ.</li>
            <li><strong>Резервирование:</strong> Настройка кластеризации серверов для отказоустойчивости.</li>
          </ul>
        </div>
      </div>
    `;
    contentArea.innerHTML = exampleContent;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadThreatModelContent(contentArea);
    });
  }
