// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

function loadStructureSecurityContent(container) {
container.innerHTML = `
<div class="structure-security-container">
      <h1>Защита структур</h1>

      <div class="structure-security-buttons">
        <button class="network-btn" id="os-security-btn">Безопасность ОС</button>
        <button class="network-btn" id="network-security-btn">Безопасность сетей</button>
        <button class="network-btn" id="auth-security-btn">Аутентификация и авторизация</button>
        <button class="network-btn" id="leak-protection-btn">Защита от утечек</button>
        <button class="network-btn state-secrets-btn">Защита гостайны</button>
        <button class="network-btn" id="cii-security-btn">Безопасность КИИ</button>
        <button class="network-btn" id="ot-security-btn">Безопасность АСУТП</button>
        <button class="network-btn" id="app-security-btn">Безопасность приложений</button>
        <button class="network-btn" id="db-security-btn">Безопасность СУБД</button>
        <button class="network-btn" id="cloud-security-btn">Безопасность облачных технологий</button>
        <button class="network-btn" id="iot-security-btn">Безопасность IoT</button>
        <button class="network-btn" id="microservices-security-btn">Безопасность микросервисов</button>
        <button class="network-btn" id="mobile-security-btn">Мобильная безопасность</button>
        <button class="network-btn" id="api-security-btn">Безопасность API</button>
        <button class="network-btn" id="container-security-btn">Безопасность контейнеров</button>
        <button class="network-btn" id="remote-work-security-btn">Безопасность удалённой работы</button>
      </div>

      <div class="structure-security-theory">
        <h2>Теория структурной безопасности</h2>
        <p>Структурная безопасность — это комплексный подход к защите информационных систем, который охватывает все уровни ИТ-инфраструктуры: от операционных систем и сетей до приложений, баз данных, облачных технологий, IoT, микросервисов и специализированных систем, таких как автоматизированные системы управления технологическими процессами (АСУТП), критическая информационная инфраструктура (КИИ) и государственная тайна. Основная цель структурной безопасности — минимизировать риски кибератак, утечек данных и сбоев в работе систем, обеспечивая их устойчивость и надёжность.</p>

        <h3>Основные принципы структурной безопасности</h3>
        <p>Структурная безопасность базируется на нескольких ключевых принципах, которые помогают создать многоуровневую защиту:</p>
        <ul>
          <li><strong>Принцип минимальных привилегий:</strong> Пользователи и процессы должны иметь доступ только к тем ресурсам, которые необходимы для выполнения их задач. Например, оператор АСУТП должен иметь доступ только к SCADA-системе, но не к корпоративной сети.</li>
          <li><strong>Многоуровневая защита (Defense-in-Depth):</strong> Использование нескольких слоёв защиты (физическая, сетевая, прикладная) для снижения риска компрометации. Например, для защиты КИИ применяются межсетевые экраны, системы обнаружения вторжений (IDS) и шифрование данных.</li>
          <li><strong>Сегментация:</strong> Разделение систем на изолированные зоны для ограничения распространения угроз. Например, сеть АСУТП должна быть изолирована от корпоративной сети с помощью VLAN и межсетевых экранов.</li>
          <li><strong>Мониторинг и реагирование:</strong> Постоянное наблюдение за состоянием систем с помощью SIEM-систем (например, Splunk) и оперативное реагирование на инциденты. Это позволяет своевременно выявлять аномалии, такие как несанкционированный доступ.</li>
          <li><strong>Соответствие нормативным требованиям:</strong> Соблюдение стандартов и законов, таких как ФЗ-187 (для КИИ), ФЗ-149 (для гостайны) и ГОСТ Р ИСО/МЭК 27001, чтобы обеспечить юридическую и техническую защиту.</li>
        </ul>

        <h3>Подходы к обеспечению структурной безопасности</h3>
        <p>Для реализации структурной безопасности применяются следующие подходы:</p>
        <ul>
          <li><strong>Управление рисками:</strong> Проведение регулярной оценки рисков для выявления уязвимостей и определения приоритетных мер защиты. Например, для АСУТП важно учитывать риски физического доступа к оборудованию.</li>
          <li><strong>Технические меры:</strong> Использование межсетевых экранов, систем шифрования (TLS, IPsec, ГОСТ), антивирусов и DLP-систем для предотвращения утечек данных.</li>
          <li><strong>Организационные меры:</strong> Обучение персонала, разработка политик безопасности, проведение аудитов и тестов на проникновение (penetration testing).</li>
          <li><strong>Автоматизация:</strong> Внедрение систем автоматизации реагирования на инциденты (SOAR), таких как IBM Resilient, для ускорения обработки угроз.</li>
        </ul>

        <h3>Примеры угроз и меры защиты</h3>
        <p>Структурная безопасность направлена на защиту от различных типов угроз. Вот несколько примеров:</p>
        <ul>
          <li><strong>Кибератаки на АСУТП:</strong> Атака Stuxnet (2010) показала, как уязвимости в SCADA-системах могут привести к физическому разрушению оборудования. Для защиты применяются изоляция сети, шифрование и регулярное обновление ПО.</li>
          <li><strong>Утечки гостайны:</strong> В 2016 году в России была зафиксирована утечка через USB-накопитель. Для предотвращения таких инцидентов используются DLP-системы и строгий контроль носителей.</li>
          <li><strong>DDoS-атаки на КИИ:</strong> Атака на энергосистему Украины (2015) привела к отключению электроэнергии. Для защиты применяются системы фильтрации трафика (например, Cloudflare) и резервирование каналов связи.</li>
          <li><strong>Утечки через технические каналы:</strong> Акустические утечки через окна могут быть предотвращены с помощью шумогенераторов и защитных плёнок.</li>
        </ul>

        <h3>Концепции анализа киберугроз</h3>
        <p>Для эффективной защиты структур важно понимать модели и методы анализа киберугроз. Ниже представлены ключевые концепции с подробным описанием и схемами:</p>
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-header">Cyber Kill Chain</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> Cyber Kill Chain (Цепочка кибератаки) — это модель, разработанная Lockheed Martin, которая описывает этапы кибератаки от подготовки до достижения цели. Она помогает понять действия злоумышленника и разработать меры противодействия на каждом этапе.</p>
              <p><strong>Схема этапов Cyber Kill Chain:</strong></p>
              <div class="kill-chain-diagram" style="margin-bottom: 20px;">
                <div class="kill-chain-container" style="display: flex; align-items: stretch; gap: 20px;">
                  <div class="kill-chain-stages" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                    <h3>Этапы атаки</h3>
                    <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                      <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                        Разведка
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сбор информации</p>
                      </div>
                      <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                        Вооружение
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Создание эксплойта</p>
                      </div>
                      <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                        Доставка
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Передача</p>
                      </div>
                      <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                        Эксплуатация
                        <p style="font-size: 12px; margin: 5px 0 0;">Выполнение кода</p>
                      </div>
                      <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                        Установка
                        <p style="font-size: 12px; margin: 5px 0 0;">Закрепление</p>
                      </div>
                      <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                        Управление
                        <p style="font-size: 12px; margin: 5px 0 0;">C2</p>
                      </div>
                      <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                        Действия
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Цель</p>
                      </div>
                    </div>
                  </div>
                  <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
                  <div style="flex: 1; padding: 15px;">
                    <h3>Описание этапов</h3>
                    <ul>
                      <li><strong>Разведка:</strong> Сбор данных о цели (OSINT, сканирование сети). Пример: поиск уязвимостей через Shodan.</li>
                      <li><strong>Вооружение:</strong> Создание вредоносного ПО или эксплойта. Пример: настройка пейлоада в Metasploit.</li>
                      <li><strong>Доставка:</strong> Передача эксплойта жертве (фишинг, USB). Пример: отправка PDF с вредоносным кодом.</li>
                      <li><strong>Эксплуатация:</strong> Использование уязвимости для выполнения кода. Пример: EternalBlue (CVE-2017-0144).</li>
                      <li><strong>Установка:</strong> Закрепление в системе (установка бэкдора). Пример: создание службы в Windows.</li>
                      <li><strong>Управление:</strong> Удалённое управление через C2-сервер. Пример: использование Cobalt Strike.</li>
                      <li><strong>Действия:</strong> Достижение цели (кража данных, шифрование). Пример: запуск шифровальщика WannaCry.</li>
                    </ul>
                    <p><strong>Противодействие:</strong> Блокировать разведку (WAF), проверять вложения (антивирус), обновлять ПО (патчи), мониторить сеть (IDS/IPS).</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">Pyramid of Pain</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> Pyramid of Pain (Пирамида боли) — это модель, предложенная Дэвидом Бьянко, которая классифицирует индикаторы компрометации (IoC) по уровню сложности их изменения для злоумышленника. Чем выше уровень в пирамиде, тем сложнее атакующему адаптироваться, что делает защиту эффективнее.</p>
              <p><strong>Схема уровней Pyramid of Pain:</strong></p>
              <div class="pyramid-pain-diagram" style="margin-bottom: 20px;">
                <div class="pyramid-pain-container" style="display: flex; align-items: stretch; gap: 20px;">
                  <div class="pyramid-pain-levels" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                    <h3>Уровни пирамиды</h3>
                    <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                      <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                        Тактики и методы
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">TTPs</p>
                      </div>
                      <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 190px;">
                        Инструменты
                        <p style="font-size: 12px; margin: 5px 0 0;">Malware</p>
                      </div>
                      <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 180px;">
                        Сетевые артефакты
                        <p style="font-size: 12px; margin: 5px 0 0;">C2</p>
                      </div>
                      <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 170px;">
                        Домены
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">DNS</p>
                      </div>
                      <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 160px;">
                        IP-адреса
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">IPs</p>
                      </div>
                      <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 150px;">
                        Хеш-суммы
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Файлы</p>
                      </div>
                    </div>
                  </div>
                  <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
                  <div style="flex: 1; padding: 15px;">
                    <h3>Описание уровней</h3>
                    <ul>
                      <li><strong>Хеш-суммы:</strong> Уникальные идентификаторы файлов (MD5, SHA). Легко блокируются, но легко меняются. Пример: блокировка WannaCry по хешу.</li>
                      <li><strong>IP-адреса:</strong> Адреса серверов атакующего. Блокировка через фаервол, но IP легко сменить. Пример: блокировка C2-сервера.</li>
                      <li><strong>Домены:</strong> DNS-имена для связи. Сложнее менять, чем IP. Пример: блокировка домена через DNS Sinkhole.</li>
                      <li><strong>Сетевые артефакты:</strong> Протоколы, порты, сигнатуры трафика. Пример: блокировка трафика Cobalt Strike по портам.</li>
                      <li><strong>Инструменты:</strong> Используемые программы (Metasploit). Смена инструмента требует усилий. Пример: обнаружение Mimikatz.</li>
                      <li><strong>Тактики и методы (TTPs):</strong> Поведение атакующего (MITRE ATT&CK). Сложнее всего изменить. Пример: обнаружение фишинга через поведенческий анализ.</li>
                    </ul>
                    <p><strong>Противодействие:</strong> Фокусируйтесь на TTPs (SIEM, EDR), используйте индикаторы нижних уровней как дополнение.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">MITRE ATT&CK</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> MITRE ATT&CK — это база знаний о тактиках, техниках и процедурах (TTPs) кибератак, основанная на реальных инцидентах. Она помогает классифицировать действия злоумышленников и разрабатывать стратегии защиты.</p>
              <p><strong>Подробности:</strong> Для детального описания тактик и техник смотрите специализированный раздел по MITRE ATT&CK в разделе "Уязвимости".</p>
              <p><strong>Противодействие:</strong> Используйте MITRE ATT&CK для настройки EDR (CrowdStrike), анализа инцидентов и обучения персонала.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">Diamond Model</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> Diamond Model (Алмазная модель) — это фреймворк для анализа киберинцидентов, который фокусируется на взаимосвязях между четырьмя элементами: злоумышленник, жертва, инфраструктура и возможности. Она помогает понять контекст атаки и разработать меры реагирования.</p>
              <p><strong>Схема элементов Diamond Model:</strong></p>
              <div class="diamond-model-diagram" style="margin-bottom: 20px;">
                <div class="diamond-model-container" style="display: flex; align-items: stretch; gap: 20px;">
                  <div class="diamond-model-elements" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                    <h3>Элементы модели</h3>
                    <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                      <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                        Злоумышленник
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Attacker</p>
                      </div>
                      <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                        Жертва
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Victim</p>
                      </div>
                      <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                        Инфраструктура
                        <p style="font-size: 12px; margin: 5px 0 0;">Infrastructure</p>
                      </div>
                      <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                        Возможности
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Capabilities</p>
                      </div>
                    </div>
                  </div>
                  <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
                  <div style="flex: 1; padding: 15px;">
                    <h3>Описание элементов</h3>
                    <ul>
                      <li><strong>Злоумышленник:</strong> Кто атакует (группа, одиночка). Пример: APT28.</li>
                      <li><strong>Жертва:</strong> Цель атаки (компания, система). Пример: сервер КИИ.</li>
                      <li><strong>Инфраструктура:</strong> Средства атаки (C2, домены). Пример: арендованный VPS.</li>
                      <li><strong>Возможности:</strong> Инструменты и методы (Malware, TTPs). Пример: использование Mimikatz.</li>
                    </ul>
                    <p><strong>Противодействие:</strong> Анализируйте инциденты через SIEM, блокируйте инфраструктуру (IP/DNS), изучайте TTPs для предотвращения повторных атак.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <h3>Роль нормативных актов</h3>
        <p>В России структурная безопасность регулируется рядом нормативных актов, которые задают стандарты защиты:</p>
        <ul>
          <li><strong>ФЗ-187 "О безопасности КИИ":</strong> Определяет требования к защите критической информационной инфраструктуры, включая категорирование объектов и взаимодействие с ГосСОПКА.</li>
          <li><strong>ФЗ-149 "Об информации":</strong> Устанавливает общие требования к защите информации, включая гостайну.</li>
          <li><strong>ГОСТ Р ИСО/МЭК 27001:</strong> Международный стандарт управления информационной безопасностью, адаптированный для России.</li>
          <li><strong>Приказы ФСТЭК и ФСБ:</strong> Например, Приказ ФСТЭК № 239 для КИИ и Приказ ФСБ № 378 для защиты гостайны.</li>
        </ul>

        <h3>Рекомендации по внедрению структурной безопасности</h3>
        <ol>
          <li><strong>Проведите инвентаризацию активов:</strong> Определите все системы, сети и данные, которые нужно защищать.</li>
          <li><strong>Разработайте политики безопасности:</strong> Установите правила доступа, шифрования и мониторинга.</li>
          <li><strong>Внедрите многоуровневую защиту:</strong> Используйте комбинацию технических и организационных мер.</li>
          <li><strong>Обучайте персонал:</strong> Регулярно проводите тренинги по кибербезопасности.</li>
          <li><strong>Проводите аудиты:</strong> Регулярно проверяйте системы на уязвимости и соответствие требованиям.</li>
        </ol>

        <h3>Заключение</h3>
        <p>Структурная безопасность — это не разовое мероприятие, а непрерывный процесс, который требует постоянного обновления и адаптации к новым угрозам. Использование современных технологий, соблюдение нормативных требований и обучение персонала позволяют создать надёжную защиту для всех компонентов ИТ-инфраструктуры.</p>
      </div>
    </div>
  `;

    document.getElementById('os-security-btn').addEventListener('click', () => {
      loadOSSecurityContent(container);
    });

    document.getElementById('network-security-btn').addEventListener('click', () => {
      loadNetworkSecurityContent(container);
    });

    document.getElementById('auth-security-btn').addEventListener('click', () => {
      loadAuthSecurityContent(container);
    });

    document.getElementById('leak-protection-btn').addEventListener('click', () => {
      loadLeakProtectionContent(container);
    });

    document.querySelector('.state-secrets-btn').addEventListener('click', () => {
      loadStateSecretsContent(container);
    });

    document.getElementById('cii-security-btn').addEventListener('click', () => {
      loadCIISecurityContent(container);
    });

    document.getElementById('ot-security-btn').addEventListener('click', () => {
      loadOTSecurityContent(container);
    });

    document.getElementById('app-security-btn').addEventListener('click', () => {
      loadAppSecurityContent(container);
    });

    document.getElementById('db-security-btn').addEventListener('click', () => {
      loadDBSecurityContent(container);
    });

    document.getElementById('cloud-security-btn').addEventListener('click', () => {
      loadCloudSecurityContent(container);
    });

    document.getElementById('iot-security-btn').addEventListener('click', () => {
      loadIoTSecurityContent(container);
    });

    document.getElementById('microservices-security-btn').addEventListener('click', () => {
      loadMicroservicesSecurityContent(container);
    });

    document.getElementById('mobile-security-btn').addEventListener('click', () => {
      loadMobileSecurityContent(container);
    });
    document.getElementById('api-security-btn').addEventListener('click', () => {
      loadAPISecurityContent(container);
    });
    document.getElementById('container-security-btn').addEventListener('click', () => {
      loadContainersOrchestrationSecurityContent(container);
    });
    document.getElementById('remote-work-security-btn').addEventListener('click', () => {
      loadRemoteWorkSecurityContent(container);
    });

    const accordionHeaders = document.querySelectorAll('.accordion-header');
    accordionHeaders.forEach(header => {
    header.addEventListener('click', () => {
      const content = header.nextElementSibling;
      content.style.display = content.style.display === 'block' ? 'none' : 'block';
    });
  });
  }

  function loadOSSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность ОС</h1>
        <p>Безопасность операционных систем (ОС) включает защиту от уязвимостей, обеспечение контроля доступа, мониторинг активности и предотвращение атак.</p>
  
        <h2>Теоретические основы безопасности ОС</h2>
        <p>Безопасность ОС опирается на фундаментальные принципы компьютерной науки, теории систем и криптографии. Основная цель — минимизировать поверхность атаки, обеспечить устойчивость системы к внешним и внутренним угрозам и гарантировать выполнение трех ключевых свойств: конфиденциальности, целостности и доступности (CIA Triad).</p>
        <ul>
          <li><strong>Изоляция процессов:</strong> Теория разделения адресного пространства, заложенная в 1960-х годах в системах вроде Multics, позволяет изолировать процессы через механизмы виртуальной памяти. Современные ОС (Windows, Linux) используют пространства имен (namespaces) и контроль групп (cgroups) для контейнеризации (например, Docker). Это предотвращает утечки данных между процессами и ограничивает влияние компрометации одного процесса на систему.</li>
          <li><strong>Контроль доступа:</strong> Модели управления доступом, такие как Bell-LaPadula (для конфиденциальности) и Biba (для целостности), легли в основу современных систем, таких как SELinux. Теория ролевого доступа (RBAC) позволяет минимизировать привилегии, а концепция "нулевого доверия" (Zero Trust) требует проверки каждого действия, даже внутри системы.</li>
          <li><strong>Обновления и патчи:</strong> Теория управления уязвимостями (CVSS) помогает приоритизировать исправления. Например, уязвимость EternalBlue (CVE-2017-0144) эксплуатировала SMB и была закрыта патчем MS17-010. Теория временных окон уязвимостей (Time-to-Exploit) показывает, что задержка в обновлениях увеличивает риск (например, WannaCry заразил системы через 2 месяца после выпуска патча).</li>
          <li><strong>Мониторинг:</strong> Основан на теории обнаружения аномалий (Anomaly Detection). Системы EDR и SIEM используют статистические модели, такие как скрытые марковские модели (HMM), и машинное обучение (ML) для выявления угроз. Например, алгоритмы кластеризации (k-means) помогают обнаружить аномальное поведение процессов.</li>
          <li><strong>Криптография:</strong> Шифрование данных (AES-256 в BitLocker) и хеширование паролей (bcrypt, Argon2) опираются на математические основы, такие как односторонние функции и стойкость к коллизиям. Теория стойкости к атакам (например, атакам по сторонним каналам, как Spectre/Meltdown) требует использования защищенных алгоритмов и изоляции на уровне ядра.</li>
          <li><strong>Атаки на ядро:</strong> Теория эксплойтов, таких как буферные переполнения, описана в статье "Smashing the Stack for Fun and Profit" (1996). Современные атаки, такие как Dirty Pipe (CVE-2022-0847), используют ошибки в системных вызовах (syscalls) для повышения привилегий.</li>
          <li><strong>Социальная инженерия:</strong> Теория человеческого фактора (Human-Computer Interaction, HCI) показывает, что пользователи — слабое звено. Фишинг-атаки, такие как WannaCry, эксплуатируют доверие пользователей, обходя технические меры.</li>
        </ul>
        <p>Угрозы возникают из-за нарушения этих принципов:</p>
        <ul>
          <li><strong>Буферные переполнения:</strong> Атака на стек позволяет переписать адрес возврата (return address), что приводит к выполнению вредоносного кода.</li>
          <li><strong>Неправильная конфигурация:</strong> Теория минимальной функциональности (least privilege) часто игнорируется, что приводит к открытым портам или слабым паролям.</li>
          <li><strong>Атаки на учетные записи:</strong> Теория перебора паролей (brute-force) и атаки по словарю эксплуатируют слабые учетные данные.</li>
        </ul>
  
        <h2>Схема уровней защиты ОС</h2>
        <div class="os-security-method" style="margin-bottom: 20px;">
          <div class="os-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="os-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты ОС</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Вход в систему</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  MFA
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аутентификация</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  SELinux/AppArmor
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Контроль доступа</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  ОС (Windows/Linux)
                  <p style="font-size: 12px; margin: 5px 0 0;">Ядро</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  EDR
                  <p style="font-size: 12px; margin: 5px 0 0;">Обнаружение угроз</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обновления
                  <p style="font-size: 12px; margin: 5px 0 0;">Патчи</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Файловая система
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Данные</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  SIEM
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней защиты ОС</h3>
              <p>Многоуровневая защита ОС охватывает все этапы взаимодействия с системой:</p>
              <ul>
                <li><strong>Пользователь:</strong> Требуется надежная аутентификация для входа.</li>
                <li><strong>MFA:</strong> Усиливает защиту учетных данных (например, TOTP).</li>
                <li><strong>SELinux/AppArmor:</strong> Ограничивает действия процессов по политикам.</li>
                <li><strong>ОС:</strong> Ядро изолирует процессы и управляет ресурсами.</li>
                <li><strong>EDR:</strong> Обнаруживает угрозы в реальном времени.</li>
                <li><strong>Обновления:</strong> Закрывают уязвимости ядра и служб.</li>
                <li><strong>Файловая система:</strong> Защищает данные через права и шифрование.</li>
                <li><strong>SIEM:</strong> Анализирует логи для долгосрочной защиты.</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Меры защиты ОС</h2>
        <div class="os-security-measures" style="margin-bottom: 20px;">
          <div class="os-security-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="os-security-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Меры защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Обновления
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Патчи</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Учетные записи
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Ограничения</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Контроль доступа
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ACL</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                  Отключение служб
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Порты</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Аудит</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                  Антивирус/EDR
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">Защита</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание мер защиты ОС</h3>
              <p>Эти меры обеспечивают комплексную защиту ОС:</p>
              <ul>
                <li><strong>Обновления:</strong> Устраняют уязвимости (например, PrintNightmare, CVE-2021-34527). Рекомендация: автоматизация через WSUS или yum.</li>
                <li><strong>Учетные записи:</strong> Ограничивают привилегии (отключение Guest, MFA). Рекомендация: внедрить политики паролей.</li>
                <li><strong>Контроль доступа:</strong> Настройка прав (chmod 600 /etc/shadow). Рекомендация: использовать SELinux/AppArmor.</li>
                <li><strong>Отключение служб:</strong> Уменьшение поверхности атаки (отключение SMBv1). Рекомендация: проверять порты через netstat.</li>
                <li><strong>Мониторинг:</strong> Обнаружение угроз (Windows Event Log, syslog). Рекомендация: использовать SIEM (Splunk).</li>
                <li><strong>Антивирус/EDR:</strong> Защита от вредоносного ПО (CrowdStrike). Рекомендация: регулярные проверки и обновления.</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Рекомендации по защите ОС</h2>
        <ol>
          <li>Автоматизируйте обновления и следите за CVE.</li>
          <li>Внедрите MFA и строгие политики паролей.</li>
          <li>Настройте SELinux/AppArmor и права доступа.</li>
          <li>Отключите ненужные службы и порты.</li>
          <li>Используйте SIEM и EDR для мониторинга.</li>
        </ol>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadNetworkSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность сетей</h1>
        <p>Безопасность сетей включает защиту инфраструктуры, данных и трафика от атак, а также обеспечение их конфиденциальности и доступности.</p>
  
        <h2>Теоретические основы безопасности сетей</h2>
        <p>Безопасность сетей опирается на модель OSI, теорию графов, криптографию и теорию системного анализа. Основная цель — защитить каждый уровень сетевого стека, минимизировать риски компрометации и обеспечить отказоустойчивость системы.</p>
        <ul>
          <li><strong>Модель OSI:</strong> Каждый уровень (L1-L7) имеет свои угрозы и методы защиты. Например, L2 подвержен ARP-спуфингу, а L7 — SQL-инъекциям. Теория многоуровневой защиты (Defense-in-Depth) требует применения мер на каждом уровне, от физического (L1) до прикладного (L7).</li>
          <li><strong>Теория графов:</strong> Сети моделируются как направленные графы, где узлы — устройства, а ребра — связи. Алгоритмы маршрутизации (Dijkstra, OSPF) оптимизируют пути, но уязвимы к атакам, таким как BGP-hijacking, где злоумышленник перенаправляет трафик, изменяя граф маршрутов.</li>
          <li><strong>Криптография:</strong> Шифрование (RSA, ECC в TLS) и цифровые подписи (SHA-256) защищают данные. Теория стойкости к атакам MitM опирается на протоколы Диффи-Хеллмана для безопасного обмена ключами. Современные атаки, такие как Logjam (2015), эксплуатируют слабые параметры Диффи-Хеллмана.</li>
          <li><strong>Обнаружение аномалий:</strong> IDS/IPS используют байесовский анализ, скрытые марковские модели (HMM) и машинное обучение (ML) для выявления DDoS или спуфинга. Например, алгоритмы SVM (Support Vector Machines) помогают классифицировать трафик как нормальный или аномальный.</li>
          <li><strong>Теория отказоустойчивости:</strong> Принципы резервирования (HAProxy) и распределенных систем (CDN) минимизируют последствия атак. Теория очередей (M/M/1) объясняет, как DDoS перегружает серверы, нарушая доступность.</li>
          <li><strong>Теория игр:</strong> Используется для моделирования поведения атакующих и защитников. Например, злоумышленник выбирает стратегию (DDoS, MitM), а защитник — контрмеры (WAF, IPsec). Оптимальная стратегия определяется через равновесие Нэша.</li>
          <li><strong>Сетевые протоколы:</strong> Теория конечных автоматов (Finite State Machines) лежит в основе протоколов, таких как TCP. Уязвимости, такие как SYN-флуд, эксплуатируют состояния автомата, вызывая отказ в обслуживании.</li>
          <li><strong>Социальные атаки:</strong> Теория социальной инженерии (например, модель MITRE ATT&CK) показывает, как фишинг или поддельные точки доступа Wi-Fi (Evil Twin) обходят технические меры.</li>
        </ul>
        <p>Типичные угрозы связаны с нарушением этих принципов:</p>
        <ul>
          <li><strong>DDoS:</strong> Нарушение доступности через перегрузку (атака на Dyn, 2016).</li>
          <li><strong>MitM:</strong> Перехват трафика из-за слабого шифрования (POODLE, 2014).</li>
          <li><strong>Спуфинг:</strong> Подмена адресов (ARP Poisoning).</li>
          <li><strong>Уязвимости оборудования:</strong> Эксплуатация багов (CVE-2023-20198 в Cisco).</li>
        </ul>
  
        <h2>Схема уровней защиты сети</h2>
        <div class="network-security-method" style="margin-bottom: 20px;">
          <div class="network-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="network-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты сети</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Интернет
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Внешний трафик</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  WAF
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Защита от DDoS</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Брандмауэр
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ACL, фильтрация</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  DMZ
                  <p style="font-size: 12px; margin: 5px 0 0;">Публичные сервисы</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  IDS/IPS
                  <p style="font-size: 12px; margin: 5px 0 0;">Обнаружение атак</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Внутренняя сеть
                  <p style="font-size: 12px; margin: 5px 0 0;">VLAN</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  IPsec
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шифрование</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  SIEM
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней защиты сети</h3>
              <p>Многоуровневая защита сети охватывает весь путь трафика:</p>
              <ul>
                <li><strong>Интернет:</strong> Внешний трафик, уязвимый к DDoS.</li>
                <li><strong>WAF:</strong> Фильтрует атаки L7 (Cloudflare).</li>
                <li><strong>Брандмауэр:</strong> Ограничивает доступ (Cisco ASA).</li>
                <li><strong>DMZ:</strong> Изолирует публичные сервисы.</li>
                <li><strong>IDS/IPS:</strong> Обнаруживает и блокирует угрозы (Snort).</li>
                <li><strong>Внутренняя сеть:</strong> Сегментирована через VLAN.</li>
                <li><strong>IPsec:</strong> Шифрует трафик (VPN).</li>
                <li><strong>SIEM:</strong> Анализирует события (ELK).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Меры защиты сетей</h2>
        <div class="network-security-measures" style="margin-bottom: 20px;">
          <div class="network-security-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="network-security-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Меры защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сегментация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">VLAN</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Шифрование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">TLS/IPsec</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Фильтрация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ACL</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                  Обнаружение
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">IDS/IPS</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word; color: #000;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #000;">SIEM</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание мер защиты сетей</h3>
              <p>Эти меры обеспечивают комплексную защиту сетей:</p>
              <ul>
                <li><strong>Сегментация:</strong> Ограничивает распространение угроз (VLAN).</li>
                <li><strong>Шифрование:</strong> Защищает данные (TLS, IPsec).</li>
                <li><strong>Фильтрация:</strong> Ограничивает доступ (iptables).</li>
                <li><strong>Обнаружение:</strong> Выявляет атаки (Suricata).</li>
                <li><strong>Мониторинг:</strong> Анализирует события (Splunk).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Протоколы безопасности</h2>
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-header">Internet Key Exchange (IKE)</button>
            <div class="accordion-content" style="display: none;">
              <p><strong>Описание:</strong> Internet Key Exchange (IKE) — это протокол, используемый для установления защищённых соединений в IPsec (Internet Protocol Security). Он отвечает за аутентификацию сторон, согласование криптографических параметров и создание ключей для шифрования и целостности данных. IKE работает в двух версиях: IKEv1 (RFC 2409, 1998) и IKEv2 (RFC 7296, 2005), причём IKEv2 более современен, эффективен и устойчив к атакам.</p>
              
              <h3>Основные принципы IKE</h3>
              <ul>
                <li><strong>Аутентификация:</strong> Подтверждение идентичности участников через предварительно общие ключи (PSK), цифровые подписи (RSA, ECDSA) или сертификаты (X.509).</li>
                <li><strong>Обмен ключами:</strong> Использование алгоритма Диффи-Хеллмана (DH) или эллиптических кривых (ECDH) для создания общего секретного ключа.</li>
                <li><strong>Создание SA:</strong> Установление Security Associations (SA) — набора параметров для шифрования и аутентификации трафика в IPsec.</li>
                <li><strong>Защита от атак:</strong> IKEv2 включает защиту от DoS (например, через "cookie"-механизм) и перехвата (MitM).</li>
              </ul>
  
              <h3>Этапы работы IKEv2</h3>
              <p>IKEv2 делится на две основные фазы:</p>
              <div class="ike-phases" style="margin-bottom: 20px;">
                <div class="ike-phases-container" style="display: flex; align-items: stretch; gap: 20px;">
                  <div class="ike-phases-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                    <h3>Фазы IKEv2</h3>
                    <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                      <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                        IKE_SA_INIT
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Обмен ключами</p>
                      </div>
                      <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                        IKE_AUTH
                        <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аутентификация</p>
                      </div>
                      <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                        CHILD_SA
                        <p style="font-size: 12px; margin: 5px 0 0;">Ключи IPsec</p>
                      </div>
                    </div>
                  </div>
                  <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
                  <div style="flex: 1; padding: 15px;">
                    <h3>Описание фаз</h3>
                    <ul>
                      <li><strong>IKE_SA_INIT:</strong> Инициатор и респондент обмениваются сообщениями для согласования алгоритмов (AES, SHA) и создания общего ключа через Диффи-Хеллмана. Устанавливается IKE SA (Security Association).</li>
                      <li><strong>IKE_AUTH:</strong> Происходит аутентификация сторон (PSK, сертификаты) и настройка защищённого канала. Подтверждается целостность сообщений через HMAC.</li>
                      <li><strong>CHILD_SA:</strong> Создаются дополнительные SA для IPsec (ESP или AH), определяются ключи и параметры шифрования трафика.</li>
                    </ul>
                  </div>
                </div>
              </div>
  
              <h3>Преимущества IKEv2</h3>
              <ul>
                <li>Быстрое восстановление соединения (MOBIKE для мобильных устройств).</li>
                <li>Устойчивость к DoS (механизм "cookie").</li>
                <li>Поддержка NAT-T (Network Address Translation Traversal).</li>
                <li>Меньшее количество сообщений по сравнению с IKEv1.</li>
              </ul>
  
              <h3>Уязвимости и противодействие</h3>
              <ul>
                <li><strong>Слабые ключи DH:</strong> Атака Logjam (2015) показала, что слабые параметры DH (группы 512/1024 бит) уязвимы. Рекомендация: использовать DH группы 2048 бит или ECDH.</li>
                <li><strong>MitM:</strong> Возможен при слабой аутентификации (PSK). Рекомендация: использовать сертификаты X.509.</li>
                <li><strong>DoS:</strong> Перегрузка инициации SA. Рекомендация: включить "cookie" в IKEv2.</li>
              </ul>
  
              <h3>Применение</h3>
              <p>IKE используется в VPN (например, Cisco AnyConnect, StrongSwan), защищённых сетях КИИ и удалённом доступе. В России применяется в продуктах, сертифицированных ФСБ (например, ViPNet).</p>
  
              <h3>Рекомендации</h3>
              <ul>
                <li>Используйте IKEv2 вместо IKEv1.</li>
                <li>Настройте сильные алгоритмы: AES-256, SHA-256, DH Group 14+ или ECDH.</li>
                <li>Применяйте сертификаты для аутентификации.</li>
                <li>Включите NAT-T для работы через NAT.</li>
                <li>Мониторьте IKE-логи через SIEM для выявления аномалий.</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });

    const accordionHeaders = document.querySelectorAll('.accordion-header');
    accordionHeaders.forEach(header => {
      header.addEventListener('click', () => {
        const content = header.nextElementSibling;
        content.style.display = content.style.display === 'block' ? 'none' : 'block';
      });
    });
  }

  function loadAuthSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Аутентификация и авторизация</h1>
        <p>Аутентификация и авторизация — ключевые процессы обеспечения безопасности, позволяющие подтвердить подлинность пользователей и устройств, а также управлять их доступом к ресурсам.</p>

        <h2>Теоретические основы</h2>
        <p>Безопасность аутентификации и авторизации опирается на криптографию, теорию управления доступом и модели безопасности. Основная цель — гарантировать, что только легитимные пользователи и процессы получают доступ к данным и системам.</p>
        <ul>
          <li><strong>Аутентификация:</strong> Подтверждение личности через пароли, токены или биометрию.</li>
          <li><strong>Авторизация:</strong> Определение прав доступа на основе ролей или атрибутов.</li>
          <li><strong>Криптография:</strong> Использование хеш-функций (SHA-256) и шифрования (RSA) для защиты данных.</li>
        </ul>

        <h2>Схема уровней аутентификации и авторизации</h2>
        <div class="auth-security-method" style="margin-bottom: 20px;">
          <div class="auth-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="auth-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Вход</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  Пароль
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Однофакторная</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  MFA
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Многофакторная</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Токены
                  <p style="font-size: 12px; margin: 5px 0 0;">JWT/OAuth</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  RBAC
                  <p style="font-size: 12px; margin: 5px 0 0;">Роли</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  ABAC
                  <p style="font-size: 12px; margin: 5px 0 0;">Атрибуты</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Логи</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней</h3>
              <p>Многоуровневый подход к аутентификации и авторизации:</p>
              <ul>
                <li><strong>Пользователь:</strong> Инициирует вход в систему.</li>
                <li><strong>Пароль:</strong> Базовая однофакторная аутентификация.</li>
                <li><strong>MFA:</strong> Усиливает защиту вторым фактором (TOTP).</li>
                <li><strong>Токены:</strong> Используются для программного доступа (JWT).</li>
                <li><strong>RBAC:</strong> Управление доступом по ролям.</li>
                <li><strong>ABAC:</strong> Более гибкое управление по атрибутам.</li>
                <li><strong>Мониторинг:</strong> Отслеживание попыток доступа.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Меры защиты</h2>
        <div class="auth-security-measures" style="margin-bottom: 20px;">
          <div class="auth-security-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="auth-security-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Меры защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Сложные пароли
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Политики</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  MFA
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">2FA/TOTP</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Токены
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">JWT</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  RBAC/ABAC
                  <p style="font-size: 12px; margin: 5px 0 0;">Контроль</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Шифрование
                  <p style="font-size: 12px; margin: 5px 0 0;">Хеши</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0;">SIEM</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание мер защиты</h3>
              <p>Комплексный подход к защите:</p>
              <ul>
                <li><strong>Сложные пароли:</strong> Минимум 12 символов, с цифрами и спецсимволами.</li>
                <li><strong>MFA:</strong> Добавление второго фактора (SMS, TOTP).</li>
                <li><strong>Токены:</strong> Использование JWT/OAuth для API.</li>
                <li><strong>RBAC/ABAC:</strong> Ограничение доступа по ролям или атрибутам.</li>
                <li><strong>Шифрование:</strong> Хеширование паролей (bcrypt).</li>
                <li><strong>Мониторинг:</strong> Логирование и анализ (Splunk).</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Рекомендации</h2>
        <ol>
          <li>Внедрите политики сложных паролей.</li>
          <li>Обязательно используйте MFA.</li>
          <li>Применяйте токены для API-доступа.</li>
          <li>Настройте RBAC или ABAC.</li>
          <li>Шифруйте учетные данные.</li>
          <li>Мониторьте попытки входа.</li>
        </ol>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }
  
  function loadLeakProtectionContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Защита от утечек</h1>
        <p>Защита от утечек включает меры по предотвращению несанкционированного раскрытия информации через технические, физические и электронные каналы.</p>

        <h2>Каналы утечек</h2>
        <div class="leak-channels-method" style="margin-bottom: 20px;">
          <div class="leak-channels-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="leak-channels-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Каналы утечек</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Акустический
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Звук</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  Электромагнитный
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ПЭМИН</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Электронный
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Данные</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Оптический
                  <p style="font-size: 12px; margin: 5px 0 0;">Свет</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Физический
                  <p style="font-size: 12px; margin: 5px 0 0;">Носители</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание каналов</h3>
              <p>Возможные пути утечки информации:</p>
              <ul>
                <li><strong>Акустический:</strong> Перехват звука через микрофоны или лазеры.</li>
                <li><strong>Электромагнитный:</strong> Снятие излучений (ПЭМИН) от оборудования.</li>
                <li><strong>Электронный:</strong> Утечка через сети или ПО.</li>
                <li><strong>Оптический:</strong> Визуальный перехват (камеры, окна).</li>
                <li><strong>Физический:</strong> Утечка через носители (USB, бумага).</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Схема защиты от утечек</h2>
        <div class="leak-protection-method" style="margin-bottom: 20px;">
          <div class="leak-protection-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="leak-protection-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Схема защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Внешний периметр
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Контроль доступа</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  Видеонаблюдение
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  Защитные плёнки
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Оптика</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Экранированное помещение
                  <p style="font-size: 12px; margin: 5px 0 0;">ПЭМИН</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Шумогенераторы
                  <p style="font-size: 12px; margin: 5px 0 0;">Акустика</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Защищённые устройства
                  <p style="font-size: 12px; margin: 5px 0 0;">Оборудование</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                  Фильтры питания
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Электромагнит</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  DLP
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание схемы</h3>
              <p>Многоуровневая защита от утечек:</p>
              <ul>
                <li><strong>Внешний периметр:</strong> Защита от физического доступа.</li>
                <li><strong>Видеонаблюдение:</strong> Контроль территории.</li>
                <li><strong>Защитные плёнки:</strong> Предотвращение визуального перехвата.</li>
                <li><strong>Экранированное помещение:</strong> Блокировка ПЭМИН.</li>
                <li><strong>Шумогенераторы:</strong> Защита от акустических утечек.</li>
                <li><strong>Защищённые устройства:</strong> Сертифицированное оборудование.</li>
                <li><strong>Фильтры питания:</strong> Подавление электромагнитных наводок.</li>
                <li><strong>DLP:</strong> Мониторинг электронных утечек.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Методы защиты</h2>
        <div class="leak-protection-measures" style="margin-bottom: 20px;">
          <div class="leak-protection-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="leak-protection-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Методы защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Шумогенераторы
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Акустика</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  Экранирование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ПЭМИН</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  DLP-системы
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Электронные</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Защитные плёнки
                  <p style="font-size: 12px; margin: 5px 0 0;">Оптика</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Контроль носителей
                  <p style="font-size: 12px; margin: 5px 0 0;">Физические</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание методов</h3>
              <p>Комплекс мер для защиты:</p>
              <ul>
                <li><strong>Шумогенераторы:</strong> Маскировка звука.</li>
                <li><strong>Экранирование:</strong> Блокировка электромагнитных излучений.</li>
                <li><strong>DLP-системы:</strong> Контроль передачи данных.</li>
                <li><strong>Защитные плёнки:</strong> Предотвращение визуального перехвата.</li>
                <li><strong>Контроль носителей:</strong> Ограничение USB и бумаги.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Рекомендации</h2>
        <ol>
          <li>Аттестуйте помещения на утечки.</li>
          <li>Используйте экранирование и шумогенераторы.</li>
          <li>Внедрите DLP-системы.</li>
          <li>Установите защитные плёнки на окна.</li>
          <li>Контролируйте физические носители.</li>
        </ol>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadStateSecretsContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Защита гостайны</h1>
        <p>Государственная тайна (гостайна) — это сведения, разглашение которых может нанести ущерб безопасности Российской Федерации. Защита гостайны требует строгого соблюдения нормативных требований, включая аттестацию персональных компьютеров (ПК) и других объектов информатизации, которые используются для обработки таких сведений. В России защита гостайны регулируется федеральными законами, приказами ФСТЭК, ФСБ и другими нормативными актами.</p>

        <h2>Основные принципы защиты гостайны</h2>
        <div class="state-secrets-principles" style="margin-bottom: 20px;">
          <div class="state-secrets-principles-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="state-secrets-principles-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Принципы защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Классификация информации
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Грифы</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  Физическая безопасность
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Охрана</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Шифрование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">ГОСТ</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Контроль доступа
                  <p style="font-size: 12px; margin: 5px 0 0;">MFA</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Сегментация сети
                  <p style="font-size: 12px; margin: 5px 0 0;">Air-gap</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Мониторинг и аудит
                  <p style="font-size: 12px; margin: 5px 0 0;">DLP</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Соответствие требованиям
                  <p style="font-size: 12px; margin: 5px 0 0;">ФЗ-149</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание принципов</h3>
              <p>Основные аспекты защиты гостайны:</p>
              <ul>
                <li><strong>Классификация информации:</strong> Присвоение грифов ("секретно", "совершенно секретно").</li>
                <li><strong>Физическая безопасность:</strong> Ограничение доступа (сейфы, видеонаблюдение).</li>
                <li><strong>Шифрование:</strong> Использование ГОСТ 28147-89 для защиты данных.</li>
                <li><strong>Контроль доступа:</strong> MFA и допуск сотрудников.</li>
                <li><strong>Сегментация сети:</strong> Изоляция с помощью air-gap.</li>
                <li><strong>Мониторинг и аудит:</strong> Логирование и DLP-системы.</li>
                <li><strong>Соответствие требованиям:</strong> Соблюдение ФЗ-149 и приказов ФСБ.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Аттестация ПК для обработки гостайны</h2>
        <p>Аттестация персональных компьютеров (ПК) и других объектов информатизации, используемых для обработки гостайны, является обязательной процедурой в России. Она проводится для подтверждения соответствия требованиям безопасности информации, установленным нормативными актами. Вот основные этапы и требования:</p>
        <ul>
          <li><strong>Нормативная база:</strong> Аттестация проводится в соответствии с Федеральным законом № 149-ФЗ "Об информации, информационных технологиях и о защите информации", а также приказами ФСТЭК и ФСБ. Например, Приказ ФСТЭК России № 77 от 29 апреля 2021 года устанавливает порядок аттестации объектов информатизации, хотя он в основном касается информации, не составляющей гостайну. Для гостайны применяются более строгие требования, часто основанные на ГОСТ Р 0043-003-2012 и внутренних инструкциях ФСБ.</li>
          <li><strong>Лицензирование:</strong> Аттестацию могут проводить только организации, имеющие лицензии ФСБ на работу с гостайной и лицензии ФСТЭК на техническую защиту информации. Например, такие компании, как ГК "ЦИБИТ", предлагают услуги по аттестации ПК и помещений.</li>
          <li><strong>Этапы аттестации:</strong>
            <ol>
              <li><strong>Обследование:</strong> Проводится анализ ПК, его программного и аппаратного обеспечения, а также условий эксплуатации (например, помещения, где он находится).</li>
              <li><strong>Модель угроз:</strong> Разрабатывается модель угроз, учитывающая возможные риски (например, утечка по техническим каналам, несанкционированный доступ).</li>
              <li><strong>Тестирование:</strong> Проверяется устойчивость ПК к атакам, включая тестирование на проникновение (penetration testing) и проверку на наличие недекларированных возможностей в ПО.</li>
              <li><strong>Установка средств защиты:</strong> На ПК устанавливаются сертифицированные средства защиты, такие как антивирусы (например, Kaspersky с сертификатом ФСБ), межсетевые экраны и криптографическое ПО (например, "КриптоПро" с ГОСТ-шифрованием).</li>
              <li><strong>Документация:</strong> Составляются аттестационные документы, включая программу и методику испытаний, протоколы испытаний и аттестат соответствия.</li>
              <li><strong>Контроль:</strong> После аттестации проводится регулярный контроль (не реже одного раза в год), чтобы убедиться, что ПК продолжает соответствовать требованиям.</li>
            </ol>
          </li>
          <li><strong>Требования к ПК:</strong> ПК должен быть изолирован от интернета, использовать сертифицированное ПО и оборудование, а также иметь средства защиты от утечек по техническим каналам (например, защита от электромагнитного излучения). Все носители информации (например, жёсткие диски) должны быть учтены и защищены.</li>
          <li><strong>Срок действия аттестата:</strong> Для объектов, обрабатывающих гостайну, срок действия аттестата обычно составляет не более 3 лет, после чего требуется переаттестация.</li>
        </ul>

        <h2>Сегментация сети для защиты гостайны</h2>
        <p>Сегментация сети при работе с гостайной направлена на полную изоляцию систем, обрабатывающих секретные данные, от внешнего мира.</p>
        <div class="state-secrets-diagram" style="margin-bottom: 20px;">
          <div class="state-secrets-diagram-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="state-secrets-diagram-content" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Схема сегментации</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Внешний периметр
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Интернет</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  Брандмауэр
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изоляция</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  IPsec
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шифрование</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Изолированная сеть
                  <p style="font-size: 12px; margin: 5px 0 0;">Гостайна</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Защищённые ПК
                  <p style="font-size: 12px; margin: 5px 0 0;">Аттестация</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  DLP
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание схемы</h3>
              <p>Многоуровневая сегментация сети:</p>
              <ul>
                <li><strong>Внешний периметр:</strong> Зона взаимодействия с интернетом.</li>
                <li><strong>Брандмауэр:</strong> Фильтрация трафика для изоляции.</li>
                <li><strong>IPsec:</strong> Шифрование каналов связи (ГОСТ).</li>
                <li><strong>Изолированная сеть:</strong> Полная изоляция систем с гостайной.</li>
                <li><strong>Защищённые ПК:</strong> Аттестованные устройства.</li>
                <li><strong>DLP:</strong> Мониторинг утечек данных.</li>
              </ul>
            </div>
          </div>
        </div>
        <p>Для защиты от утечек по техническим каналам (например, через электромагнитное излучение) помещения, где находятся ПК, должны быть экранированы, а оборудование — сертифицировано на отсутствие побочных излучений.</p>

        <h2>Нормативные документы по защите гостайны в России</h2>
        <p>Защита гостайны в России регулируется рядом нормативных актов, включая федеральные законы, указы Президента, постановления Правительства, приказы ФСТЭК и ФСБ. Вот основные документы:</p>
        <ul>
          <li><strong>Федеральный закон № 5485-1 от 21 июля 1993 года "О государственной тайне":</strong> Основной закон, определяющий, что такое гостайна, порядок её защиты, ответственность за разглашение и допуск к работе с секретными сведениями.</li>
          <li><strong>Федеральный закон № 149-ФЗ от 27 июля 2006 года "Об информации, информационных технологиях и о защите информации":</strong> Устанавливает общие требования к защите информации, включая гостайну.</li>
          <li><strong>Указ Президента РФ № 1203 от 30 ноября 1995 года "Об утверждении перечня сведений, отнесённых к государственной тайне":</strong> Определяет, какие сведения относятся к гостайне (например, военные, экономические, научно-технические данные).</li>
          <li><strong>Постановление Правительства РФ № 1233 от 3 октября 2015 года "Об утверждении требований к защите сведений, составляющих государственную тайну":</strong> Устанавливает требования к защите гостайны, включая технические и организационные меры.</li>
          <li><strong>Приказ ФСБ России № 378 от 10 июля 2014 года:</strong> Утверждает меры по обеспечению безопасности информации с использованием средств криптографической защиты (СКЗИ).</li>
          <li><strong>Приказ ФСБ России № 66 от 9 февраля 2005 года "Об утверждении Положения о разработке, производстве, реализации и эксплуатации шифровальных средств (Положение ПКЗ-2005)":</strong> Регулирует использование криптографических средств для защиты гостайны.</li>
          <li><strong>ГОСТ Р 0043-003-2012 "Защита информации. Аттестация объектов информатизации":</strong> Устанавливает общие положения для аттестации объектов, включая ПК, обрабатывающие гостайну.</li>
        </ul>
        <p>Эти документы обязывают организации, работающие с гостайной, проводить аттестацию, использовать сертифицированные средства защиты и регулярно отчитываться перед ФСБ о состоянии безопасности.</p>

        <h2>Средства защиты гостайны</h2>
        <ul>
          <li><strong>Криптографические средства:</strong> Используйте сертифицированные решения, такие как "КриптоПро CSP" с ГОСТ-шифрованием, для защиты данных.</li>
          <li><strong>Антивирусы:</strong> Установите антивирусы, сертифицированные ФСБ и ФСТЭК, например, Kaspersky Endpoint Security, который соответствует требованиям для защиты гостайны.</li>
          <li><strong>Межсетевые экраны:</strong> Применяйте сертифицированные межсетевые экраны (например, Cisco ASA с сертификатом ФСБ) для защиты изолированных сетей.</li>
          <li><strong>SIEM:</strong> Используйте системы управления событиями и информационной безопасностью (например, QRadar) для мониторинга и регистрации событий.</li>
          <li><strong>DLP:</strong> Внедрите системы предотвращения утечек данных (например, InfoWatch) для защиты от несанкционированного копирования гостайны.</li>
          <li><strong>Экранирование:</strong> Используйте экранированные помещения и оборудование для защиты от утечек по техническим каналам.</li>
          <li><strong>Физическая защита:</strong> Установите сейфы, замки и системы видеонаблюдения для ограничения физического доступа.</li>
        </ul>

        <h2>Рекомендации по защите гостайны</h2>
        <ol>
          <li><strong>Допуск персонала:</strong> Убедитесь, что все сотрудники, работающие с гостайной, имеют соответствующий допуск (например, форма 1, 2 или 3) и прошли инструктаж.</li>
          <li><strong>Изоляция систем:</strong> Полностью изолируйте ПК и сети, обрабатывающие гостайну, от интернета и других внешних сетей.</li>
          <li><strong>Сертификация:</strong> Используйте только сертифицированные ФСБ и ФСТЭК средства защиты (например, антивирусы, криптографическое ПО).</li>
          <li><strong>Регулярный контроль:</strong> Проводите ежегодные проверки аттестованных объектов, чтобы убедиться в их соответствии требованиям.</li>
          <li><strong>Обучение:</strong> Регулярно обучайте персонал правилам работы с гостайной и мерам реагирования на инциденты.</li>
          <li><strong>Учёт носителей:</strong> Ведите строгий учёт всех носителей информации (жёсткие диски, USB-накопители), содержащих гостайну, и храните их в сейфах.</li>
          <li><strong>Взаимодействие с ФСБ:</strong> Своевременно информируйте ФСБ о любых инцидентах, связанных с гостайной, и сотрудничайте с органами безопасности.</li>
        </ol>

        <h2>Пример инцидента с гостайной</h2>
        <p>В 2016 году в России был зафиксирован случай утечки гостайны из-за несоблюдения требований к защите. Сотрудник одной из организаций, имеющий допуск к гостайне, использовал личный USB-накопитель для копирования секретных данных. Накопитель был заражён вредоносным ПО, что привело к утечке информации. Этот инцидент подчёркивает важность строгого контроля носителей, изоляции систем и обучения персонала.</p>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadCIISecurityContent(container) {
  container.innerHTML = `
    <div class="structure-security-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Безопасность КИИ</h1>
      <p>Критическая информационная инфраструктура (КИИ) включает системы, сети и объекты, которые обеспечивают функционирование ключевых отраслей (энергетика, транспорт, здравоохранение и т.д.). Нарушение работы КИИ может привести к серьёзным последствиям для экономики, безопасности и общества. В России защита КИИ регулируется Федеральным законом № 187-ФЗ "О безопасности критической информационной инфраструктуры". Безопасность КИИ требует комплексного подхода, включая сегментацию, мониторинг, соответствие нормативным требованиям и защиту от кибератак.</p>

      <h2>Основные принципы защиты КИИ</h2>
      <div class="cii-security-principles" style="margin-bottom: 20px;">
        <div class="cii-security-principles-container" style="display: flex; align-items: stretch; gap: 20px;">
          <div class="cii-security-principles-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Принципы защиты</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                Идентификация объектов КИИ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Категорирование</p>
              </div>
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                Сегментация сети
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изоляция</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                Контроль доступа
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">MFA</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0;">TLS</p>
              </div>
              <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                Мониторинг и реагирование
                <p style="font-size: 12px; margin: 5px 0 0;">SIEM</p>
              </div>
              <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                Соответствие требованиям
                <p style="font-size: 12px; margin: 5px 0 0;">187-ФЗ</p>
              </div>
              <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                Обучение персонала
                <p style="font-size: 12px; margin: 5px 0 0;">Тренинги</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>Описание принципов</h3>
            <p>Основные аспекты защиты КИИ:</p>
            <ul>
              <li><strong>Идентификация объектов КИИ:</strong> Категорирование объектов (SCADA).</li>
              <li><strong>Сегментация сети:</strong> Изоляция с помощью VPN.</li>
              <li><strong>Контроль доступа:</strong> MFA и RBAC (802.1X).</li>
              <li><strong>Шифрование:</strong> Использование TLS, IPsec, ГОСТ.</li>
              <li><strong>Мониторинг и реагирование:</strong> SIEM и SOC.</li>
              <li><strong>Соответствие требованиям:</strong> Соблюдение 187-ФЗ.</li>
              <li><strong>Обучение персонала:</strong> Тренинги по фишингу.</li>
            </ul>
          </div>
        </div>
      </div>

      <h2>Сегментация сети КИИ</h2>
      <p>Сегментация сети КИИ — это ключевой метод защиты, который позволяет изолировать критические системы от внешних угроз.</p>
      <div class="cii-security-diagram" style="margin-bottom: 20px;">
        <div class="cii-security-diagram-container" style="display: flex; align-items: stretch; gap: 20px;">
          <div class="cii-security-diagram-content" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Схема сегментации</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                Внешняя сеть
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Интернет</p>
              </div>
              <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                WAF
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Защита от атак</p>
              </div>
              <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                Периметр (DMZ)
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шлюзы</p>
              </div>
              <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                Внутренняя сеть КИИ
                <p style="font-size: 12px; margin: 5px 0 0;">Серверы</p>
              </div>
              <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                RBAC
                <p style="font-size: 12px; margin: 5px 0 0;">Контроль доступа</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                SIEM
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>Описание схемы</h3>
            <p>Многоуровневая сегментация сети КИИ:</p>
            <ul>
              <li><strong>Внешняя сеть:</strong> Зона с доступом из интернета.</li>
              <li><strong>WAF:</strong> Защита от веб-атак.</li>
              <li><strong>Периметр (DMZ):</strong> Шлюзы и прокси-серверы.</li>
              <li><strong>Внутренняя сеть КИИ:</strong> Изолированные серверы.</li>
              <li><strong>RBAC:</strong> Ролевой контроль доступа.</li>
              <li><strong>SIEM:</strong> Мониторинг и анализ логов.</li>
            </ul>
          </div>
        </div>
      </div>
      <p>Между зонами устанавливаются межсетевые экраны (firewalls) и системы предотвращения вторжений (IPS) для фильтрации трафика и защиты от атак. Например, доступ из внешней сети в DMZ может быть разрешён только для определённых портов (например, HTTPS), а из DMZ во внутреннюю сеть — только для авторизованных пользователей через VPN. Также важно настроить мониторинг трафика с помощью систем анализа (например, NetFlow), чтобы выявлять аномалии, такие как необычно высокий объём запросов, который может указывать на DDoS-атаку.</p>

      <h2>Российская документация по защите КИИ</h2>
      <p>Защита КИИ в России регулируется рядом нормативных актов, включая федеральные законы, указы Президента, постановления Правительства, а также приказы ФСТЭК и ФСБ. Вот основные документы, которые определяют требования к безопасности КИИ:</p>
      <ul>
        <li><strong>Федеральный закон № 187-ФЗ от 26 июля 2017 года "О безопасности критической информационной инфраструктуры Российской Федерации":</strong> Основной закон, который устанавливает правовые основы защиты КИИ. Закон определяет понятие КИИ, обязанности субъектов КИИ (например, категорирование объектов, обеспечение безопасности), а также роль государства в координации защиты (через ГосСОПКА).</li>
        <li><strong>Указ Президента РФ № 250 от 1 мая 2022 года "О дополнительных мерах по обеспечению информационной безопасности Российской Федерации":</strong> Указ вводит дополнительные меры для защиты КИИ, включая обязательство использовать российское ПО и оборудование на значимых объектах КИИ, а также привлекать лицензированные организации для оценки защищённости.</li>
        <li><strong>Указ Президента РФ № 166 от 30 марта 2022 года "О мерах по обеспечению технологической независимости и безопасности КИИ":</strong> Требует перехода на отечественные решения для защиты КИИ, чтобы снизить зависимость от иностранных технологий.</li>
        <li><strong>Постановление Правительства РФ № 127 от 8 февраля 2018 года "Об утверждении Правил категорирования объектов КИИ":</strong> Устанавливает правила категорирования объектов КИИ, включая критерии значимости (например, социальная, экономическая, экологическая значимость) и порядок присвоения категорий.</li>
        <li><strong>Приказ ФСТЭК России № 235 от 21 декабря 2017 года "Об утверждении Требований к созданию систем безопасности значимых объектов КИИ":</strong> Определяет требования к созданию систем безопасности, включая организационные и технические меры, а также этапы их внедрения.</li>
        <li><strong>Приказ ФСТЭК России № 239 от 25 декабря 2017 года "Об утверждении Требований по обеспечению безопасности значимых объектов КИИ":</strong> Устанавливает меры защиты для значимых объектов КИИ, включая управление доступом, шифрование, мониторинг и реагирование на инциденты.</li>
        <li><strong>Приказ ФСБ России № 366 от 24 июля 2018 года "О Национальном координационном центре по компьютерным инцидентам (НКЦКИ)":</strong> Создаёт НКЦКИ как центр координации для обнаружения, предупреждения и ликвидации последствий кибератак.</li>
        <li><strong>Приказ ФСБ России № 367 от 24 июля 2018 года "Об утверждении Перечня информации, представляемой в ГосСОПКА":</strong> Определяет, какую информацию субъекты КИИ должны передавать в ГосСОПКА (например, данные об инцидентах, сведения о значимых объектах).</li>
        <li><strong>Приказ ФСБ России № 524 от 24 октября 2022 года "Об утверждении Требований о защите информации с использованием шифровальных средств":</strong> Устанавливает требования к применению криптографии на объектах КИИ, включая использование ГОСТ-шифрования.</li>
      </ul>
      <p>Эти документы формируют основу для защиты КИИ в России. Субъекты КИИ обязаны соблюдать их, включая категорирование объектов, взаимодействие с ГосСОПКА и регулярное информирование ФСБ о выявленных инцидентах.</p>

      <h2>Теория защиты от кибератак и повышения безопасности</h2>
      <p>Для защиты КИИ от кибератак и повышения безопасности специалисты должны применять многоуровневый подход, который включает предотвращение, обнаружение и реагирование на угрозы. Вот ключевые аспекты:</p>
      <h3>Защита от кибератак</h3>
      <ul>
        <li><strong>DDoS-атаки:</strong> Для защиты от распределённых атак типа "отказ в обслуживании" (DDoS) используйте системы защиты, такие как Cloudflare или отечественные решения (например, Qrator Labs). Настройте ограничение скорости запросов (rate limiting) и фильтрацию трафика на уровне межсетевых экранов. Также полезно иметь резервные каналы связи, чтобы минимизировать последствия атаки.</li>
        <li><strong>APT-атаки (целенаправленные атаки):</strong> Целенаправленные атаки (Advanced Persistent Threats) часто начинаются с фишинга. Для защиты внедрите системы обнаружения аномалий (например, через SIEM), которые могут выявить подозрительную активность, такую как несанкционированный доступ к системам. Используйте песочницы (sandboxes) для анализа подозрительных файлов и ссылок.</li>
        <li><strong>Фишинг и социальная инженерия:</strong> Проводите регулярное обучение персонала, чтобы сотрудники могли распознавать фишинговые письма. Внедрите системы фильтрации электронной почты (например, DMARC, SPF, DKIM), чтобы блокировать поддельные письма. Также полезно использовать двухфакторную аутентификацию (2FA) для защиты учётных записей.</li>
        <li><strong>Эксплуатация уязвимостей:</strong> Регулярно проводите сканирование уязвимостей с помощью инструментов, таких как Nessus или OpenVAS. Устанавливайте обновления и патчи для программного обеспечения и прошивок устройств. Для критических систем настройте WAF (Web Application Firewall) для защиты веб-приложений.</li>
      </ul>
      <h3>Повышение безопасности</h3>
      <ul>
        <li><strong>Управление уязвимостями:</strong> Создайте процесс управления уязвимостями: регулярно сканируйте системы, оценивайте риски и устраняйте уязвимости в порядке приоритета. Например, уязвимости с высоким уровнем критичности (CVSS 9-10) должны устраняться в течение 24-48 часов.</li>
        <li><strong>Мониторинг и реагирование:</strong> Внедрите SIEM-системы (например, Splunk, QRadar) для централизованного анализа логов и выявления инцидентов. Настройте автоматические оповещения о подозрительной активности, например, о множественных неудачных попытках входа в систему.</li>
        <li><strong>Обучение персонала:</strong> Проводите тренинги по кибербезопасности, включая симуляции фишинговых атак. Сотрудники должны знать, как безопасно работать с данными и реагировать на инциденты (например, сообщать в ИТ-отдел о подозрительных письмах).</li>
        <li><strong>Резервное копирование:</strong> Регулярно создавайте резервные копии данных и систем КИИ. Проверяйте возможность восстановления из резервных копий, чтобы минимизировать время простоя в случае атаки (например, шифровальщика).</li>
        <li><strong>Тестирование на проникновение:</strong> Проводите регулярные тесты на проникновение (penetration testing), чтобы выявить слабые места в инфраструктуре. Например, тестируйте, могут ли злоумышленники получить доступ к внутренней сети через уязвимости в DMZ.</li>
        <li><strong>Шифрование данных:</strong> Используйте шифрование для защиты данных как при передаче (TLS, IPsec), так и при хранении (например, с помощью ГОСТ-алгоритмов). Убедитесь, что ключи шифрования хранятся в безопасном месте, например, в HSM (Hardware Security Module).</li>
      </ul>
      <p>Эти меры помогут минимизировать риски кибератак и повысить общий уровень безопасности КИИ. Важно также регулярно пересматривать и обновлять политики безопасности, чтобы учитывать новые угрозы и изменения в инфраструктуре.</p>

      <h2>Средства защиты КИИ</h2>
      <ul>
        <li><strong>Межсетевые экраны (Firewalls):</strong> Используйте межсетевые экраны нового поколения (NGFW), такие как Cisco Firepower, Palo Alto Networks, для фильтрации трафика.</li>
        <li><strong>IDS/IPS:</strong> Системы обнаружения и предотвращения вторжений (например, Cisco Secure IPS, Snort) для мониторинга и защиты от атак.</li>
        <li><strong>SIEM:</strong> Системы управления событиями и информационной безопасностью (например, Splunk, ArcSight) для анализа логов и выявления инцидентов.</li>
        <li><strong>DLP:</strong> Системы предотвращения утечек данных (например, Symantec DLP) для защиты конфиденциальной информации.</li>
        <li><strong>Шифрование:</strong> Используйте ГОСТ-шифрование (например, с помощью решений от "КриптоПро") для соответствия требованиям ФСБ.</li>
        <li><strong>Мониторинг:</strong> Используйте системы мониторинга (например, Zabbix, SolarWinds) для отслеживания состояния сети КИИ.</li>
        <li><strong>SOAR:</strong> Платформы автоматизации реагирования на инциденты (например, IBM Resilient) для ускорения реагирования.</li>
        <li><strong>Антивирусы:</strong> Установите антивирусное ПО (например, Kaspersky Endpoint Security) на все рабочие станции и серверы.</li>
      </ul>

      <h2>Рекомендации по защите КИИ</h2>
      <ol>
        <li><strong>Категорирование объектов КИИ:</strong> Проведите инвентаризацию и определите значимость объектов КИИ в соответствии с 187-ФЗ.</li>
        <li><strong>Изоляция сети:</strong> Изолируйте сеть КИИ от интернета, используя VPN и межсетевые экраны для доступа.</li>
        <li><strong>Многоуровневая защита:</strong> Применяйте защиту на всех уровнях (сетевая, прикладная, физическая).</li>
        <li><strong>Регулярный аудит:</strong> Проводите аудиты и тесты на проникновение (penetration testing) для выявления уязвимостей.</li>
        <li><strong>Взаимодействие с ФСБ:</strong> Уведомляйте ФСБ о выявленных инцидентах и сотрудничайте с ГосСОПКА.</li>
        <li><strong>Резервное копирование:</strong> Регулярно создавайте резервные копии данных КИИ и проверяйте их восстановление.</li>
        <li><strong>Обновление ПО:</strong> Своевременно обновляйте программное обеспечение и прошивки устройств КИИ.</li>
      </ol>

      <h2>Пример атаки на КИИ</h2>
      <p>Одним из известных примеров атаки на КИИ является кибератака на энергосистему Украины в 2015 году (BlackEnergy). Злоумышленники использовали фишинговые письма для заражения рабочих станций, а затем получили доступ к SCADA-системам, что привело к отключению электроэнергии для сотен тысяч потребителей. Этот инцидент подчёркивает важность сегментации, контроля доступа и мониторинга в сетях КИИ.</p>
    </div>
  `;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadStructureSecurityContent(container);
  });
  }

  function loadOTSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность АСУТП</h1>
        <p>Сети АСУТП (автоматизированных систем управления технологическими процессами) используются в промышленности для управления производственными процессами (например, на заводах, электростанциях, нефтеперерабатывающих предприятиях). Эти сети критически важны, и их компрометация может привести к остановке производства, авариям или даже угрозе жизни. Поэтому безопасность АСУТП требует особого подхода.</p>

        <h2>Основные принципы защиты АСУТП</h2>
        <div class="ot-security-principles" style="margin-bottom: 20px;">
          <div class="ot-security-principles-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="ot-security-principles-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Принципы защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Сегментация сети
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">VLAN</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  Контроль доступа
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">802.1X</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Шифрование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">IPsec</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Мониторинг и обнаружение
                  <p style="font-size: 12px; margin: 5px 0 0;">IDS</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Обновление и патчи
                  <p style="font-size: 12px; margin: 5px 0 0;">Прошивки</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Физическая безопасность
                  <p style="font-size: 12px; margin: 5px 0 0;">Замки</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Резервирование
                  <p style="font-size: 12px; margin: 5px 0 0;">VRRP</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание принципов</h3>
              <p>Основные аспекты защиты АСУТП:</p>
              <ul>
                <li><strong>Сегментация сети:</strong> Изоляция с помощью VLAN и DMZ.</li>
                <li><strong>Контроль доступа:</strong> Аутентификация через 802.1X.</li>
                <li><strong>Шифрование:</strong> Защита данных с помощью IPsec, TLS.</li>
                <li><strong>Мониторинг и обнаружение:</strong> Использование IDS и NetFlow.</li>
                <li><strong>Обновление и патчи:</strong> Регулярное обновление прошивок.</li>
                <li><strong>Физическая безопасность:</strong> Ограничение доступа (замки).</li>
                <li><strong>Резервирование:</strong> Отказоустойчивость через VRRP.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Сегментация сети АСУТП</h2>
        <p>Одним из ключевых методов защиты АСУТП является сегментация сети. Сегментация позволяет изолировать критически важные компоненты АСУТП от корпоративной сети (IT) и внешнего мира. Для этого используется модель Purdue, которая делит сеть на уровни.</p>
        <div class="ot-security-diagram" style="margin-bottom: 20px;">
          <div class="ot-security-diagram-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="ot-security-diagram-content" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Схема сегментации</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Уровень 4-5 (IT)
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Корпоративная сеть</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  Брандмауэр
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Между IT и OT</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  DMZ
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шлюзы</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Уровень 3 (MES)
                  <p style="font-size: 12px; margin: 5px 0 0;">Операции</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  IDS
                  <p style="font-size: 12px; margin: 5px 0 0;">Обнаружение атак</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Уровень 2 (SCADA, HMI)
                  <p style="font-size: 12px; margin: 5px 0 0;">Мониторинг</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                  Уровень 1 (ПЛК)
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Контроллеры</p>
                </div>
                <div style="background-color: #b2dfdb; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Уровень 0 (Датчики)
                  <p style="font-size: 12px; margin: 5px 0 0;">Устройства</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  SIEM
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание схемы</h3>
              <p>Многоуровневая сегментация по модели Purdue:</p>
              <ul>
                <li><strong>Уровень 4-5 (IT):</strong> Корпоративная сеть (ERP, CRM).</li>
                <li><strong>Брандмауэр:</strong> Фильтрация между IT и OT.</li>
                <li><strong>DMZ:</strong> Шлюзы для обмена данными.</li>
                <li><strong>Уровень 3 (MES):</strong> Системы управления производством.</li>
                <li><strong>IDS:</strong> Обнаружение атак на уровне операций.</li>
                <li><strong>Уровень 2 (SCADA, HMI):</strong> Мониторинг процессов.</li>
                <li><strong>Уровень 1 (ПЛК):</strong> Контроллеры управления.</li>
                <li><strong>Уровень 0 (Датчики):</strong> Физические устройства.</li>
                <li><strong>SIEM:</strong> Мониторинг и анализ логов.</li>
              </ul>
            </div>
          </div>
        </div>
        <p>Между уровнями устанавливаются межсетевые экраны (firewalls) и системы предотвращения вторжений (IPS) для фильтрации трафика. Например, доступ из уровня 4-5 в DMZ может быть разрешён только для определённых сервисов (например, передачи логов), а из DMZ в уровень 3 — только для авторизованных систем через VPN.</p>

        <h2>Российская документация по защите АСУТП</h2>
        <p>В России защита АСУТП регулируется рядом нормативных актов, включая стандарты ФСТЭК и ГОСТ. Вот основные документы:</p>
        <ul>
          <li><strong>ГОСТ Р 51583-2014 "Защита информации. Порядок создания автоматизированных систем в защищённом исполнении":</strong> Устанавливает требования к созданию АСУТП в защищённом исполнении, включая этапы проектирования, внедрения и эксплуатации.</li>
          <li><strong>Приказ ФСТЭК России № 31 от 14 марта 2014 года "Об утверждении требований к обеспечению защиты информации в АСУТП":</strong> Определяет меры защиты для АСУТП, включая сегментацию, контроль доступа и мониторинг.</li>
          <li><strong>ГОСТ Р ИСО/МЭК 62443 "Безопасность АСУТП":</strong> Международный стандарт, адаптированный в России, который описывает методы защиты АСУТП от киберугроз.</li>
        </ul>

        <h2>Теория защиты от кибератак и повышения безопасности</h2>
        <p>Для защиты АСУТП от кибератак и повышения безопасности специалисты должны применять многоуровневый подход, который включает предотвращение, обнаружение и реагирование на угрозы. Вот ключевые аспекты:</p>
        <h3>Защита от кибератак</h3>
        <ul>
          <li><strong>Атаки на SCADA-системы:</strong> Злоумышленники могут использовать уязвимости в SCADA-системах для изменения параметров технологических процессов. Для защиты используйте шифрование (TLS, IPsec) и изолируйте SCADA-системы от интернета.</li>
          <li><strong>Атаки на устаревшие протоколы:</strong> Многие устройства АСУТП используют устаревшие протоколы (например, Modbus, DNP3), которые не поддерживают шифрование. Для защиты настройте межсетевые экраны и используйте шлюзы безопасности для фильтрации трафика.</li>
          <li><strong>Фишинг и социальная инженерия:</strong> Обучайте персонал распознаванию фишинговых атак, так как они часто используются для получения доступа к системам АСУТП.</li>
          <li><strong>Физические атаки:</strong> Защищайте оборудование АСУТП от физического доступа, используя замки, видеонаблюдение и системы контроля доступа.</li>
        </ul>
        <h3>Повышение безопасности</h3>
        <ul>
          <li><strong>Управление уязвимостями:</strong> Регулярно проводите сканирование уязвимостей (например, с помощью Nessus) и устанавливайте обновления для устройств АСУТП.</li>
          <li><strong>Мониторинг:</strong> Используйте системы мониторинга (например, Zabbix) и SIEM (например, Splunk) для анализа логов и выявления аномалий.</li>
          <li><strong>Обучение персонала:</strong> Проводите тренинги по кибербезопасности для операторов и инженеров АСУТП.</li>
          <li><strong>Резервное копирование:</strong> Регулярно создавайте резервные копии конфигураций ПЛК и SCADA-систем, чтобы минимизировать время простоя в случае атаки.</li>
        </ul>

        <h2>Средства защиты АСУТП</h2>
        <ul>
          <li><strong>Межсетевые экраны:</strong> Используйте промышленные межсетевые экраны (например, Cisco Industrial Security Appliance) для фильтрации трафика.</li>
          <li><strong>IDS/IPS:</strong> Установите системы обнаружения и предотвращения вторжений (например, Nozomi Networks) для мониторинга трафика АСУТП.</li>
          <li><strong>Шифрование:</strong> Применяйте IPsec или TLS для защиты связи между устройствами АСУТП.</li>
          <li><strong>Антивирусы:</strong> Используйте антивирусное ПО, совместимое с АСУТП (например, Kaspersky Industrial CyberSecurity).</li>
          <li><strong>Сегментация:</strong> Используйте VLAN и межсетевые экраны для изоляции уровней АСУТП.</li>
        </ul>

        <h2>Рекомендации по защите АСУТП</h2>
        <ol>
          <li><strong>Изоляция сети:</strong> Полностью изолируйте сеть АСУТП от интернета и корпоративной сети.</li>
          <li><strong>Многоуровневая защита:</strong> Применяйте защиту на всех уровнях (физическая, сетевая, прикладная).</li>
          <li><strong>Регулярный аудит:</strong> Проводите аудиты и тесты на проникновение для выявления уязвимостей.</li>
          <li><strong>Обновление ПО:</strong> Своевременно обновляйте прошивки и ПО устройств АСУТП.</li>
          <li><strong>Мониторинг:</strong> Настройте мониторинг трафика и логов для быстрого обнаружения инцидентов.</li>
        </ol>

        <h2>Пример атаки на АСУТП</h2>
        <p>Одним из известных примеров атаки на АСУТП является Stuxnet (2010). Этот вирус был нацелен на иранские ядерные объекты и использовал уязвимости в SCADA-системах Siemens для изменения параметров работы центрифуг, что привело к их физическому разрушению. Этот инцидент подчёркивает важность изоляции, обновления ПО и мониторинга в сетях АСУТП.</p>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadAppSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность приложений</h1>
        <p>Безопасность приложений (Application Security, AppSec) — это дисциплина, направленная на защиту программного обеспечения от угроз на всех этапах его жизненного цикла: проектирования, разработки, тестирования, развертывания и эксплуатации. AppSec охватывает веб-приложения, мобильные приложения, API, десктопные программы и встроенное ПО, защищая их от атак, таких как инъекции, утечки данных и несанкционированный доступ. Основная цель — минимизировать риски, связанные с уязвимостями кода, конфигурации и зависимостей, обеспечивая конфиденциальность, целостность и доступность данных.</p>
  
        <h2>Теоретические основы безопасности приложений</h2>
        <p>AppSec опирается на теорию информационной безопасности, криптографию, модели управления доступом и процессы разработки ПО. Вот ключевые концепции:</p>
        <ul>
          <li><strong>Поверхность атаки:</strong> Чем сложнее приложение (много кода, зависимостей, API), тем больше точек входа для атак. Теория минимизации поверхности атаки требует сокращения ненужных функций и строгой валидации данных.</li>
          <li><strong>Secure SDLC:</strong> Secure Software Development Lifecycle — интеграция безопасности в процесс разработки (DevSecOps). Это включает статический анализ (SAST), динамический анализ (DAST), управление зависимостями и тестирование на проникновение (pentesting).</li>
          <li><strong>Криптография:</strong> Шифрование данных (AES, RSA) и хеширование (SHA-256, bcrypt) защищают данные в транзите и в покое. Теория стойкости к атакам требует использования современных алгоритмов и защиты от атак по сторонним каналам (side-channel attacks).</li>
          <li><strong>Модели угроз:</strong> Использование STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) для анализа рисков приложения.</li>
          <li><strong>Zero Trust:</strong> Принцип "никому не доверяй" применяется к приложениям: каждый запрос должен быть аутентифицирован и авторизован, даже внутри системы.</li>
          <li><strong>Управление зависимостями:</strong> Теория цепочки поставок ПО (Software Supply Chain) подчёркивает риски от устаревших или скомпрометированных библиотек (например, Log4Shell, CVE-2021-44228).</li>
          <li><strong>Оркестрация:</strong> Современные приложения часто разворачиваются в контейнерах (Docker, Kubernetes), что требует защиты на уровне оркестрации, включая управление секретами, сетевые политики и сканирование образов.</li>
        </ul>
        <p>Основные угрозы для приложений:</p>
        <ul>
          <li><strong>Инъекции:</strong> SQL-инъекции, XSS, командные инъекции из-за недостаточной валидации данных.</li>
          <li><strong>Утечки данных:</strong> Неправильная конфигурация (например, открытые API) или слабое шифрование.</li>
          <li><strong>Компрометация зависимостей:</strong> Атаки через устаревшие библиотеки (Log4j).</li>
          <li><strong>DoS:</strong> Перегрузка приложения запросами (например, через слабые API).</li>
          <li><strong>Социальная инженерия:</strong> Фишинг для получения учетных данных приложения.</li>
        </ul>
  
        <h2>Жизненный цикл разработки безопасного ПО (Secure SDLC)</h2>
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-header">Этапы Secure SDLC</button>
            <div class="accordion-content">
              <table class="osi-table">
                <thead>
                  <tr>
                    <th>Этап</th>
                    <th>Описание</th>
                    <th>Действия</th>
                    <th>Инструменты</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>Планирование</strong></td>
                    <td>Определение требований безопасности и моделирование угроз.</td>
                    <td>Анализ рисков, создание модели угроз (STRIDE).</td>
                    <td>Microsoft Threat Modeling Tool, OWASP Threat Dragon</td>
                  </tr>
                  <tr>
                    <td><strong>Проектирование</strong></td>
                    <td>Разработка архитектуры с учётом безопасности.</td>
                    <td>Выбор безопасных паттернов (например, принцип наименьших привилегий).</td>
                    <td>Diagrams.net, Enterprise Architect</td>
                  </tr>
                  <tr>
                    <td><strong>Разработка</strong></td>
                    <td>Написание кода с учётом безопасности.</td>
                    <td>Статический анализ кода (SAST), валидация данных.</td>
                    <td>SonarQube, Checkmarx, ESLint</td>
                  </tr>
                  <tr>
                    <td><strong>Тестирование</strong></td>
                    <td>Проверка приложения на уязвимости.</td>
                    <td>Динамический анализ (DAST), пентест.</td>
                    <td>OWASP ZAP, Burp Suite, Postman</td>
                  </tr>
                  <tr>
                    <td><strong>Развертывание</strong></td>
                    <td>Запуск приложения с защитой окружения.</td>
                    <td>Настройка WAF, шифрование, оркестрация.</td>
                    <td>AWS WAF, Kubernetes, Docker</td>
                  </tr>
                  <tr>
                    <td><strong>Эксплуатация</strong></td>
                    <td>Мониторинг и реагирование на угрозы.</td>
                    <td>Runtime-защита (RASP), анализ логов.</td>
                    <td>Splunk, Imperva, ELK</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
  
        <h2>Процессы DevSecOps</h2>
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-header">Этапы DevSecOps</button>
            <div class="accordion-content">
              <table class="osi-table">
                <thead>
                  <tr>
                    <th>Этап</th>
                    <th>Описание</th>
                    <th>Действия</th>
                    <th>Инструменты</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td><strong>CI (Continuous Integration)</strong></td>
                    <td>Автоматизация сборки и тестирования кода.</td>
                    <td>Запуск SAST и SCA в пайплайне.</td>
                    <td>Jenkins, GitLab CI, SonarQube</td>
                  </tr>
                  <tr>
                    <td><strong>CD (Continuous Deployment)</strong></td>
                    <td>Автоматическое развертывание с проверками.</td>
                    <td>DAST и проверка конфигурации окружения.</td>
                    <td>CircleCI, ArgoCD, OWASP ZAP</td>
                  </tr>
                  <tr>
                    <td><strong>Сканирование зависимостей</strong></td>
                    <td>Проверка библиотек на уязвимости.</td>
                    <td>Анализ через SCA (например, npm audit).</td>
                    <td>Snyk, Dependabot, WhiteSource</td>
                  </tr>
                  <tr>
                    <td><strong>Оркестрация</strong></td>
                    <td>Управление контейнерами и сервисами.</td>
                    <td>Сканирование образов, настройка Network Policies.</td>
                    <td>Kubernetes, Trivy, Istio</td>
                  </tr>
                  <tr>
                    <td><strong>Мониторинг</strong></td>
                    <td>Обнаружение угроз в реальном времени.</td>
                    <td>Интеграция SIEM и RASP.</td>
                    <td>Prometheus, Splunk, Imperva</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
  
        <h2>Процессы AppSec</h2>
        <p>Безопасность приложений реализуется через структурированные процессы, интегрированные в жизненный цикл разработки:</p>
        <div class="appsec-processes-table" style="margin-bottom: 20px;">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Процесс</th>
                <th>Описание</th>
                <th>Инструменты</th>
                <th>Применение</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>SAST</strong></td>
                <td>Static Application Security Testing — статический анализ исходного кода для поиска уязвимостей без выполнения приложения.</td>
                <td>SonarQube, Checkmarx, Fortify</td>
                <td>Интеграция в CI/CD для анализа кода на этапе разработки (например, поиск SQL-инъекций в Python).</td>
              </tr>
              <tr>
                <td><strong>DAST</strong></td>
                <td>Dynamic Application Security Testing — динамический анализ работающего приложения для выявления уязвимостей (black-box тестирование).</td>
                <td>OWASP ZAP, Burp Suite, AppScan</td>
                <td>Тестирование веб-приложений на этапе QA (например, проверка XSS через ввод данных).</td>
              </tr>
              <tr>
                <td><strong>IAST</strong></td>
                <td>Interactive Application Security Testing — комбинация SAST и DAST, анализ кода в реальном времени во время выполнения.</td>
                <td>Contrast Security, Acunetix</td>
                <td>Мониторинг приложений в тестовой среде для точного определения уязвимостей.</td>
              </tr>
              <tr>
                <td><strong>SCA</strong></td>
                <td>Software Composition Analysis — анализ зависимостей на наличие известных уязвимостей (CVE).</td>
                <td>Snyk, Dependabot, WhiteSource</td>
                <td>Проверка библиотек в package.json или pom.xml на этапе сборки.</td>
              </tr>
              <tr>
                <td><strong>Оркестрация</strong></td>
                <td>Управление безопасностью контейнеров и микросервисов в распределённых системах.</td>
                <td>Kubernetes, Istio, Docker</td>
                <td>Настройка Network Policies, управление секретами через Vault, сканирование образов Trivy.</td>
              </tr>
              <tr>
                <td><strong>Penetration Testing</strong></td>
                <td>Ручное или автоматизированное тестирование на проникновение для поиска уязвимостей.</td>
                <td>Metasploit, Kali Linux, Burp Suite</td>
                <td>Симуляция атак на приложение перед релизом.</td>
              </tr>
              <tr>
                <td><strong>RASP</strong></td>
                <td>Runtime Application Self-Protection — защита приложения в реальном времени на уровне выполнения.</td>
                <td>Imperva, Sqreen</td>
                <td>Блокировка атак (например, SQL-инъекций) в продакшене.</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Подробное описание процессов AppSec</h2>
        <div class="accordion">
          <div class="accordion-item">
            <button class="accordion-header">SAST (Static Application Security Testing)</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> SAST анализирует исходный код или бинарные файлы приложения без его выполнения (white-box тестирование). Он выявляет уязвимости, такие как SQL-инъекции, XSS, буферные переполнения и слабые криптографические алгоритмы, на ранних этапах разработки.</p>
              <p><strong>Как работает:</strong> Инструменты SAST сканируют код, строят модель данных (AST — Abstract Syntax Tree) и проверяют её на соответствие правилам безопасности. Например, инструмент может обнаружить использование функции <code>eval()</code> в JavaScript как потенциально опасной.</p>
              <p><strong>Пример:</strong> В коде на Python строка <code>cursor.execute(user_input)</code> без параметризации будет помечена как уязвимость к SQL-инъекциям.</p>
              <p><strong>Преимущества:</strong> Раннее обнаружение ошибок, интеграция в IDE и CI/CD, высокая точность при правильной настройке.</p>
              <p><strong>Недостатки:</strong> Не видит runtime-уязвимости, может выдавать ложные срабатывания (false positives).</p>
              <p><strong>Инструменты:</strong> SonarQube, Checkmarx, Fortify, ESLint (для JS), Bandit (для Python).</p>
              <p><strong>Рекомендации:</strong> Интегрируйте SAST в CI/CD (например, GitLab CI), настройте правила под проект, регулярно обновляйте базы уязвимостей.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">DAST (Dynamic Application Security Testing)</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> DAST тестирует приложение во время его выполнения (black-box тестирование), моделируя атаки извне. Он проверяет веб-приложения, API и мобильные приложения на уязвимости, такие как XSS, CSRF и некорректная обработка ошибок.</p>
              <p><strong>Как работает:</strong> Инструменты отправляют вредоносные запросы (например, <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>) и анализируют ответы приложения на наличие уязвимостей.</p>
              <p><strong>Пример:</strong> DAST-инструмент может обнаружить XSS, если ввод пользователя отображается на странице без экранирования.</p>
              <p><strong>Преимущества:</strong> Проверяет реальное поведение приложения, не требует доступа к коду, эффективен для веб-приложений.</p>
              <p><strong>Недостатки:</strong> Не видит уязвимости в коде, которые не проявляются в runtime, требует запущенного приложения.</p>
              <p><strong>Инструменты:</strong> OWASP ZAP, Burp Suite, AppScan, Nikto.</p>
              <p><strong>Рекомендации:</strong> Используйте DAST на этапе QA, комбинируйте с SAST, настройте тестовую среду с покрытием всех API-эндпоинтов.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">IAST (Interactive Application Security Testing)</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> IAST сочетает преимущества SAST и DAST, анализируя приложение в реальном времени во время выполнения. Он использует агентов или библиотеки, внедрённые в код, для мониторинга выполнения и выявления уязвимостей.</p>
              <p><strong>Как работает:</strong> Агент отслеживает выполнение кода (например, через JVM или .NET CLR) и фиксирует уязвимости, такие как SQL-инъекции, в момент их проявления.</p>
              <p><strong>Пример:</strong> IAST может обнаружить, что строка <code>request.getParameter("id")</code> в Java передаётся в SQL-запрос без экранирования.</p>
              <p><strong>Преимущества:</strong> Высокая точность, низкий уровень ложных срабатываний, видит runtime-уязвимости.</p>
              <p><strong>Недостатки:</strong> Требует внедрения агента, может замедлять приложение, сложнее в настройке.</p>
              <p><strong>Инструменты:</strong> Contrast Security, Acunetix, Synopsys Seeker.</p>
              <p><strong>Рекомендации:</strong> Используйте IAST в тестовой среде, настройте агентов для покрытия критических частей кода, комбинируйте с другими методами.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">SCA (Software Composition Analysis)</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> SCA анализирует зависимости приложения (библиотеки, фреймворки) на наличие известных уязвимостей (CVE) и лицензионных рисков.</p>
              <p><strong>Как работает:</strong> Инструменты сканируют файлы зависимостей (например, <code>package.json</code>, <code>pom.xml</code>) и сопоставляют их с базами уязвимостей (NVD).</p>
              <p><strong>Пример:</strong> SCA может обнаружить уязвимость Log4j (CVE-2021-44228) в проекте и предложить обновить версию.</p>
              <p><strong>Преимущества:</strong> Быстрое обнаружение проблем в зависимостях, автоматизация в CI/CD, проверка лицензий.</p>
              <p><strong>Недостатки:</strong> Не видит уязвимости в собственном коде, зависит от актуальности баз данных.</p>
              <p><strong>Инструменты:</strong> Snyk, Dependabot, WhiteSource, OWASP Dependency-Check.</p>
              <p><strong>Рекомендации:</strong> Интегрируйте SCA в CI/CD, настройте автоматическое обновление зависимостей, проверяйте лицензии перед релизом.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">Оркестрация</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> Оркестрация управляет безопасностью контейнеров и микросервисов в распределённых системах, таких как Kubernetes или Docker Swarm, обеспечивая изоляцию, управление секретами и мониторинг.</p>
              <p><strong>Как работает:</strong> Используются инструменты для автоматизации развертывания, настройки сетевых политик (Network Policies), сканирования образов и управления доступом.</p>
              <p><strong>Пример:</strong> Kubernetes может ограничить доступ между подами через Network Policies, а Trivy просканирует образ на уязвимости перед развертыванием.</p>
              <p><strong>Преимущества:</strong> Повышает безопасность микросервисов, автоматизирует управление, изолирует компоненты.</p>
              <p><strong>Недостатки:</strong> Требует глубоких знаний DevOps, сложность настройки.</p>
              <p><strong>Инструменты:</strong> Kubernetes, Docker, Istio, Trivy, HashiCorp Vault.</p>
              <p><strong>Рекомендации:</strong> Настройте Network Policies, используйте Vault для секретов, сканируйте образы в CI/CD, применяйте принцип наименьших привилегий.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">RASP (Runtime Application Self-Protection)</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> RASP защищает приложение в реальном времени, внедряя агентов на уровне выполнения (runtime), которые блокируют атаки, такие как SQL-инъекции или XSS, без изменения кода.</p>
              <p><strong>Как работает:</strong> Агент отслеживает выполнение приложения (например, через JVM или PHP) и вмешивается, если обнаруживает подозрительное поведение, например, выполнение вредоносного SQL-запроса.</p>
              <p><strong>Пример:</strong> RASP может заблокировать SQL-инъекцию, если запрос содержит <code>1=1 OR DROP TABLE</code>, даже если код уязвим.</p>
              <p><strong>Преимущества:</strong> Защита в продакшене, минимальные ложные срабатывания, не требует доработки кода.</p>
              <p><strong>Недостатки:</strong> Может замедлять приложение, требует интеграции, не заменяет превентивные меры.</p>
              <p><strong>Инструменты:</strong> Imperva, Sqreen, Signal Sciences.</p>
              <p><strong>Рекомендации:</strong> Используйте RASP как дополнительный слой защиты, настройте в продакшене, комбинируйте с WAF и мониторингом.</p>
            </div>
          </div>
          <div class="accordion-item">
            <button class="accordion-header">Penetration Testing (Тестирование на проникновение)</button>
            <div class="accordion-content">
              <p><strong>Описание:</strong> Penetration Testing (пентест) — это симуляция атак на приложение для выявления уязвимостей, которые могут быть пропущены автоматическими инструментами. Может быть ручным или автоматизированным.</p>
              <p><strong>Как работает:</strong> Специалисты или инструменты моделируют действия хакеров, используя техники, такие как перебор паролей, инъекции или эксплуатация API.</p>
              <p><strong>Пример:</strong> Пентестер может обнаружить, что API принимает некорректный токен JWT и выдаёт доступ к данным.</p>
              <p><strong>Преимущества:</strong> Выявляет сложные уязвимости, имитирует реальные атаки, даёт рекомендации по устранению.</p>
              <p><strong>Недостатки:</strong> Затратно по времени и ресурсам, зависит от квалификации исполнителя.</p>
              <p><strong>Инструменты:</strong> Metasploit, Kali Linux, Burp Suite, Nmap, Hydra.</p>
              <p><strong>Рекомендации:</strong> Проводите пентест перед релизом, используйте как дополнение к SAST/DAST, нанимайте сертифицированных специалистов (CEH, OSCP).</p>
            </div>
          </div>
        </div>
  
        <h2>Схема уровней защиты приложений</h2>
        <div class="app-security-method" style="margin-bottom: 20px;">
          <div class="app-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="app-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Клиент</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  WAF
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фильтрация</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  TLS
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шифрование</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Приложение
                  <p style="font-size: 12px; margin: 5px 0 0;">Код</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  RASP
                  <p style="font-size: 12px; margin: 5px 0 0;">Защита runtime</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Контейнер
                  <p style="font-size: 12px; margin: 5px 0 0;">Docker</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                  Данные
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">БД</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  SIEM
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней</h3>
              <p>Многоуровневая защита приложения:</p>
              <ul>
                <li><strong>Пользователь:</strong> Клиент, отправляющий запросы.</li>
                <li><strong>WAF:</strong> Защита от атак L7 (Cloudflare).</li>
                <li><strong>TLS:</strong> Шифрование соединения.</li>
                <li><strong>Приложение:</strong> Код с встроенной защитой (валидация).</li>
                <li><strong>RASP:</strong> Защита в реальном времени.</li>
                <li><strong>Контейнер:</strong> Изоляция в Docker/Kubernetes.</li>
                <li><strong>Данные:</strong> Шифрование в БД.</li>
                <li><strong>SIEM:</strong> Мониторинг логов (Splunk).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Меры защиты приложений</h2>
        <div class="app-security-measures" style="margin-bottom: 20px;">
          <div class="app-security-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="app-security-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Меры защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  SAST/DAST
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Анализ</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  SCA
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Зависимости</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Шифрование
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Данные</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Контроль доступа
                  <p style="font-size: 12px; margin: 5px 0 0;">RBAC</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Оркестрация
                  <p style="font-size: 12px; margin: 5px 0 0;">Kubernetes</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0;">Логи</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание мер</h3>
              <p>Комплексный подход к защите:</p>
              <ul>
                <li><strong>SAST/DAST:</strong> Анализ кода и тестирование (SonarQube, OWASP ZAP).</li>
                <li><strong>SCA:</strong> Проверка зависимостей (Snyk).</li>
                <li><strong>Шифрование:</strong> Защита данных (AES-256).</li>
                <li><strong>Контроль доступа:</strong> RBAC или ABAC.</li>
                <li><strong>Оркестрация:</strong> Безопасность контейнеров (Kubernetes).</li>
                <li><strong>Мониторинг:</strong> Анализ логов (ELK).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Рекомендации по защите приложений</h2>
        <ol>
          <li>Интегрируйте SAST (SonarQube) и DAST (OWASP ZAP) в CI/CD.</li>
          <li>Используйте SCA (Snyk) для проверки зависимостей на уязвимости.</li>
          <li>Шифруйте данные в транзите (TLS 1.3) и в покое (AES-256).</li>
          <li>Настройте RBAC/ABAC для управления доступом.</li>
          <li>Применяйте оркестрацию (Kubernetes) с Network Policies и секретами (Vault).</li>
          <li>Внедрите мониторинг с помощью SIEM (Splunk) и RASP для runtime-защиты.</li>
          <li>Проводите регулярные пентесты и аудиты безопасности.</li>
        </ol>
  
        <h2>Примеры атак на приложения</h2>
        <ul>
          <li><strong>Equifax (2017):</strong> Уязвимость в Apache Struts (CVE-2017-5638) привела к утечке данных 147 миллионов человек из-за отсутствия обновлений.</li>
          <li><strong>Log4Shell (2021):</strong> Уязвимость в Log4j (CVE-2021-44228) позволила удалённое выполнение кода в тысячах приложений.</li>
          <li><strong>SQL-инъекция в Sony (2011):</strong> Атака через слабую валидацию ввода украла данные 77 миллионов пользователей.</li>
        </ul>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });

    const accordionHeaders = document.querySelectorAll('.accordion-header');
    accordionHeaders.forEach(header => {
      header.addEventListener('click', () => {
        const content = header.nextElementSibling;
        content.style.display = content.style.display === 'block' ? 'none' : 'block';
      });
    });
  }

  function loadDBSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность СУБД</h1>
        <p>Системы управления базами данных (СУБД) являются критически важным компонентом инфраструктуры, так как они хранят и обрабатывают конфиденциальные данные. Обеспечение безопасности СУБД требует комплексного подхода, включая шифрование, контроль доступа, мониторинг и защиту от SQL-инъекций.</p>

        <h2>Теоретические основы безопасности СУБД</h2>
        <p>Безопасность СУБД базируется на нескольких ключевых принципах:</p>
        <ul>
          <li><strong>Конфиденциальность:</strong> Данные должны быть доступны только авторизованным пользователям. Это достигается через шифрование данных (в покое и при передаче) и строгий контроль доступа.</li>
          <li><strong>Целостность:</strong> Данные не должны быть изменены несанкционированно. Для этого применяются механизмы хэширования (например, SHA-256) и цифровые подписи.</li>
          <li><strong>Доступность:</strong> СУБД должна быть устойчива к атакам типа "отказ в обслуживании" (DDoS). Используются резервное копирование, репликация и кластеризация.</li>
          <li><strong>Аудит и мониторинг:</strong> Все действия с данными должны логироваться для возможности анализа инцидентов. Современные СУБД поддерживают встроенные механизмы аудита (например, Oracle Audit Vault).</li>
        </ul>
        <p>Основные угрозы для СУБД включают:</p>
        <ul>
          <li><strong>SQL-инъекции:</strong> Злоумышленник может внедрить вредоносный SQL-код через пользовательский ввод, если он не валидируется.</li>
          <li><strong>Утечка данных:</strong> Неправильная настройка прав доступа или отсутствие шифрования может привести к утечке конфиденциальной информации.</li>
          <li><strong>Атаки на учетные записи:</strong> Использование слабых паролей или отсутствие многофакторной аутентификации (MFA) делает СУБД уязвимой для брутфорс-атак.</li>
          <li><strong>Эксплуатация уязвимостей:</strong> Устаревшие версии СУБД могут содержать известные уязвимости (например, CVE-2023-2454 в PostgreSQL).</li>
        </ul>

        <h2>Схема защиты СУБД</h2>
        <div class="db-security-diagram" style="margin-bottom: 20px;">
          <div class="db-security-diagram-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="db-security-diagram-content" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Схема защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Клиент</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  WAF
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Защита от SQL-инъекций</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  TLS
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шифрование соединения</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  СУБД
                  <p style="font-size: 12px; margin: 5px 0 0;">PostgreSQL, Oracle</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  RBAC
                  <p style="font-size: 12px; margin: 5px 0 0;">Контроль доступа</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  TDE
                  <p style="font-size: 12px; margin: 5px 0 0;">Шифрование данных</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                  Хранилище данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Данные</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  SIEM
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мониторинг и аудит</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание схемы</h3>
              <p>Многоуровневая защита СУБД:</p>
              <ul>
                <li><strong>Пользователь:</strong> Клиент, взаимодействующий с СУБД.</li>
                <li><strong>WAF:</strong> Фильтрация SQL-инъекций.</li>
                <li><strong>TLS:</strong> Шифрование соединения.</li>
                <li><strong>СУБД:</strong> PostgreSQL, Oracle и др.</li>
                <li><strong>RBAC:</strong> Контроль доступа на уровне ролей.</li>
                <li><strong>TDE:</strong> Шифрование данных в покое.</li>
                <li><strong>Хранилище данных:</strong> Физическое хранилище.</li>
                <li><strong>SIEM:</strong> Мониторинг и аудит активности.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Основные меры защиты СУБД</h2>
        <div class="db-security-measures" style="margin-bottom: 20px;">
          <div class="db-security-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="db-security-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Меры защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Аутентификация и авторизация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">RBAC</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  Шифрование данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">TDE</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Ограничение доступа
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">IP-фильтрация</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Патчи и обновления
                  <p style="font-size: 12px; margin: 5px 0 0;">CVE</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Аудит и мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0;">Логи</p>
                </div>
                <div style="background-color: #f3e5f5; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Защита от инъекций
                  <p style="font-size: 12px; margin: 5px 0 0;">Параметризация</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание мер</h3>
              <p>Комплексный подход к защите СУБД:</p>
              <ul>
                <li><strong>Аутентификация и авторизация:</strong> RBAC и MFA.</li>
                <li><strong>Шифрование данных:</strong> TDE и TLS (AES).</li>
                <li><strong>Ограничение доступа:</strong> IP-фильтрация, VPN.</li>
                <li><strong>Патчи и обновления:</strong> Устранение уязвимостей (CVE).</li>
                <li><strong>Аудит и мониторинг:</strong> Логирование запросов (SIEM).</li>
                <li><strong>Защита от инъекций:</strong> Параметризованные запросы.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Рекомендации по защите СУБД</h2>
        <ol>
          <li>Используйте минимальные привилегии для учетных записей (принцип наименьших привилегий).</li>
          <li>Шифруйте данные как в покое, так и при передаче, используя современные алгоритмы (AES, TLS).</li>
          <li>Регулярно обновляйте СУБД и следите за новыми уязвимостями (CVE).</li>
          <li>Настройте мониторинг и аудит для быстрого обнаружения инцидентов.</li>
          <li>Изолируйте СУБД от публичного доступа, используйте VPN для удаленного подключения.</li>
        </ol>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadCloudSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность облачных технологий</h1>
        <p>Безопасность облачных технологий включает защиту данных, приложений и инфраструктуры, размещённых в облаке, от утечек, атак и несанкционированного доступа.</p>

        <h2>Теоретические основы безопасности облачных технологий</h2>
        <p>Безопасность в облаке основывается на модели разделяемой ответственности (Shared Responsibility Model):</p>
        <ul>
          <li><strong>Провайдер облака:</strong> Отвечает за безопасность инфраструктуры (физические серверы, гипервизоры). Например, AWS обеспечивает безопасность своих дата-центров.</li>
          <li><strong>Клиент:</strong> Отвечает за безопасность данных, приложений и конфигураций (например, настройка IAM, шифрование данных).</li>
          <li><strong>Модель "Defense in Depth":</strong> Использование нескольких уровней защиты: шифрование, IAM, мониторинг, WAF.</li>
          <li><strong>Zero Trust:</strong> Принцип "никому не доверяй" — каждый запрос должен быть аутентифицирован и авторизован, даже внутри облака.</li>
        </ul>
        <p>Основные угрозы в облаке:</p>
        <ul>
          <li><strong>Утечка данных:</strong> Неправильная настройка хранилищ (например, публичный доступ к S3-бакетам).</li>
          <li><strong>Компрометация учетных записей:</strong> Кража ключей API или учетных данных через фишинг.</li>
          <li><strong>DDoS-атаки:</strong> Атаки на облачные приложения, приводящие к простоям.</li>
          <li><strong>Уязвимости контейнеров:</strong> Использование уязвимых образов Docker (например, CVE-2020-8558 в Kubernetes).</li>
        </ul>

        <h2>Схема архитектуры облачной безопасности</h2>
        <div class="cloud-security-diagram" style="margin-bottom: 20px;">
          <div class="cloud-security-diagram-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="cloud-security-diagram-content" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Схема защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Клиент</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px;">
                  Cloudflare
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">DDoS-защита</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px;">
                  TLS
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шифрование</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  Облако
                  <p style="font-size: 12px; margin: 5px 0 0;">AWS, Azure</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  IAM
                  <p style="font-size: 12px; margin: 5px 0 0;">Контроль доступа</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px;">
                  KMS
                  <p style="font-size: 12px; margin: 5px 0 0;">Шифрование данных</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px;">
                  Данные
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">S3, RDS</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px;">
                  CloudTrail
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аудит</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание схемы</h3>
              <p>Многоуровневая защита облачной инфраструктуры:</p>
              <ul>
                <li><strong>Пользователь:</strong> Клиент, взаимодействующий с облаком.</li>
                <li><strong>Cloudflare:</strong> Защита от DDoS-атак.</li>
                <li><strong>TLS:</strong> Шифрование соединения.</li>
                <li><strong>Облако:</strong> AWS, Azure и др.</li>
                <li><strong>IAM:</strong> Контроль доступа через роли.</li>
                <li><strong>KMS:</strong> Шифрование данных в облаке.</li>
                <li><strong>Данные:</strong> Хранилища (S3, RDS).</li>
                <li><strong>CloudTrail:</strong> Аудит и мониторинг действий.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Основные меры защиты облачных технологий</h2>
        <div class="cloud-security-measures" style="margin-bottom: 20px;">
          <div class="cloud-security-measures-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="cloud-security-measures-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Меры защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #7b1fa2; padding: 8px; border-radius: 5px; width: 200px;">
                  Шифрование данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">KMS</p>
                </div>
                <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px;">
                  Контроль доступа
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">IAM</p>
                </div>
                <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px;">
                  Мониторинг и аудит
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">CloudTrail</p>
                </div>
                <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Защита от DDoS
                  <p style="font-size: 12px; margin: 5px 0 0;">AWS Shield</p>
                </div>
                <div style="background-color: #e1bee7; padding: 8px; border-radius: 5px; width: 200px; color: #000;">
                  Обновление ПО
                  <p style="font-size: 12px; margin: 5px 0 0;">CVE</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание мер</h3>
              <p>Комплексный подход к защите облака:</p>
              <ul>
                <li><strong>Шифрование данных:</strong> KMS для шифрования (AES-256).</li>
                <li><strong>Контроль доступа:</strong> IAM и MFA.</li>
                <li><strong>Мониторинг и аудит:</strong> Логирование (CloudTrail).</li>
                <li><strong>Защита от DDoS:</strong> AWS Shield, Cloudflare.</li>
                <li><strong>Обновление ПО:</strong> Устранение уязвимостей (CVE).</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Рекомендации по защите облачных технологий</h2>
        <ol>
          <li>Шифруйте данные в облаке с помощью KMS и современных алгоритмов.</li>
          <li>Используйте IAM и MFA для строгого контроля доступа.</li>
          <li>Настройте мониторинг и аудит с помощью CloudTrail и SIEM.</li>
          <li>Внедрите защиту от DDoS (например, Cloudflare, AWS Shield).</li>
          <li>Регулярно обновляйте облачные сервисы и приложения.</li>
        </ol>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadIoTSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность IoT</h1>
        <p>Интернет вещей (IoT) представляет собой экосистему устройств, подключённых к сети, таких как умные камеры, датчики, термостаты, медицинские устройства, носимые гаджеты и промышленные системы. Эти устройства собирают, обрабатывают и передают данные, часто в реальном времени, что делает их критически важными для автоматизации, мониторинга и управления. Однако IoT-устройства имеют ограниченные вычислительные ресурсы, используют устаревшие протоколы и часто поставляются с настройками по умолчанию, что делает их уязвимыми для атак. Безопасность IoT требует комплексного подхода, включая защиту устройств, данных, сетей и серверов, а также обеспечения конфиденциальности, целостности и доступности (CIA: Confidentiality, Integrity, Availability).</p>
  
        <h2>Теоретические основы безопасности IoT</h2>
        <p>Безопасность IoT базируется на нескольких ключевых концепциях:</p>
        <ul>
          <li><strong>Ограниченные ресурсы:</strong> IoT-устройства часто имеют ограниченную вычислительную мощность, память и энергию, что затрудняет внедрение сложных механизмов защиты, таких как современные алгоритмы шифрования или антивирусное ПО. Например, датчик температуры в умном доме может не поддерживать AES-256 из-за ограничений процессора.</li>
          <li><strong>Разнородность устройств:</strong> Экосистема IoT включает устройства от разных производителей с различными операционными системами (RTOS, Linux, проприетарные ОС) и протоколами (MQTT, CoAP, HTTP). Это усложняет стандартизацию мер безопасности.</li>
          <li><strong>Масштабируемость:</strong> В крупных IoT-сетях (например, в умных городах) могут быть миллионы устройств, что требует автоматизированных решений для управления безопасностью, таких как централизованные шлюзы и системы мониторинга.</li>
          <li><strong>Устаревшие протоколы:</strong> Многие IoT-устройства используют протоколы, такие как MQTT или CoAP, которые изначально не были разработаны с учётом безопасности. Например, MQTT без TLS уязвим для перехвата данных.</li>
          <li><strong>Физическая доступность:</strong> IoT-устройства часто находятся в общедоступных местах (например, датчики на улице), что делает их уязвимыми для физических атак, таких как вскрытие или подмена.</li>
          <li><strong>Принципы Zero Trust:</strong> В IoT-сетях нельзя доверять ни одному устройству по умолчанию. Каждый запрос должен быть аутентифицирован и авторизован, даже если устройство находится внутри сети.</li>
        </ul>
  
        <h2>Основные угрозы для IoT</h2>
        <p>IoT-устройства сталкиваются с широким спектром угроз, которые могут привести к компрометации данных, нарушению работы систем или использованию устройств в злонамеренных целях. Вот основные угрозы:</p>
        <ul>
          <li><strong>Ботнеты:</strong> Злоумышленники заражают IoT-устройства для создания ботнетов, которые используются для DDoS-атак. Например, ботнет Mirai в 2016 году заразил устройства с паролями по умолчанию и использовал их для атаки на Dyn, нарушив работу крупных сервисов, таких как Twitter и Netflix.</li>
          <li><strong>Перехват данных:</strong> Многие IoT-устройства передают данные по незашифрованным каналам (например, через HTTP или MQTT без TLS), что позволяет злоумышленникам перехватывать конфиденциальную информацию, такую как видеопотоки с камер или медицинские данные.</li>
          <li><strong>Физические атаки:</strong> Устройства, расположенные в общедоступных местах, могут быть вскрыты, прошиты или заменены. Например, злоумышленник может подключиться к умному счётчику электроэнергии и изменить показания.</li>
          <li><strong>Уязвимости прошивок:</strong> Устаревшие прошивки содержат известные уязвимости, которые не устраняются из-за отсутствия обновлений. Например, CVE-2021-28372 в прошивке умных устройств позволяла удалённое выполнение кода (RCE).</li>
          <li><strong>Слабые пароли:</strong> Многие устройства поставляются с паролями по умолчанию (например, admin/admin), которые легко подбираются. Это одна из основных причин заражения устройств ботнетами.</li>
          <li><strong>Атаки на протоколы:</strong> Протоколы, такие как Zigbee или BLE (Bluetooth Low Energy), могут быть уязвимы к атакам, таким как перехват ключей или подмена устройств (device spoofing).</li>
          <li><strong>Отказ в обслуживании (DoS):</strong> Злоумышленники могут перегрузить устройство или сеть, отправив большое количество запросов, что особенно опасно для устройств с ограниченными ресурсами.</li>
          <li><strong>Социальная инженерия:</strong> Пользователи IoT-устройств могут стать жертвами фишинга, что позволяет злоумышленникам получить доступ к управляющим приложениям или облачным сервисам.</li>
          <li><strong>Утечка данных:</strong> Неправильная конфигурация облачных сервисов, к которым подключены IoT-устройства (например, публичный доступ к S3-бакету), может привести к утечке данных.</li>
        </ul>
  
        <h2>Основные принципы защиты IoT</h2>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Аспект</th>
                <th>Описание</th>
                <th>Пример применения</th>
                <th>Рекомендации</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Сегментация сети</strong></td>
                <td>Изоляция IoT-устройств в отдельной сети для ограничения распространения атак.</td>
                <td>Создание VLAN для умных камер, изолированной от корпоративной сети.</td>
                <td>Используйте VLAN или SD-WAN для изоляции. Настройте межсетевые экраны для фильтрации трафика.</td>
              </tr>
              <tr>
                <td><strong>Шифрование</strong></td>
                <td>Использование шифрования для защиты данных при передаче и хранении.</td>
                <td>Настройка TLS для связи между IoT-устройством и сервером.</td>
                <td>Применяйте TLS 1.3 или DTLS для устройств с ограниченными ресурсами. Используйте сертификаты для аутентификации.</td>
              </tr>
              <tr>
                <td><strong>Контроль доступа</strong></td>
                <td>Ограничение доступа к устройствам с помощью аутентификации и авторизации.</td>
                <td>Использование уникальных паролей и сертификатов для каждого устройства.</td>
                <td>Используйте OAuth 2.0 или сертификаты X.509. Отключите доступ по умолчанию (admin/admin).</td>
              </tr>
              <tr>
                <td><strong>Обновление ПО</strong></td>
                <td>Регулярное обновление прошивок IoT-устройств для устранения уязвимостей.</td>
                <td>Обновление прошивки умного термостата для устранения CVE-2021-28372.</td>
                <td>Настройте OTA-обновления (Over-The-Air). Проверяйте подписи обновлений для защиты от подмены.</td>
              </tr>
              <tr>
                <td><strong>Мониторинг</strong></td>
                <td>Использование систем мониторинга для обнаружения аномалий в поведении устройств.</td>
                <td>Настройка SIEM для анализа логов IoT-устройств.</td>
                <td>Используйте SIEM (Splunk, QRadar) или специализированные решения (Azure Defender for IoT). Настройте оповещения на аномалии.</td>
              </tr>
              <tr>
                <td><strong>Физическая безопасность</strong></td>
                <td>Защита устройств от физического доступа и манипуляций.</td>
                <td>Установка датчиков в труднодоступных местах с защитой от вскрытия.</td>
                <td>Используйте tamper-proof корпуса. Установите видеонаблюдение в зонах с устройствами.</td>
              </tr>
              <tr>
                <td><strong>Минимизация данных</strong></td>
                <td>Сбор и хранение только необходимых данных для минимизации рисков утечек.</td>
                <td>Ограничение сбора данных умной камеры только видеопотоком без аудио.</td>
                <td>Применяйте принцип минимизации данных (Data Minimization). Удаляйте устаревшие данные.</td>
              </tr>
              <tr>
                <td><strong>Безопасная разработка</strong></td>
                <td>Внедрение практик безопасной разработки (Secure SDLC) для IoT-устройств.</td>
                <td>Проверка кода прошивки с помощью SAST (Static Application Security Testing).</td>
                <td>Используйте SAST (SonarQube) и DAST (OWASP ZAP) для проверки прошивок. Проводите пентесты.</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Схема архитектуры безопасности IoT</h2>
        <p>Архитектура безопасности IoT должна учитывать распределённый характер устройств, их взаимодействие с облаком и необходимость защиты на всех уровнях. Вот типичная схема:</p>
        <ul>
          <li><strong>Интернет:</strong> Внешняя сеть, через которую пользователи или злоумышленники могут взаимодействовать с IoT-устройствами. Здесь применяются межсетевые экраны и шифрование (TLS).</li>
          <li><strong>IoT-шлюз:</strong> Промежуточный уровень, который фильтрует и аутентифицирует запросы. Шлюз может выполнять функции маршрутизации, агрегации данных и защиты (например, с помощью OAuth).</li>
          <li><strong>IoT-устройства:</strong> Конечные устройства, которые собирают и передают данные. Они должны быть изолированы в отдельной сети (VLAN) и защищены от физического доступа.</li>
          <li><strong>Облако:</strong> Серверы, которые обрабатывают и хранят данные IoT-устройств. Здесь применяются меры защиты, такие как шифрование данных в покое (AES-256) и контроль доступа (IAM).</li>
        </ul>
        <div class="iot-security-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Интернет</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Брандмауэр (фильтрация)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">TLS (шифрование)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #000; padding: 5px; border-radius: 5px;">IoT-шлюз</div>
              <div style="background-color: #fff176; color: #000; padding: 5px; border-radius: 5px; margin-top: 5px;">Аутентификация (OAuth)</div>
            </div>
            <div style="border: 2px solid #ff9800; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #ff9800; color: #000; padding: 5px; border-radius: 5px;">IoT-устройства</div>
              <div style="background-color: #d32f2f; padding: 5px; border-radius: 5px; margin-top: 5px;">VLAN (сегментация)</div>
            </div>
            <div style="background-color: #b2dfdb; padding: 10px; border-radius: 5px; width: 200px;">Облако (AWS IoT)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (мониторинг)</div>
          </div>
        </div>
  
        <h2>Методы защиты IoT от кибератак</h2>
        <h3>Защита от ботнетов</h3>
        <ul>
          <li><strong>Смена паролей:</strong> Измените пароли по умолчанию на уникальные и сложные. Используйте генераторы паролей для создания надёжных комбинаций.</li>
          <li><strong>Сегментация:</strong> Изолируйте устройства в отдельной сети, чтобы ограничить их взаимодействие с другими системами.</li>
          <li><strong>Мониторинг:</strong> Используйте системы обнаружения аномалий (например, Azure Defender for IoT) для выявления подозрительного трафика, характерного для ботнетов.</li>
        </ul>
        <h3>Защита от перехвата данных</h3>
        <ul>
          <li><strong>Шифрование:</strong> Используйте TLS или DTLS для защиты данных при передаче. Для устройств с ограниченными ресурсами можно применять облегчённые алгоритмы, такие как ChaCha20.</li>
          <li><strong>Проверка сертификатов:</strong> Настройте проверку сертификатов на стороне устройства и сервера, чтобы предотвратить атаки типа "человек посередине" (MitM).</li>
          <li><strong>Шифрование в покое:</strong> Храните данные на устройстве в зашифрованном виде (например, с помощью AES-128).</li>
        </ul>
        <h3>Защита от физических атак</h3>
        <ul>
          <li><strong>Физическая защита:</strong> Используйте корпуса с защитой от вскрытия (tamper-proof). Устанавливайте устройства в труднодоступных местах.</li>
          <li><strong>Обнаружение вмешательства:</strong> Внедрите датчики вскрытия, которые отправляют уведомления при попытке физического доступа.</li>
          <li><strong>Шифрование прошивки:</strong> Зашифруйте прошивку устройства, чтобы предотвратить её модификацию при физическом доступе.</li>
        </ul>
        <h3>Защита от уязвимостей прошивок</h3>
        <ul>
          <li><strong>Обновления:</strong> Настройте автоматическое обновление прошивок через OTA. Убедитесь, что обновления подписаны цифровой подписью.</li>
          <li><strong>Сканирование уязвимостей:</strong> Используйте инструменты, такие как OpenVAS, для проверки прошивок на известные уязвимости.</li>
          <li><strong>Минимизация кода:</strong> Уменьшите размер прошивки, исключив ненужные функции, чтобы сократить поверхность атаки.</li>
        </ul>
  
        <h2>Средства защиты IoT</h2>
        <ul>
          <li><strong>IoT-шлюзы:</strong> Используйте шлюзы (например, AWS IoT Core, Azure IoT Hub) для фильтрации, аутентификации и агрегации данных.</li>
          <li><strong>Шифрование:</strong> Применяйте TLS или DTLS для защиты связи. Для устройств с ограниченными ресурсами используйте облегчённые алгоритмы (ChaCha20, Poly1305).</li>
          <li><strong>Мониторинг:</strong> Используйте решения, такие как Azure Defender for IoT или Nozomi Networks, для обнаружения угроз и аномалий.</li>
          <li><strong>Сегментация:</strong> Изолируйте IoT-устройства с помощью VLAN или SD-WAN. Настройте Network Access Control (NAC) для ограничения доступа.</li>
          <li><strong>Обновления:</strong> Настройте автоматическое обновление прошивок (OTA) с проверкой цифровой подписи (например, с помощью ECDSA).</li>
          <li><strong>Антивирусы:</strong> Для устройств на базе Linux используйте лёгкие антивирусы, такие как ClamAV.</li>
          <li><strong>DLP:</strong> Используйте системы предотвращения утечек данных (DLP) для контроля передачи данных с IoT-устройств.</li>
        </ul>
  
        <h2>Нормативные документы по защите IoT в России</h2>
        <p>В России защита IoT регулируется общими нормативными актами по информационной безопасности, а также стандартами, применимыми к IoT:</p>
        <ul>
          <li><strong>ГОСТ Р ИСО/МЭК 27001:</strong> Международный стандарт управления информационной безопасностью, адаптированный для России. Требует внедрения системы управления рисками для IoT.</li>
          <li><strong>Приказ ФСТЭК России № 239:</strong> Устанавливает требования к защите значимых объектов, включая IoT-устройства в составе КИИ.</li>
          <li><strong>ГОСТ Р 57580.1-2017:</strong> Описывает меры защиты информации в организациях, включая управление IoT-устройствами.</li>
        </ul>
  
        <h2>Рекомендации по защите IoT</h2>
        <ol>
          <li>Изолируйте IoT-устройства в отдельной сети с помощью VLAN или SD-WAN.</li>
          <li>Используйте шифрование (TLS, DTLS) для всех каналов связи. Применяйте облегчённые алгоритмы для устройств с ограниченными ресурсами.</li>
          <li>Настройте строгую аутентификацию (сертификаты X.509, OAuth 2.0). Отключите доступ по умолчанию.</li>
          <li>Регулярно обновляйте прошивки устройств через OTA с проверкой цифровой подписи.</li>
          <li>Внедрите мониторинг с помощью SIEM (Splunk, QRadar) или специализированных решений (Azure Defender for IoT).</li>
          <li>Обеспечьте физическую защиту устройств с помощью tamper-proof корпусов и видеонаблюдения.</li>
          <li>Минимизируйте сбор данных, удаляйте устаревшие данные и шифруйте хранимые данные.</li>
          <li>Проводите регулярные аудиты и тесты на проникновение для выявления уязвимостей.</li>
        </ol>
  
        <h2>Примеры атак на IoT</h2>
        <p>Вот несколько известных инцидентов, подчёркивающих важность защиты IoT:</p>
        <ul>
          <li><strong>Ботнет Mirai (2016):</strong> Злоумышленники заразили тысячи IoT-устройств (камер, роутеров) с использованием стандартных паролей. Ботнет использовался для проведения масштабных DDoS-атак, включая атаку на Dyn, которая нарушила работу крупных сервисов, таких как Twitter и Netflix.</li>
          <li><strong>Атака на умные камеры Ring (2019):</strong> Злоумышленники получили доступ к камерам Ring, используя украденные учётные данные, и шпионили за пользователями. Это подчёркивает важность двухфакторной аутентификации (2FA) и шифрования данных.</li>
          <li><strong>Уязвимость в медицинских устройствах (2017):</strong> FDA сообщила об уязвимостях в кардиостимуляторах St. Jude Medical, которые позволяли удалённо изменять настройки устройств. Это показало риски для IoT в здравоохранении и необходимость шифрования и обновлений.</li>
        </ul>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadMicroservicesSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность микросервисов</h1>
        <p>Микросервисная архитектура предполагает разделение приложения на небольшие независимые сервисы, которые взаимодействуют через API (обычно REST, gRPC или GraphQL). Это обеспечивает гибкость, масштабируемость и независимость разработки, но создаёт новые вызовы для безопасности. Микросервисы увеличивают поверхность атаки из-за большого количества взаимодействий, распределённой природы системы и использования контейнеров (например, Docker, Kubernetes). Безопасность микросервисов требует применения принципов Zero Trust, шифрования, строгого контроля доступа, мониторинга и автоматизации.</p>
  
        <h2>Теоретические основы безопасности микросервисов</h2>
        <p>Безопасность микросервисов базируется на следующих концепциях:</p>
        <ul>
          <li><strong>Распределённая архитектура:</strong> Микросервисы работают как независимые процессы, часто развёрнутые в контейнерах (Docker) и управляемые оркестраторами (Kubernetes). Это требует защиты каждого сервиса и их взаимодействия.</li>
          <li><strong>Zero Trust:</strong> В микросервисной архитектуре нельзя доверять ни одному сервису или запросу по умолчанию. Каждый запрос должен быть аутентифицирован и авторизован, даже внутри сети (east-west traffic).</li>
          <li><strong>API как точка входа:</strong> Микросервисы взаимодействуют через API, что делает их уязвимыми для атак, таких как SQL-инъекции, XSS или подделка запросов (CSRF).</li>
          <li><strong>Контейнеризация:</strong> Микросервисы часто разворачиваются в контейнерах, что требует защиты образов, управления доступом и изоляции контейнеров.</li>
          <li><strong>Сложность мониторинга:</strong> Распределённая природа микросервисов затрудняет мониторинг и обнаружение угроз. Требуются инструменты для распределённого трейсинга (Jaeger, Zipkin) и централизованного мониторинга (Prometheus).</li>
          <li><strong>DevSecOps:</strong> Безопасность должна быть интегрирована в процесс разработки (CI/CD), чтобы выявлять уязвимости на ранних этапах (например, с помощью SAST и DAST).</li>
          <li><strong>Сетевые взаимодействия:</strong> Микросервисы генерируют большое количество сетевого трафика (east-west traffic), который должен быть зашифрован и защищён от перехвата.</li>
        </ul>
  
        <h2>Основные угрозы для микросервисов</h2>
        <p>Микросервисная архитектура сталкивается с множеством угроз из-за своей распределённой природы и большого количества точек взаимодействия. Вот основные угрозы:</p>
        <ul>
          <li><strong>Атаки на API:</strong> Злоумышленники могут эксплуатировать уязвимости API, такие как SQL-инъекции, XSS, или использовать недостатки валидации данных. Например, отсутствие проверки входных данных может привести к инъекции кода.</li>
          <li><strong>Несанкционированный доступ:</strong> Компрометация токенов (например, JWT) или ключей API может позволить злоумышленникам получить доступ к сервисам. Например, утечка ключа API в репозитории GitHub может привести к компрометации.</li>
          <li><strong>Сетевые атаки:</strong> Если трафик между сервисами не зашифрован, злоумышленники могут перехватить данные (MitM-атаки) или подменить запросы (request spoofing).</li>
          <li><strong>Уязвимости контейнеров:</strong> Устаревшие образы Docker или Kubernetes могут содержать известные уязвимости (например, CVE-2021-41092 в Docker), которые позволяют удалённое выполнение кода (RCE).</li>
          <li><strong>Нарушение изоляции:</strong> Неправильная конфигурация Kubernetes (например, отсутствие Network Policies) может позволить одному скомпрометированному сервису атаковать другие.</li>
          <li><strong>DoS-атаки:</strong> Злоумышленники могут перегрузить сервис, отправив большое количество запросов, что особенно опасно для микросервисов с ограниченными ресурсами.</li>
          <li><strong>Утечка данных:</strong> Неправильная конфигурация хранилищ (например, публичный доступ к S3-бакету) или отсутствие шифрования может привести к утечке данных.</li>
          <li><strong>Сложность управления доступом:</strong> Большое количество сервисов усложняет управление доступом. Ошибки в настройке IAM (например, избыточные привилегии) могут привести к компрометации.</li>
          <li><strong>Атаки на зависимости:</strong> Использование устаревших библиотек (например, Log4j с CVE-2021-44228) в микросервисах может привести к эксплуатации уязвимостей.</li>
          <li><strong>Отсутствие мониторинга:</strong> Без распределённого трейсинга и мониторинга сложно обнаружить аномалии, такие как несанкционированный доступ или атака на API.</li>
        </ul>
  
        <h2>Основные принципы защиты микросервисов</h2>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Аспект</th>
                <th>Описание</th>
                <th>Пример применения</th>
                <th>Рекомендации</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Zero Trust</strong></td>
                <td>Каждый запрос между сервисами должен быть аутентифицирован и авторизован.</td>
                <td>Использование Istio для проверки всех запросов между сервисами.</td>
                <td>Внедрите Service Mesh (Istio, Linkerd) для реализации Zero Trust. Используйте mTLS для аутентификации.</td>
              </tr>
              <tr>
                <td><strong>Шифрование</strong></td>
                <td>Шифрование связи между сервисами и с внешними клиентами.</td>
                <td>Настройка mTLS (mutual TLS) для шифрования трафика между сервисами.</td>
                <td>Используйте mTLS для east-west трафика. Применяйте TLS 1.3 для внешних подключений.</td>
              </tr>
              <tr>
                <td><strong>API Gateway</strong></td>
                <td>Использование шлюза API для фильтрации и аутентификации запросов.</td>
                <td>Настройка Kong API Gateway для проверки токенов JWT.</td>
                <td>Используйте Kong, AWS API Gateway или NGINX. Настройте rate limiting и валидацию запросов.</td>
              </tr>
              <tr>
                <td><strong>Контроль доступа</strong></td>
                <td>Ограничение доступа между сервисами с помощью RBAC или ABAC.</td>
                <td>Настройка RBAC в Kubernetes для ограничения доступа сервисов.</td>
                <td>Применяйте RBAC или ABAC. Используйте IAM для управления доступом в облаке.</td>
              </tr>
              <tr>
                <td><strong>Мониторинг</strong></td>
                <td>Использование распределённого трейсинга и мониторинга для обнаружения аномалий.</td>
                <td>Настройка Jaeger для трейсинга запросов между сервисами.</td>
                <td>Используйте Jaeger или Zipkin для трейсинга, Prometheus для мониторинга, Grafana для визуализации.</td>
              </tr>
              <tr>
                <td><strong>Сегментация</strong></td>
                <td>Изоляция сервисов в контейнерах или сетевых пространствах.</td>
                <td>Использование Network Policies в Kubernetes для ограничения трафика.</td>
                <td>Настройте Network Policies. Используйте namespaces в Kubernetes для логической изоляции.</td>
              </tr>
              <tr>
                <td><strong>Обновление</strong></td>
                <td>Регулярное обновление зависимостей и контейнеров для устранения уязвимостей.</td>
                <td>Обновление образа Docker для устранения CVE-2021-41092.</td>
                <td>Используйте Trivy или Clair для сканирования образов. Автоматизируйте обновления через CI/CD.</td>
              </tr>
              <tr>
                <td><strong>Безопасная разработка</strong></td>
                <td>Внедрение практик DevSecOps для выявления уязвимостей на этапе разработки.</td>
                <td>Интеграция Snyk в CI/CD для проверки зависимостей.</td>
                <td>Используйте SAST (SonarQube), DAST (OWASP ZAP), SCA (Snyk). Проводите пентесты.</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Схема архитектуры безопасности микросервисов</h2>
        <p>Архитектура безопасности микросервисов должна учитывать распределённый характер системы, большое количество взаимодействий и необходимость защиты на всех уровнях. Вот типичная схема:</p>
        <ul>
          <li><strong>Клиент:</strong> Внешний пользователь или приложение, отправляющее запросы. Здесь применяются меры защиты, такие как JWT-аутентификация и TLS.</li>
          <li><strong>API Gateway:</strong> Единая точка входа, которая фильтрует запросы, выполняет аутентификацию (например, через JWT) и rate limiting.</li>
          <li><strong>Service Mesh:</strong> Слой управления трафиком, который обеспечивает шифрование (mTLS), аутентификацию и мониторинг между сервисами.</li>
          <li><strong>Микросервисы:</strong> Независимые сервисы, развёрнутые в контейнерах (Kubernetes). Они изолированы с помощью Network Policies и namespaces.</li>
          <li><strong>Хранилище данных:</strong> Базы данных или объектные хранилища (например, PostgreSQL, S3), которые должны быть зашифрованы и защищены от несанкционированного доступа.</li>
        </ul>
        <div class="microservices-security-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Клиент</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">API Gateway (Kong)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">JWT (аутентификация)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #000; padding: 5px; border-radius: 5px;">Service Mesh (Istio)</div>
              <div style="background-color: #fff176; color: #000; padding: 5px; border-radius: 5px; margin-top: 5px;">mTLS (шифрование)</div>
            </div>
            <div style="border: 2px solid #ff9800; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #ff9800; color: #000; padding: 5px; border-radius: 5px;">Микросервисы (Kubernetes)</div>
              <div style="background-color: #d32f2f; padding: 5px; border-radius: 5px; margin-top: 5px;">Network Policies</div>
            </div>
            <div style="background-color: #b2dfdb; padding: 10px; border-radius: 5px; width: 200px;">Хранилище (PostgreSQL)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Jaeger (трейсинг)</div>
          </div>
        </div>
  
        <h2>Методы защиты микросервисов от кибератак</h2>
        <h3>Защита от атак на API</h3>
        <ul>
          <li><strong>Валидация данных:</strong> Проверяйте все входные данные на стороне сервера, чтобы предотвратить инъекции (SQL, XSS).</li>
          <li><strong>Rate Limiting:</strong> Ограничивайте количество запросов через API Gateway, чтобы предотвратить DoS-атаки.</li>
          <li><strong>WAF:</strong> Используйте Web Application Firewall (например, AWS WAF) для защиты от атак на API.</li>
        </ul>
        <h3>Защита от несанкционированного доступа</h3>
        <ul>
          <li><strong>Аутентификация:</strong> Используйте JWT или OAuth 2.0 для аутентификации запросов. Настройте ротацию токенов.</li>
          <li><strong>IAM:</strong> Применяйте принцип наименьших привилегий (Least Privilege) для ролей IAM в облаке.</li>
          <li><strong>Секреты:</strong> Храните ключи API и секреты в менеджерах секретов (например, HashiCorp Vault, AWS Secrets Manager).</li>
        </ul>
        <h3>Защита от сетевых атак</h3>
        <ul>
          <li><strong>mTLS:</strong> Используйте mutual TLS для шифрования и аутентификации трафика между сервисами.</li>
          <li><strong>Сегментация:</strong> Настройте Network Policies в Kubernetes для ограничения трафика между сервисами.</li>
          <li><strong>IDS/IPS:</strong> Используйте системы обнаружения и предотвращения вторжений (например, Falco) для мониторинга сетевого трафика.</li>
        </ul>
        <h3>Защита от уязвимостей контейнеров</h3>
        <ul>
          <li><strong>Сканирование:</strong> Используйте Trivy или Clair для проверки образов Docker на уязвимости.</li>
          <li><strong>Обновления:</strong> Регулярно обновляйте образы и зависимости. Используйте минимальные образы (например, Alpine).</li>
          <li><strong>Изоляция:</strong> Запускайте контейнеры с минимальными привилегиями (non-root) и используйте seccomp для ограничения системных вызовов.</li>
        </ul>
  
        <h2>Средства защиты микросервисов</h2>
        <ul>
          <li><strong>API Gateway:</strong> Используйте Kong, AWS API Gateway или NGINX для фильтрации, аутентификации и rate limiting.</li>
          <li><strong>Service Mesh:</strong> Применяйте Istio или Linkerd для шифрования (mTLS), управления трафиком и мониторинга.</li>
          <li><strong>Мониторинг:</strong> Используйте Jaeger или Zipkin для трейсинга, Prometheus для мониторинга, Grafana для визуализации.</li>
          <li><strong>Сегментация:</strong> Настройте Network Policies и namespaces в Kubernetes для изоляции сервисов.</li>
          <li><strong>Сканирование:</strong> Используйте Trivy, Clair или Snyk для проверки уязвимостей контейнеров и зависимостей.</li>
          <li><strong>SIEM:</strong> Используйте Splunk или QRadar для централизованного анализа логов.</li>
          <li><strong>WAF:</strong> Используйте AWS WAF или Cloudflare для защиты API от атак.</li>
          <li><strong>DLP:</strong> Используйте системы предотвращения утечек данных (например, Symantec DLP) для защиты данных.</li>
        </ul>
  
        <h2>Нормативные документы по защите микросервисов в России</h2>
        <p>В России защита микросервисов регулируется общими нормативными актами по информационной безопасности:</p>
        <ul>
          <li><strong>ГОСТ Р ИСО/МЭК 27001:</strong> Требует внедрения системы управления рисками для микросервисов.</li>
          <li><strong>ФЗ-149 "Об информации":</strong> Устанавливает общие требования к защите информации, включая данные, обрабатываемые микросервисами.</li>
          <li><strong>ГОСТ Р 57580.1-2017:</strong> Описывает меры защиты информации в организациях, включая управление доступом и мониторинг.</li>
        </ul>
  
        <h2>Рекомендации по защите микросервисов</h2>
        <ol>
          <li>Внедрите Zero Trust с помощью Service Mesh (Istio, Linkerd) и mTLS.</li>
          <li>Используйте API Gateway (Kong, AWS API Gateway) для фильтрации и аутентификации запросов.</li>
          <li>Шифруйте трафик между сервисами с помощью mTLS и внешний трафик с помощью TLS 1.3.</li>
          <li>Настройте Network Policies и namespaces в Kubernetes для сегментации.</li>
          <li>Регулярно сканируйте контейнеры и зависимости на уязвимости (Trivy, Snyk).</li>
          <li>Внедрите мониторинг и трейсинг (Prometheus, Jaeger, Grafana).</li>
          <li>Интегрируйте DevSecOps: используйте SAST, DAST и SCA в CI/CD.</li>
          <li>Храните секреты в менеджерах секретов (HashiCorp Vault, AWS Secrets Manager).</li>
          <li>Проводите регулярные аудиты и тесты на проникновение.</li>
        </ol>
  
        <h2>Примеры атак на микросервисы</h2>
        <p>Вот несколько известных инцидентов, подчёркивающих важность защиты микросервисов:</p>
        <ul>
          <li><strong>Утечка данных Capital One (2019):</strong> Злоумышленник использовал неправильно настроенные роли IAM в AWS, чтобы получить доступ к S3-бакету через уязвимость в API микросервиса. Это привело к утечке данных 100 миллионов клиентов.</li>
          <li><strong>Log4Shell (2021):</strong> Уязвимость в Log4j (CVE-2021-44228) затронула множество микросервисов, использующих эту библиотеку. Злоумышленники могли выполнять произвольный код, что подчёркивает важность управления зависимостями.</li>
          <li><strong>Атака на Kubernetes (2020):</strong> Злоумышленники скомпрометировали кластер Kubernetes из-за отсутствия Network Policies, что позволило им получить доступ к другим сервисам и украсть данные.</li>
        </ul>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadMobileSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Мобильная безопасность</h1>
        <p>Мобильная безопасность фокусируется на защите смартфонов, планшетов и приложений от уязвимостей, атак и утечек данных. Мобильные устройства — критически важный элемент экосистемы, требующий защиты на уровне ОС, приложений, данных и сети. Этот раздел охватывает теоретические основы, угрозы, инструменты, методы защиты и примеры инцидентов.</p>
  
        <h2>Теоретические основы мобильной безопасности</h2>
        <p>Мобильная безопасность опирается на теории операционных систем, криптографии, управления доступом, анализа сетевых протоколов, человеческого фактора и надежности систем. iOS и Android используют разные архитектуры, но общие принципы безопасности применимы к обоим.</p>
        <ul>
          <li><strong>Модель изоляции:</strong> iOS использует App Sandbox, Android — SELinux и UID-based изоляцию. Теория Clark-Wilson (1987) обеспечивает целостность данных, минимизируя несанкционированные изменения. Теория Bell-LaPadula ограничивает доступ приложений к системным ресурсам. Уязвимости, такие как CVE-2021-30807 в iOS, обходят sandboxing через ошибки ядра.</li>
          <li><strong>Криптография:</strong> iOS использует Secure Enclave (AES-256, ECDSA), Android — Hardware-backed Keystore. Теория стойкости к атакам по сторонним каналам (Meltdown, CVE-2017-5754) требует изоляции ключей на уровне железа. Алгоритмы PBKDF2 и Argon2 защищают пароли. Уязвимости, такие как CVE-2020-9992, связаны с ошибками в шифровании.</li>
          <li><strong>Моделирование угроз:</strong> OWASP Mobile Top 10 (2023) описывает риски: Improper Platform Usage, Insecure Data Storage, Insecure Communication. STRIDE-модель анализирует атаки (Spoofing через фишинг, Tampering через реверс-инжиниринг). DREAD-модель оценивает критичность уязвимостей, например, Insecure Data Storage имеет высокий рейтинг из-за массовости устройств.</li>
          <li><strong>Сетевые протоколы:</strong> Мобильные приложения используют HTTPS/TLS 1.3. Теория MitM-атак требует certificate pinning и HSTS. Уязвимости, такие как CVE-2019-8690 в Android, связаны с ошибками в парсинге сертификатов. Протоколы WebRTC и VoIP (например, CVE-2019-3568 в WhatsApp) уязвимы для перехвата.</li>
          <li><strong>Обнаружение аномалий:</strong> Алгоритмы SVM и Random Forest в EDR (CrowdStrike) анализируют системные вызовы. Байесовские сети выявляют аномалии в поведении приложений (например, несанкционированный доступ к камере). Скрытые марковские модели (HMM) моделируют последовательности событий для обнаружения вредоносного ПО.</li>
          <li><strong>Человеческий фактор:</strong> Теория HCI показывает, что пользователи игнорируют предупреждения безопасности. Модель MITRE ATT&CK (Tactic: Initial Access) описывает SMS-фишинг и установку вредоносных приложений. Теория когнитивных искажений (optimism bias) объясняет, почему пользователи устанавливают приложения из непроверенных источников.</li>
          <li><strong>Теория игр:</strong> Моделирует выбор атакующего (zero-day эксплойт, фишинг) и защитника (MDM, патчи). Равновесие Нэша оптимизирует стратегии, минимизируя затраты на защиту. Например, MDM с высоким уровнем ограничений снижает удобство для пользователей.</li>
          <li><strong>Формальная верификация:</strong> Теория Hoare Logic проверяет корректность кода приложений. Инструменты, такие как Infer, анализируют код на ошибки (null pointer dereference). Уязвимости, такие как CVE-2020-0022 в Android, связаны с ошибками в нативном коде.</li>
          <li><strong>Теория надежности систем:</strong> Модель отказоустойчивости требует защиты от DoS-атак на уровне приложений. Теория очередей (M/M/c) моделирует производительность под нагрузкой. Уязвимости, такие как CVE-2021-0920 в Android, приводят к сбоям через неэффективную обработку ресурсов.</li>
          <li><strong>Стандарты и нормативы:</strong> NIST SP 800-124, ISO/IEC 27036, ФСТЭК (приказ № 239) задают требования к управлению устройствами. NIST требует шифрования данных и регулярных обновлений. ФСТЭК регулирует защиту в КИИ, требуя анализа рисков по ГОСТ 57580.</li>
          <li><strong>Теория информационного потока:</strong> Модель Denning (1976) предотвращает утечки данных через анализ потоков. Например, Insecure Data Storage нарушает принцип наименьшей привилегии. Инструменты Taint Analysis проверяют потоки данных в приложениях.</li>
          <li><strong>Теория системного анализа:</strong> CVSS оценивает критичность уязвимостей (например, CVSS 9.8 для Pegasus). Теория зависимостей выявляет риски в библиотеках (например, CVE-2019-11932 в WhatsApp). Модель CAP (Consistency, Availability, Partition Tolerance) анализирует компромиссы в мобильных приложениях.</li>
          <li><strong>Теория управления рисками:</strong> Модель FAIR (Factor Analysis of Information Risk) количественно оценивает риски (например, вероятность фишинга). Теория NIST SP 800-30 требует регулярного анализа рисков для мобильных устройств.</li>
        </ul>
        <p>Угрозы возникают из-за:</p>
        <ul>
          <li><strong>Неправильной конфигурации:</strong> Отсутствие шифрования или слабые политики MDM.</li>
          <li><strong>Уязвимостей ОС:</strong> Zero-day эксплойты, такие как Pegasus (2021).</li>
          <li><strong>Человеческого фактора:</strong> Установка приложений из непроверенных источников.</li>
          <li><strong>Слабой аутентификации:</strong> Отсутствие MFA или слабые пароли.</li>
        </ul>
  
        <h2>Схема уровней защиты мобильных устройств</h2>
        <div class="mobile-security-method" style="margin-bottom: 20px;">
          <div class="mobile-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="mobile-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  ОС
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Патчи</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Приложения
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Sandbox</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Данные
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Шифрование</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сеть
                  <p style="font-size: 12px; margin: 5px 0 0;">VPN</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Устройство
                  <p style="font-size: 12px; margin: 5px 0 0;">MDM</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0;">MFA</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">EDR</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней защиты</h3>
              <p>Многоуровневая защита охватывает все аспекты мобильных устройств:</p>
              <ul>
                <li><strong>ОС:</strong> Регулярные обновления и патчи безопасности.</li>
                <li><strong>Приложения:</strong> Изоляция через sandboxing и SELinux.</li>
                <li><strong>Данные:</strong> Шифрование с AES-256 (Secure Enclave, Keystore).</li>
                <li><strong>Сеть:</strong> Защита трафика с VPN, TLS, HSTS.</li>
                <li><strong>Устройство:</strong> Контроль через MDM (Intune).</li>
                <li><strong>Пользователь:</strong> Аутентификация с MFA, биометрией.</li>
                <li><strong>Мониторинг:</strong> Обнаружение угроз с EDR (CrowdStrike).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Уязвимости мобильных устройств</h2>
        <p>Уязвимости по OWASP Mobile Top 10 (2023):</p>
        <ul>
          <li><strong>Improper Platform Usage:</strong> Неправильное использование API. Пример: хранение ключей в SharedPreferences.</li>
          <li><strong>Insecure Data Storage:</strong> Отсутствие шифрования. Пример: утечка данных через SQLite.</li>
          <li><strong>Insecure Communication:</strong> Передача данных без TLS. Пример: CVE-2020-9992 в iOS.</li>
          <li><strong>Insecure Authentication:</strong> Слабые пароли или отсутствие MFA.</li>
          <li><strong>Code Tampering:</strong> Модификация кода через реверс-инжиниринг.</li>
          <li><strong>Reverse Engineering:</strong> Декомпиляция для извлечения секретов.</li>
          <li><strong>Extraneous Functionality:</strong> Скрытые функции в коде, раскрывающие данные.</li>
        </ul>
  
        <h2>Инструменты</h2>
        <p>Для анализа и защиты мобильных устройств используются следующие инструменты:</p>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Инструмент</th>
                <th>Функция</th>
                <th>Применение</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>MobSF</td>
                <td>Статический анализ</td>
                <td>Проверка кода приложений</td>
              </tr>
              <tr>
                <td>Drozer</td>
                <td>Динамический анализ</td>
                <td>Тестирование Android-приложений</td>
              </tr>
              <tr>
                <td>Frida</td>
                <td>Реверс-инжиниринг</td>
                <td>Анализ runtime-поведения</td>
              </tr>
              <tr>
                <td>Intune</td>
                <td>MDM</td>
                <td>Управление устройствами</td>
              </tr>
              <tr>
                <td>CrowdStrike</td>
                <td>EDR</td>
                <td>Обнаружение угроз</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Рекомендации</h2>
        <p>Для обеспечения мобильной безопасности:</p>
        <ol>
          <li>Обновляйте ОС и приложения для устранения уязвимостей.</li>
          <li>Шифруйте данные с AES-256 (Secure Enclave, Keystore).</li>
          <li>Используйте TLS, HSTS, certificate pinning для сети.</li>
          <li>Внедрите MDM (Intune) для управления устройствами.</li>
          <li>Настройте MFA и биометрию для аутентификации.</li>
          <li>Тестируйте приложения с MobSF, Drozer, Frida.</li>
          <li>Мониторьте устройства с EDR (CrowdStrike).</li>
          <li>Проводите аудит кода и зависимостей (Snyk).</li>
        </ol>
  
        <h2>Примеры атак</h2>
        <p>Реальные инциденты:</p>
        <ul>
          <li><strong>Pegasus (2021):</strong> Zero-day эксплойт через iMessage заразил iOS-устройства.</li>
          <li><strong>WhatsApp (2019):</strong> Уязвимость VoIP (CVE-2019-3568) установила шпионское ПО.</li>
          <li><strong>Joker Malware (2020):</strong> Вредоносное ПО в Google Play крало данные.</li>
        </ul>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadAPISecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность API</h1>
        <p>Безопасность API фокусируется на защите программных интерфейсов, обеспечивающих взаимодействие между сервисами, от уязвимостей, атак и утечек данных. API — критический компонент современных приложений, требующий комплексного подхода к аутентификации, авторизации, валидации и мониторингу. Этот раздел охватывает теоретические основы, угрозы, инструменты, методы защиты и примеры инцидентов.</p>

        <h2>Теоретические основы безопасности API</h2>
        <p>Безопасность API опирается на фундаментальные теории информационной безопасности, включая управление доступом, криптографию, анализ сетевых протоколов, моделирование угроз и поведенческий анализ. Эти теории формируют подходы к защите API от атак, таких как инъекции, несанкционированный доступ и утечки данных.</p>
        <ul>
          <li><strong>Модель управления доступом:</strong> Основана на RBAC (Role-Based Access Control), ABAC (Attribute-Based Access Control) и стандартах OAuth 2.0/OpenID Connect. Теория Bell-LaPadula (1973) регулирует доступ к данным, предотвращая утечки через ограничение scopes. Модель Biba (1977) обеспечивает целостность, минимизируя несанкционированные изменения. Неправильная настройка OAuth (например, слабые scopes) приводит к атакам типа BOLA (Broken Object Level Authorization).</li>
          <li><strong>Криптография:</strong> API используют TLS 1.3 (RFC 8446) для шифрования трафика и JWT (JSON Web Tokens, RFC 7519) для аутентификации. Алгоритмы HMAC-SHA256 и ECDSA обеспечивают целостность и подлинность токенов. Теория атак по сторонним каналам (например, Timing Attacks, CVE-2016-10555) требует использования constant-time операций. Уязвимости, такие как Heartbleed (CVE-2014-0160), подчеркивают важность проверки сертификатов и ротации ключей.</li>
          <li><strong>Моделирование угроз:</strong> STRIDE-модель (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) применяется для анализа рисков. OWASP API Security Top 10 (2023) детализирует угрозы: BOLA, Broken Authentication, Excessive Data Exposure. DREAD-модель (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) оценивает критичность уязвимостей. Например, BOLA имеет высокий DREAD-рейтинг из-за простоты эксплуатации.</li>
          <li><strong>Сетевые протоколы:</strong> REST, GraphQL и SOAP используют HTTP/2 или WebSocket. Теория конечных автоматов описывает парсинг запросов, но слабые парсеры (например, CVE-2021-22931 в Node.js) уязвимы для инъекций. Протоколы gRPC требуют особого внимания к сериализации (Protobuf), где ошибки приводят к DoS. Теория MitM-атак требует проверки сертификатов (certificate pinning) и HSTS (HTTP Strict Transport Security).</li>
          <li><strong>Обнаружение аномалий:</strong> Машинное обучение (LSTM, алгоритмы кластеризации k-means) анализирует трафик API. Байесовские сети моделируют вероятность атак (например, SQL-инъекций). Скрытые марковские модели (HMM) выявляют аномалии в последовательности запросов. Инструменты, такие как Wallarm, используют эти подходы для обнаружения brute-force или XSS.</li>
          <li><strong>Теория игр:</strong> Моделирует взаимодействие атакующих и защитников. Злоумышленник выбирает стратегию (инъекция, утечка токенов), защитник — контрмеры (WAF, rate limiting). Равновесие Нэша оптимизирует политики безопасности, минимизируя затраты. Например, WAF с высоким уровнем ложных срабатываний снижает эффективность защиты.</li>
          <li><strong>Формальная верификация:</strong> Теория TLA+ (Temporal Logic of Actions) используется для проверки корректности API-контрактов (OpenAPI/Swagger). Модель проверяет инварианты, такие как отсутствие утечек данных при валидации. Уязвимости, такие как CVE-2020-28282 в Swagger, связаны с ошибками парсинга спецификаций.</li>
          <li><strong>Человеческий фактор:</strong> Теория HCI (Human-Computer Interaction) объясняет утечки API-ключей через GitHub или Postman (hardcoded credentials). Модель MITRE ATT&CK (Tactic: Credential Access) описывает атаки через фишинг для получения токенов. Теория когнитивных искажений (confirmation bias) показывает, почему разработчики игнорируют предупреждения о слабых настройках.</li>
          <li><strong>Теория надежности систем:</strong> Модель отказоустойчивости (fault tolerance) требует защиты от DoS-атак. Теория очередей (M/M/1) моделирует производительность API под нагрузкой. Уязвимости, такие как CVE-2021-21315 в Express.js, приводят к DoS через неэффективную обработку запросов.</li>
          <li><strong>Стандарты и нормативы:</strong> OWASP API Security Top 10, NIST SP 800-95, ISO/IEC 27034 (Application Security) и ФСТЭК (приказ № 239) задают требования. Например, NIST требует валидации всех входных данных и ротации ключей каждые 90 дней. ФСТЭК регулирует защиту API в КИИ, требуя анализа рисков по ГОСТ 57580.</li>
          <li><strong>Теория информационного потока:</strong> Модель Denning (1976) анализирует потоки данных в API, предотвращая утечки. Например, Excessive Data Exposure нарушает принцип наименьшей привилегии (least privilege). Инструменты, такие как Taint Analysis, проверяют потоки данных на уровне кода.</li>
          <li><strong>Теория системного анализа:</strong> Модель CVSS (Common Vulnerability Scoring System) оценивает критичность уязвимостей (например, CVSS 9.8 для CVE-2018-13379). Теория зависимостей (dependency graph) выявляет риски в библиотеках (например, Log4Shell, CVE-2021-44228).</li>
        </ul>
        <p>Угрозы возникают из-за:</p>
        <ul>
          <li><strong>Неправильной конфигурации:</strong> Слабые политики CORS, отсутствие rate limiting или HSTS.</li>
          <li><strong>Недостаточной валидации:</strong> Принятие непроверенных данных, приводящее к инъекциям (SQL, XSS, GraphQL).</li>
          <li><strong>Утечки секретов:</strong> Хранение ключей в коде, ConfigMap или переменных окружения без шифрования.</li>
          <li><strong>Слабой аутентификации:</strong> Использование устаревших токенов или отсутствие проверки подписи JWT.</li>
        </ul>

        <h2>Схема уровней защиты API</h2>
        <div class="api-security-method" style="margin-bottom: 20px;">
          <div class="api-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="api-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Аутентификация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">OAuth/JWT</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Авторизация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">RBAC/ABAC</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Валидация
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">OpenAPI</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Шифрование
                  <p style="font-size: 12px; margin: 5px 0 0;">TLS 1.3</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Ограничение
                  <p style="font-size: 12px; margin: 5px 0 0;">Rate Limiting</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  WAF
                  <p style="font-size: 12px; margin: 5px 0 0;">Фильтрация</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SIEM</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней защиты</h3>
              <p>Многоуровневая защита API охватывает весь жизненный цикл запросов:</p>
              <ul>
                <li><strong>Аутентификация:</strong> Проверка личности через OAuth 2.0, JWT, OpenID Connect.</li>
                <li><strong>Авторизация:</strong> Ограничение доступа с помощью RBAC, ABAC, scopes.</li>
                <li><strong>Валидация:</strong> Проверка данных через JSON Schema или OpenAPI.</li>
                <li><strong>Шифрование:</strong> Защита трафика с TLS 1.3, HSTS, certificate pinning.</li>
                <li><strong>Ограничение:</strong> Контроль запросов через rate limiting и throttling.</li>
                <li><strong>WAF:</strong> Фильтрация атак с помощью Cloudflare, Wallarm.</li>
                <li><strong>Мониторинг:</strong> Анализ логов через Splunk, ELK Stack.</li>
              </ul>
            </div>
          </div>
        </div>

        <h2>Уязвимости API</h2>
        <p>API подвержены уязвимостям, описанным в OWASP API Security Top 10 (2023):</p>
        <ul>
          <li><strong>Broken Object Level Authorization (BOLA):</strong> Доступ к объектам без проверки прав. Пример: изменение ID в запросе <code>/api/users/123</code>.</li>
          <li><strong>Broken Authentication:</strong> Слабые токены или отсутствие проверки JWT. Пример: CVE-2018-13379 в Fortinet API.</li>
          <li><strong>Excessive Data Exposure:</strong> Возврат лишних данных. Пример: раскрытие паролей в JSON.</li>
          <li><strong>Injection Attacks:</strong> SQL, XSS, GraphQL-инъекции через непроверенные данные.</li>
          <li><strong>Improper Assets Management:</strong> Открытые старые версии API.</li>
          <li><strong>Mass Assignment:</strong> Обновление непредназначенных полей.</li>
          <li><strong>Security Misconfiguration:</strong> Слабые CORS или отсутствие HSTS.</li>
        </ul>

        <h2>Инструменты</h2>
        <p>Для анализа и защиты API используются следующие инструменты:</p>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Инструмент</th>
                <th>Функция</th>
                <th>Применение</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Postman</td>
                <td>Тестирование API</td>
                <td>Отправка запросов, проверка ответов</td>
              </tr>
              <tr>
                <td>Burp Suite</td>
                <td>Анализ уязвимостей</td>
                <td>Перехват и модификация запросов</td>
              </tr>
              <tr>
                <td>Wallarm</td>
                <td>WAF и мониторинг</td>
                <td>Защита от инъекций, аномалий</td>
              </tr>
              <tr>
                <td>OWASP ZAP</td>
                <td>Сканирование уязвимостей</td>
                <td>Автоматическое тестирование API</td>
              </tr>
              <tr>
                <td>Apigee</td>
                <td>Управление API</td>
                <td>Настройка политик, rate limiting</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h2>Рекомендации</h2>
        <p>Для обеспечения безопасности API:</p>
        <ol>
          <li>Используйте OAuth 2.0/OpenID Connect и JWT с ротацией ключей.</li>
          <li>Настройте RBAC/ABAC и ограничьте scopes.</li>
          <li>Валидируйте данные с JSON Schema или OpenAPI.</li>
          <li>Шифруйте трафик с TLS 1.3, HSTS, certificate pinning.</li>
          <li>Внедрите rate limiting, throttling и WAF (Cloudflare, Wallarm).</li>
          <li>Мониторьте трафик с SIEM (Splunk, ELK).</li>
          <li>Тестируйте API с Burp Suite, OWASP ZAP и Postman.</li>
          <li>Проводите аудит кода и зависимостей (Snyk, Dependabot).</li>
        </ol>

        <h2>Примеры атак</h2>
        <p>Реальные инциденты:</p>
        <ul>
          <li><strong>Twitter (2022):</strong> BOLA в API раскрыла данные 5.4 млн пользователей.</li>
          <li><strong>T-Mobile (2021):</strong> Слабая авторизация API привела к утечке данных 50 млн клиентов.</li>
          <li><strong>Facebook (2018):</strong> Уязвимость OAuth-токенов раскрыла данные 50 млн пользователей.</li>
        </ul>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadContainersOrchestrationSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность контейнеров и оркестрации</h1>
        <p>Безопасность контейнеров и оркестраторов (Docker, Podman, Kubernetes, OpenShift) фокусируется на защите контейнеризованных сред от уязвимостей, неправильных конфигураций и атак. Этот раздел охватывает теоретические основы, ключевые угрозы, инструменты, методы защиты и примеры реальных инцидентов.</p>
  
        <h2>Теоретические основы безопасности контейнеров</h2>
        <p>Безопасность контейнеров опирается на теории операционных систем, виртуализации, криптографии и управления доступом. Контейнеры, в отличие от виртуальных машин, используют общее ядро хоста, что требует особого внимания к изоляции и управлению ресурсами.</p>
        <ul>
          <li><strong>Модель изоляции:</strong> Контейнеры используют Linux namespaces (pid, net, mnt) и cgroups для изоляции процессов и ресурсов. Теория разделения пространства имён, разработанная в 2000-х годах, позволяет изолировать процессы, но уязвимости ядра (например, CVE-2022-0492) могут привести к breakout-атакам.</li>
          <li><strong>Принципы минимальных привилегий:</strong> Основаны на модели Bell-LaPadula и NIST SP 800-190. Контейнеры должны работать с минимальными правами (non-root, read-only filesystem), чтобы снизить риск компрометации.</li>
          <li><strong>Многоуровневая защита (Defense-in-Depth):</strong> Охватывает образы, runtime, хост и оркестратор. CIS Benchmarks для Docker и Kubernetes задают стандарты защиты (например, отключение privileged-режима).</li>
          <li><strong>Криптография:</strong> Шифрование секретов (AES-256 в Vault) и сетевого трафика (TLS в Kubernetes Ingress) защищает данные. Теория стойкости к атакам по сторонним каналам (например, Spectre) требует изоляции контейнеров на уровне ядра.</li>
          <li><strong>Моделирование угроз:</strong> STRIDE-модель (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) применяется для анализа рисков. Например, breakout-атаки относятся к Elevation of Privilege, а DDoS — к Denial of Service.</li>
          <li><strong>Обнаружение аномалий:</strong> Используются скрытые марковские модели (HMM) и машинное обучение (ML) для анализа системных вызовов (syscalls). Инструменты, такие как Falco, применяют алгоритмы кластеризации для выявления подозрительных действий.</li>
          <li><strong>Теория игр:</strong> Моделирует взаимодействие атакующих и защитников. Злоумышленник выбирает стратегию (эксплуатация API Kubernetes или уязвимости образа), а защитник — контрмеры (RBAC, сканирование).</li>
          <li><strong>Стандарты и нормативы:</strong> NIST SP 800-190 и CIS Benchmarks обеспечивают формальные требования. В России ФСТЭК регулирует защиту контейнеров в КИИ через приказы (например, № 239).</li>
        </ul>
        <p>Угрозы возникают из-за нарушения этих принципов:</p>
        <ul>
          <li><strong>Неправильная конфигурация:</strong> Теория минимальной функциональности (least privilege) часто игнорируется, что приводит к запуску контейнеров с root-доступом.</li>
          <li><strong>Уязвимости ядра:</strong> Теория эксплойтов (например, Dirty Pipe, CVE-2022-0847) показывает, как ошибки в системных вызовах позволяют повысить привилегии.</li>
          <li><strong>Социальная инженерия:</strong> Атаки на DevOps-инженеров через фишинг для получения доступа к CI/CD-пайплайнам.</li>
        </ul>
  
        <h2>Схема уровней защиты контейнеров</h2>
        <div class="container-security-method" style="margin-bottom: 20px;">
          <div class="container-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="container-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Образы
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сканирование</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Контейнеры
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изоляция</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Хост
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Ядро</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Оркестратор
                  <p style="font-size: 12px; margin: 5px 0 0;">RBAC</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сеть
                  <p style="font-size: 12px; margin: 5px 0 0;">Network Policies</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Секреты
                  <p style="font-size: 12px; margin: 5px 0 0;">Шифрование</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SIEM/Falco</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней защиты</h3>
              <p>Многоуровневая защита охватывает весь жизненный цикл контейнеров:</p>
              <ul>
                <li><strong>Образы:</strong> Сканирование на уязвимости (Trivy).</li>
                <li><strong>Контейнеры:</strong> Изоляция через namespaces и cgroups.</li>
                <li><strong>Хост:</strong> Защита ядра (AppArmor, seccomp).</li>
                <li><strong>Оркестратор:</strong> Ограничение доступа (RBAC, PSP).</li>
                <li><strong>Сеть:</strong> Контроль трафика (Calico).</li>
                <li><strong>Секреты:</strong> Шифрование (Vault).</li>
                <li><strong>Мониторинг:</strong> Обнаружение угроз (Falco, Sysdig).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Уязвимости контейнеров</h2>
        <p>Контейнеры и оркестраторы подвержены следующим уязвимостям:</p>
        <ul>
          <li><strong>Неправильные конфигурации:</strong> Запуск контейнеров с root-привилегиями или открытыми портами. Пример: Docker с <code>--privileged</code> без ограничений.</li>
          <li><strong>Уязвимости образов:</strong> Использование устаревших библиотек или вредоносных образов. Пример: Log4Shell (CVE-2021-44228) в образе.</li>
          <li><strong>Breakout-атаки:</strong> Выход из контейнера в хост через уязвимости ядра. Пример: CVE-2022-0492 в runc позволял получить root-доступ на хосте.</li>
          <li><strong>Слабая изоляция:</strong> Неправильная настройка namespaces или cgroups позволяет контейнерам взаимодействовать друг с другом.</li>
          <li><strong>Компрометация оркестратора:</strong> Уязвимости в API Kubernetes (CVE-2020-8554) позволяют захватить кластер.</li>
          <li><strong>Секреты в коде:</strong> Хранение ключей в Dockerfile или ConfigMap без шифрования.</li>
        </ul>
  
        <h2>Инструменты</h2>
        <p>Для анализа и защиты контейнеров используются следующие инструменты:</p>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Инструмент</th>
                <th>Функция</th>
                <th>Применение</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Trivy</td>
                <td>Сканирование образов</td>
                <td>Выявление CVE в Dockerfile и зависимостях</td>
              </tr>
              <tr>
                <td>Clair</td>
                <td>Статический анализ</td>
                <td>Проверка образов в CI/CD</td>
              </tr>
              <tr>
                <td>Sysdig</td>
                <td>Runtime-мониторинг</td>
                <td>Обнаружение аномалий в контейнерах</td>
              </tr>
              <tr>
                <td>Falco</td>
                <td>Обнаружение угроз</td>
                <td>Анализ syscalls для выявления атак</td>
              </tr>
              <tr>
                <td>Aqua Security</td>
                <td>Комплексная защита</td>
                <td>Сканирование, runtime, политики</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Безопасность Kubernetes</h2>
        <p>Для защиты Kubernetes применяются следующие меры:</p>
        <ul>
          <li><strong>RBAC:</strong> Ограничение доступа к API. Пример: запрет анонимного доступа.</li>
          <li><strong>Pod Security Standards (PSS):</strong> Замена Pod Security Policies, ограничивает привилегии подов.</li>
          <li><strong>Network Policies:</strong> Контроль трафика (Calico, Cilium).</li>
          <li><strong>Secrets Management:</strong> Шифрование секретов (Vault, Kubernetes Secrets).</li>
          <li><strong>API Authentication:</strong> OIDC или сертификаты для доступа к API.</li>
          <li><strong>Audit Logging:</strong> Мониторинг действий в кластере через kube-audit.</li>
        </ul>
  
        <h2>Рекомендации</h2>
        <p>Для обеспечения безопасности контейнеров и оркестраторов:</p>
        <ol>
          <li>Сканируйте образы с помощью Trivy или Clair перед деплоем.</li>
          <li>Используйте non-root контейнеры и read-only filesystem.</li>
          <li>Шифруйте секреты с помощью Vault или Kubernetes Secrets.</li>
          <li>Настройте RBAC, PSS и Network Policies в Kubernetes.</li>
          <li>Мониторьте runtime с помощью Sysdig или Falco.</li>
          <li>Регулярно обновляйте Docker, Kubernetes и зависимости.</li>
          <li>Проводите тесты на проникновение для кластеров.</li>
        </ol>
  
        <h2>Примеры атак</h2>
        <p>Реальные инциденты подчеркивают важность безопасности:</p>
        <ul>
          <li><strong>Компрометация Kubernetes (2021):</strong> Уязвимость в API позволила злоумышленникам развернуть майнеры в кластере Tesla.</li>
          <li><strong>Майнеры в контейнерах (2022):</strong> Атака Siloscape использовала уязвимости Windows-контейнеров для майнинга.</li>
          <li><strong>Breakout-атака (2023):</strong> CVE-2022-0492 в runc позволила получить доступ к хост-системе.</li>
        </ul>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }

  function loadRemoteWorkSecurityContent(container) {
    container.innerHTML = `
      <div class="structure-security-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Безопасность удалённой работы</h1>
        <p>Безопасность удалённой работы фокусируется на защите сотрудников и инфраструктуры в условиях распределённых команд. Этот раздел охватывает теоретические основы, уязвимости, инструменты, рекомендации и настройку безопасной инфраструктуры.</p>
  
        <h2>Теоретические основы безопасности удалённой работы</h2>
        <p>Безопасность удалённой работы опирается на модели Zero Trust, криптографию, теорию управления доступом и анализ человеческого фактора. Основная цель — обеспечить конфиденциальность, целостность и доступность в условиях распределённых сетей.</p>
        <ul>
          <li><strong>Zero Trust:</strong> Модель, предложенная Джоном Киндервагом (2010), требует проверки каждого запроса, независимо от источника. Основана на принципе «никогда не доверяй, всегда проверяй». Формально описана в NIST SP 800-207, включает идентификацию, аутентификацию и мониторинг.</li>
          <li><strong>Криптография:</strong> VPN и ZTNA используют протоколы TLS 1.3 и IPsec (AES-256, SHA-256). Теория стойкости к атакам MitM требует проверки сертификатов (certificate pinning) и Диффи-Хеллмана для обмена ключами.</li>
          <li><strong>Моделирование угроз:</strong> STRIDE-модель применяется для анализа рисков. Например, фишинг относится к Spoofing, а утечка данных через BYOD — к Information Disclosure.</li>
          <li><strong>Человеческий фактор:</strong> Теория HCI (Human-Computer Interaction) показывает, что пользователи — слабое звено. Модель MITRE ATT&CK (Tactic: Initial Access) описывает фишинг как основной вектор атаки.</li>
          <li><strong>Обнаружение аномалий:</strong> SIEM-системы используют байесовский анализ и ML (например, алгоритмы SVM) для выявления подозрительных подключений. Пример: обнаружение несанкционированного RDP-доступа.</li>
          <li><strong>Теория игр:</strong> Моделирует выбор атакующего (фишинг, RDP-атака) и защитника (MFA, ZTNA). Равновесие Нэша помогает определить оптимальную стратегию защиты.</li>
          <li><strong>Сетевые протоколы:</strong> Теория конечных автоматов лежит в основе протоколов VPN (PPTP, L2TP). Уязвимости, такие как CVE-2020-2021 в Palo Alto VPN, эксплуатируют слабые настройки.</li>
          <li><strong>Стандарты:</strong> NIST SP 800-46 (Remote Access Security) и ФЗ-187 (для КИИ) задают требования к шифрованию, аутентификации и мониторингу.</li>
        </ul>
        <p>Угрозы возникают из-за:</p>
        <ul>
          <li><strong>Небезопасные сети:</strong> Теория атак MitM показывает, как открытые Wi-Fi позволяют перехватить трафик.</li>
          <li><strong>Слабая аутентификация:</strong> Теория перебора паролей эксплуатирует отсутствие MFA.</li>
          <li><strong>Человеческий фактор:</strong> Теория социальной инженерии объясняет успех фишинга.</li>
        </ul>
  
        <h2>Схема уровней защиты удалённой работы</h2>
        <div class="remote-work-security-method" style="margin-bottom: 20px;">
          <div class="remote-work-security-method-container" style="display: flex; align-items: stretch; gap: 20px;">
            <div class="remote-work-security-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Уровни защиты</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                <div style="background-color: #2e7d32; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Пользователь
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Аутентификация</p>
                </div>
                <div style="background-color: #388e3c; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  MFA
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">2FA/TOTP</p>
                </div>
                <div style="background-color: #66bb6a; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Устройство
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">MDM</p>
                </div>
                <div style="background-color: #ffeb3b; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сеть
                  <p style="font-size: 12px; margin: 5px 0 0;">VPN/ZTNA</p>
                </div>
                <div style="background-color: #fff176; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Данные
                  <p style="font-size: 12px; margin: 5px 0 0;">Шифрование</p>
                </div>
                <div style="background-color: #ff9800; color: #000; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Приложения
                  <p style="font-size: 12px; margin: 5px 0 0;">ZTNA</p>
                </div>
                <div style="background-color: #d32f2f; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Мониторинг
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SIEM</p>
                </div>
              </div>
            </div>
            <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
            <div style="flex: 1; padding: 15px;">
              <h3>Описание уровней защиты</h3>
              <p>Многоуровневая защита охватывает все аспекты удалённой работы:</p>
              <ul>
                <li><strong>Пользователь:</strong> Проверка личности (пароль, биометрия).</li>
                <li><strong>MFA:</strong> Усиление аутентификации (TOTP, SMS).</li>
                <li><strong>Устройство:</strong> Контроль через MDM (Intune).</li>
                <li><strong>Сеть:</strong> Шифрование трафика (VPN, ZTNA).</li>
                <li><strong>Данные:</strong> Защита на уровне хранения (AES-256).</li>
                <li><strong>Приложения:</strong> Доступ через ZTNA (Zscaler).</li>
                <li><strong>Мониторинг:</strong> Анализ логов (Splunk).</li>
              </ul>
            </div>
          </div>
        </div>
  
        <h2>Уязвимости</h2>
        <p>Удалённая работа создаёт следующие риски:</p>
        <ul>
          <li><strong>Небезопасные Wi-Fi:</strong> Подключение к общедоступным сетям без VPN увеличивает риск MitM.</li>
          <li><strong>Утечка данных через BYOD:</strong> Личные устройства без контроля. Пример: копирование данных на незащищённый диск.</li>
          <li><strong>Слабая защита endpoints:</strong> Устаревшее ПО или отсутствие EDR.</li>
          <li><strong>Фишинг:</strong> Поддельные письма или звонки, эксплуатирующие удалённый контекст.</li>
          <li><strong>Социальная инженерия:</strong> Злоумышленники выдают себя за коллег через Zoom/Teams.</li>
        </ul>
  
        <h2>Инструменты</h2>
        <p>Для защиты используются следующие инструменты:</p>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Инструмент</th>
                <th>Тип</th>
                <th>Преимущества</th>
                <th>Недостатки</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Zscaler</td>
                <td>ZTNA</td>
                <td>Гибкий доступ, Zero Trust</td>
                <td>Сложная настройка</td>
              </tr>
              <tr>
                <td>Cisco AnyConnect</td>
                <td>VPN</td>
                <td>Простота, широкая поддержка</td>
                <td>Уязвимости протоколов</td>
              </tr>
              <tr>
                <td>CrowdStrike</td>
                <td>Endpoint Security</td>
                <td>Обнаружение угроз, ML</td>
                <td>Высокая стоимость</td>
              </tr>
              <tr>
                <td>Intune</td>
                <td>MDM</td>
                <td>Интеграция с Microsoft</td>
                <td>Ограничения для BYOD</td>
              </tr>
              <tr>
                <td>Splunk</td>
                <td>SIEM</td>
                <td>Глубокий анализ логов</td>
                <td>Сложность настройки</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Рекомендации</h2>
        <p>Для обеспечения безопасности удалённой работы:</p>
        <ol>
          <li>Внедрите BYOD-политики с обязательным MDM.</li>
          <li>Проводите тренинги по фишингу и социальной инженерии.</li>
          <li>Используйте MFA для всех сервисов.</li>
          <li>Настройте VPN или ZTNA с AES-256.</li>
          <li>Мониторьте подключения через SIEM.</li>
          <li>Обновляйте ПО и применяйте EDR на endpoints.</li>
        </ol>
  
        <h2>Примеры атак</h2>
        <p>Реальные инциденты:</p>
        <ul>
          <li><strong>Фишинг через Zoom (2020):</strong> Поддельные приглашения устанавливали вредоносное ПО.</li>
          <li><strong>Компрометация RDP (2021):</strong> Уязвимый RDP-сервер привёл к утечке данных.</li>
          <li><strong>Утечка через BYOD (2022):</strong> Личный ПК без защиты вызвал компрометацию.</li>
        </ul>
  
        <h2>Гайды по настройке безопасной инфраструктуры</h2>
        <p>Рекомендации:</p>
        <ul>
          <li>Настройте ZTNA (Zscaler) для доступа к ресурсам.</li>
          <li>Используйте VPN с MFA (Cisco AnyConnect).</li>
          <li>Внедрите EDR на всех устройствах (CrowdStrike).</li>
          <li>Настройте SIEM (Splunk) для мониторинга.</li>
          <li>Проводите симуляции фишинга.</li>
          <li>Разработайте BYOD-политики с MDM.</li>
        </ul>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadStructureSecurityContent(container);
    });
  }
