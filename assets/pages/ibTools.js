function loadSecurityToolsContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <h1>Инструменты ИБ</h1>
      <p>Инструменты информационной безопасности (ИБ) — это программные и аппаратные решения, предназначенные для защиты данных, сетей, устройств и пользователей от киберугроз. В этом разделе представлены основные категории инструментов ИБ, их назначение и рекомендации по использованию.</p>

      <!-- Кнопки для инструментов ИБ -->
      <h2>Основные инструменты ИБ</h2>
      <div class="security-tools-buttons">
        <button class="network-btn" id="dlp-btn">DLP</button>
        <button class="network-btn" id="siem-btn">SIEM</button>
        <button class="network-btn" id="ngfw-btn">NGFW</button>
        <button class="network-btn" id="ids-ips-btn">IDS/IPS</button>
        <button class="network-btn" id="waf-btn">WAF</button>
        <button class="network-btn" id="edr-btn">EDR</button>
        <button class="network-btn" id="xdr-btn">XDR</button>
        <button class="network-btn" id="soar-btn">SOAR</button>
        <button class="network-btn" id="pam-btn">PAM</button>
        <button class="network-btn" id="iam-btn">IAM</button>
        <button class="network-btn" id="vpn-btn">VPN</button>
        <button class="network-btn" id="nac-btn">NAC</button>
        <button class="network-btn" id="av-btn">Антивирус</button>
        <button class="network-btn" id="hsm-btn">HSM</button>
        <button class="network-btn" id="sandboxing-btn">Sandboxing</button>
        <button class="network-btn" id="tip-btn">Threat Intelligence</button>
        <button class="network-btn" id="vm-btn">Vulnerability Management</button>
        <button class="network-btn" id="seg-btn">Secure Email Gateway</button>
        <button class="network-btn" id="casb-btn">CASB</button>
        <button class="network-btn" id="sase-btn">SASE</button>
        <button class="network-btn" id="ztna-btn">ZTNA</button>
        <button class="network-btn" id="ddos-btn">DDoS Protection</button>
        <button class="network-btn" id="encryption-btn">Encryption Tools</button>
        <button class="network-btn" id="backup-btn">Backup & Recovery</button>
        <button class="network-btn" id="patch-btn">Patch Management</button>
        <button class="network-btn" id="mdm-btn">MDM</button>
        <button class="network-btn" id="whitelisting-btn">Application Whitelisting</button>
        <button class="network-btn" id="fim-btn">File Integrity Monitoring</button>
        <button class="network-btn" id="nta-btn">Network Traffic Analysis</button>
        <button class="network-btn" id="deception-btn">Deception Technology</button>
      </div>

      <!-- Кнопки для программных средств защиты рабочих станций -->
      <h2>Программные средства защиты рабочих станций</h2>
      <div class="workstation-protection-buttons">
        <button class="network-btn" id="personal-firewall-btn">Локальный межсетевой экран</button>
        <button class="network-btn" id="anti-spyware-btn">Антишпионское ПО</button>
        <button class="network-btn" id="anti-rootkit-btn">Антируткит</button>
        <button class="network-btn" id="exploit-protection-btn">Защита от эксплойтов</button>
        <button class="network-btn" id="app-control-btn">Контроль приложений</button>
        <button class="network-btn" id="disk-encryption-btn">Шифрование дисков</button>
        <button class="network-btn" id="anti-phishing-btn">Антифишинг</button>
      </div>
    </div>
  `;

  document.getElementById('dlp-btn').addEventListener('click', () => loadDlpContent(container));
  document.getElementById('siem-btn').addEventListener('click', () => loadSiemContent(container));
  document.getElementById('ngfw-btn').addEventListener('click', () => loadNgfwContent(container));
  document.getElementById('ids-ips-btn').addEventListener('click', () => loadIdsIpsContent(container));
  document.getElementById('waf-btn').addEventListener('click', () => loadWafContent(container));
  document.getElementById('edr-btn').addEventListener('click', () => loadEdrContent(container));
  document.getElementById('xdr-btn').addEventListener('click', () => loadXdrContent(container));
  document.getElementById('soar-btn').addEventListener('click', () => loadSoarContent(container));
  document.getElementById('pam-btn').addEventListener('click', () => loadPamContent(container));
  document.getElementById('iam-btn').addEventListener('click', () => loadIamContent(container));
  document.getElementById('vpn-btn').addEventListener('click', () => loadVpnContent(container));
  document.getElementById('nac-btn').addEventListener('click', () => loadNacContent(container));
  document.getElementById('av-btn').addEventListener('click', () => loadAntivirusContent(container));
  document.getElementById('hsm-btn').addEventListener('click', () => loadHsmContent(container));
  document.getElementById('sandboxing-btn').addEventListener('click', () => loadSandboxingContent(container));
  document.getElementById('tip-btn').addEventListener('click', () => loadThreatIntelligenceContent(container));
  document.getElementById('vm-btn').addEventListener('click', () => loadVulnerabilityManagementContent(container));
  document.getElementById('seg-btn').addEventListener('click', () => loadSegContent(container));
  document.getElementById('casb-btn').addEventListener('click', () => loadCasbContent(container));
  document.getElementById('sase-btn').addEventListener('click', () => loadSaseContent(container));
  document.getElementById('ztna-btn').addEventListener('click', () => loadZtnaContent(container));
  document.getElementById('ddos-btn').addEventListener('click', () => loadDdosContent(container));
  document.getElementById('encryption-btn').addEventListener('click', () => loadEncryptionContent(container));
  document.getElementById('backup-btn').addEventListener('click', () => loadBackupContent(container));
  document.getElementById('patch-btn').addEventListener('click', () => loadPatchContent(container));
  document.getElementById('mdm-btn').addEventListener('click', () => loadMdmContent(container));
  document.getElementById('whitelisting-btn').addEventListener('click', () => loadWhitelistingContent(container));
  document.getElementById('fim-btn').addEventListener('click', () => loadFimContent(container));
  document.getElementById('nta-btn').addEventListener('click', () => loadNtaContent(container));
  document.getElementById('deception-btn').addEventListener('click', () => loadDeceptionContent(container));

  document.getElementById('personal-firewall-btn').addEventListener('click', () => loadPersonalFirewallContent(container));
  document.getElementById('anti-spyware-btn').addEventListener('click', () => loadAntiSpywareContent(container));
  document.getElementById('anti-rootkit-btn').addEventListener('click', () => loadAntiRootkitContent(container));
  document.getElementById('exploit-protection-btn').addEventListener('click', () => loadExploitProtectionContent(container));
  document.getElementById('app-control-btn').addEventListener('click', () => loadAppControlContent(container));
  document.getElementById('disk-encryption-btn').addEventListener('click', () => loadDiskEncryptionContent(container));
  document.getElementById('anti-phishing-btn').addEventListener('click', () => loadAntiPhishingContent(container));
}

function loadDlpContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>DLP (Data Loss Prevention)</h1>
      <div class="theory-section">
        <h2>Теория DLP</h2>
        <p>DLP (Data Loss Prevention) — это системы, предназначенные для предотвращения утечек конфиденциальных данных. Они помогают организациям защитить чувствительную информацию, такую как персональные данные (PII), коммерческая тайна, интеллектуальная собственность или данные, подпадающие под регулирование (например, GDPR, PCI DSS). DLP-системы работают на трёх уровнях: данные в движении (Data in Motion), данные в покое (Data at Rest) и данные в использовании (Data in Use).</p>

        <h3>Принципы работы DLP</h3>
        <ul>
          <li><strong>Классификация данных:</strong> DLP идентифицирует конфиденциальные данные с помощью правил, шаблонов (например, регулярных выражений для номеров кредитных карт) и машинного обучения.</li>
          <li><strong>Мониторинг:</strong> Отслеживает передачу данных через различные каналы: сеть (email, HTTP), конечные устройства (USB, принтеры), облачные сервисы (Google Drive, Dropbox).</li>
          <li><strong>Политики:</strong> Применяет политики для блокировки, шифрования или уведомления при попытке несанкционированной передачи данных.</li>
          <li><strong>Реагирование:</strong> Генерирует инциденты и уведомления для анализа и расследования (например, через интеграцию с SIEM).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Инсайдерские угрозы:</strong> Сотрудники могут случайно или умышленно передать конфиденциальные данные (например, отправить документ по email).</li>
          <li><strong>Внешние атаки:</strong> Злоумышленники могут получить доступ к данным через фишинг или вредоносное ПО.</li>
          <li><strong>Небезопасные каналы:</strong> Использование незашифрованных каналов (например, HTTP вместо HTTPS) для передачи данных.</li>
        </ul>

        <h3>Схема работы DLP</h3>
        <div class="dlp-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Конечное устройство</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">DLP-агент (мониторинг USB, принтеров)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Сеть (email, HTTP)</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">DLP-сервер (анализ трафика)</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Облако (Google Drive)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (интеграция)</div>
          </div>
        </div>

        <h3>Примеры DLP-систем</h3>
        <ul>
          <li><strong>Symantec DLP:</strong> Обеспечивает защиту данных в облаке, на устройствах и в сети.</li>
          <li><strong>Forcepoint DLP:</strong> Использует поведенческий анализ для предотвращения утечек.</li>
          <li><strong>InfoWatch Traffic Monitor:</strong> Российское решение для контроля трафика и предотвращения утечек.</li>
        </ul>

        <h3>Рекомендации по внедрению DLP</h3>
        <ol>
          <li>Определите типы данных, которые нужно защищать (например, PII, PCI DSS).</li>
          <li>Настройте политики DLP с учётом бизнес-процессов.</li>
          <li>Интегрируйте DLP с другими системами (SIEM, CASB) для комплексного мониторинга.</li>
          <li>Обучайте сотрудников правилам работы с конфиденциальными данными.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadSiemContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>SIEM (Security Information and Event Management)</h1>
      <div class="theory-section">
        <h2>Теория SIEM</h2>
        <p>SIEM (Security Information and Event Management) — это система управления событиями и информационной безопасностью, которая собирает, анализирует и коррелирует события из различных источников (сети, серверов, приложений) для обнаружения угроз и управления инцидентами. SIEM сочетает в себе функции SIM (Security Information Management) для управления логами и SEM (Security Event Management) для анализа событий в реальном времени.</p>

        <h3>Принципы работы SIEM</h3>
        <ul>
          <li><strong>Сбор данных:</strong> SIEM собирает логи и события от устройств, приложений и систем (например, межсетевых экранов, антивирусов, ОС).</li>
          <li><strong>Нормализация:</strong> Приводит данные к единому формату для анализа (например, преобразует логи Windows и Linux в общий формат).</li>
          <li><strong>Корреляция:</strong> Анализирует события для выявления связей и аномалий (например, множественные неудачные попытки входа с одного IP).</li>
          <li><strong>Оповещения:</strong> Генерирует уведомления о подозрительных событиях (например, через email или интеграцию с SOAR).</li>
          <li><strong>Хранение:</strong> Сохраняет логи для долгосрочного анализа и соответствия требованиям (например, GDPR, ФЗ-152).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>APT-атаки:</strong> Целенаправленные атаки, которые могут оставаться незамеченными без корреляции событий.</li>
          <li><strong>Инсайдерские угрозы:</strong> Действия сотрудников, которые могут быть выявлены через анализ аномального поведения.</li>
          <li><strong>Недостаток видимости:</strong> Отсутствие централизованного анализа логов может привести к пропуску инцидентов.</li>
        </ul>

        <h3>Схема работы SIEM</h3>
        <div class="siem-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Источники (сети, серверы)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Сбор логов (Syslog, API)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Нормализация данных</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">SIEM-сервер</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Корреляция и анализ</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Оповещения (email, SOAR)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Хранилище логов</div>
          </div>
        </div>

        <h3>Примеры SIEM-систем</h3>
        <ul>
          <li><strong>Splunk:</strong> Универсальная платформа для анализа логов и событий.</li>
          <li><strong>IBM QRadar:</strong> Поддерживает корреляцию и интеграцию с SOAR.</li>
          <li><strong>MaxPatrol SIEM:</strong> Российское решение для мониторинга и анализа инцидентов.</li>
        </ul>

        <h3>Рекомендации по внедрению SIEM</h3>
        <ol>
          <li>Определите источники логов (сети, серверы, приложения) для интеграции.</li>
          <li>Настройте правила корреляции для выявления угроз (например, множественные неудачные входы).</li>
          <li>Интегрируйте SIEM с другими системами (SOAR, EDR) для автоматизации реагирования.</li>
          <li>Обеспечьте долгосрочное хранение логов для соответствия требованиям.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadNgfwContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>NGFW (Next-Generation Firewall)</h1>
      <div class="theory-section">
        <h2>Теория NGFW</h2>
        <p>NGFW (Next-Generation Firewall) — это межсетевой экран нового поколения, который сочетает функции традиционного брандмауэра (фильтрация по портам и IP) с дополнительными возможностями, такими как глубокая проверка пакетов (DPI), обнаружение приложений, предотвращение вторжений (IPS) и интеграция с системами анализа угроз.</p>

        <h3>Принципы работы NGFW</h3>
        <ul>
          <li><strong>Глубокая проверка пакетов (DPI):</strong> Анализирует содержимое пакетов, а не только заголовки, для выявления угроз (например, вредоносного кода).</li>
          <li><strong>Идентификация приложений:</strong> Определяет приложения (например, Skype, Telegram) независимо от портов и протоколов.</li>
          <li><strong>Интеграция с IPS:</strong> Обнаруживает и блокирует атаки (например, SQL-инъекции, эксплойты).</li>
          <li><strong>Контроль доступа:</strong> Применяет политики на основе пользователей, групп и приложений (например, запретить доступ к соцсетям для определённых сотрудников).</li>
          <li><strong>Шифрованный трафик:</strong> Расшифровывает и проверяет SSL/TLS-трафик для выявления скрытых угроз.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Скрытые угрозы в шифрованном трафике:</strong> Злоумышленники могут использовать HTTPS для доставки вредоносного ПО.</li>
          <li><strong>Атаки на приложения:</strong> Например, SQL-инъекции или XSS, которые могут быть пропущены традиционными брандмауэрами.</li>
          <li><strong>Обход правил:</strong> Использование нестандартных портов или туннелирования для обхода фильтрации.</li>
        </ul>

        <h3>Схема работы NGFW</h3>
        <div class="ngfw-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Интернет</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">NGFW</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">DPI (анализ пакетов)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">IPS (блокировка атак)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Внутренняя сеть</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Контроль приложений</div>
            </div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (SIEM)</div>
          </div>
        </div>

        <h3>Примеры NGFW</h3>
        <ul>
          <li><strong>Palo Alto Networks:</strong> Поддерживает DPI, контроль приложений и интеграцию с Threat Intelligence.</li>
          <li><strong>Cisco Firepower:</strong> Обеспечивает защиту от атак и анализ шифрованного трафика.</li>
          <li><strong>Континент 4:</strong> Российское решение с поддержкой ГОСТ-шифрования.</li>
        </ul>

        <h3>Рекомендации по внедрению NGFW</h3>
        <ol>
          <li>Настройте DPI для анализа всего трафика, включая шифрованный.</li>
          <li>Определите политики контроля приложений (например, запретить P2P-трафик).</li>
          <li>Интегрируйте NGFW с SIEM для мониторинга и анализа логов.</li>
          <li>Регулярно обновляйте сигнатуры угроз для IPS.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadIdsIpsContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>IDS/IPS (Intrusion Detection/Prevention System)</h1>
      <div class="theory-section">
        <h2>Теория IDS/IPS</h2>
        <p>IDS (Intrusion Detection System) и IPS (Intrusion Prevention System) — это системы обнаружения и предотвращения вторжений. IDS анализирует трафик для выявления подозрительной активности, а IPS дополнительно блокирует такие действия. Они используются для защиты сетей и хостов от атак, таких как эксплойты, DoS и вредоносное ПО.</p>

        <h3>Принципы работы IDS/IPS</h3>
        <ul>
          <li><strong>Сигнатурный анализ:</strong> Сравнивает трафик с базой известных сигнатур атак (например, сигнатура для эксплойта EternalBlue).</li>
          <li><strong>Аномальный анализ:</strong> Выявляет отклонения от нормального поведения (например, необычно высокий трафик).</li>
          <li><strong>Поведенческий анализ:</strong> Использует машинное обучение для обнаружения новых угроз.</li>
          <li><strong>Реагирование (для IPS):</strong> Блокирует вредоносный трафик (например, сбрасывает соединение).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Эксплойты:</strong> Использование уязвимостей (например, CVE-2021-44228 в Log4j).</li>
          <li><strong>DoS-атаки:</strong> Попытки перегрузить сеть или сервер.</li>
          <li><strong>Скрытые атаки:</strong> Использование шифрованного трафика для обхода обнаружения.</li>
        </ul>

        <h3>Схема работы IDS/IPS</h3>
        <div class="ids-ips-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Интернет</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">IDS/IPS</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Сигнатурный анализ</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Аномальный анализ</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Внутренняя сеть</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Блокировка (IPS)</div>
            </div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (оповещения)</div>
          </div>
        </div>

        <h3>Примеры IDS/IPS</h3>
        <ul>
          <li><strong>Snort:</strong> Бесплатная система с открытым исходным кодом для обнаружения и предотвращения атак.</li>
          <li><strong>Cisco Secure IPS:</strong> Интегрируется с NGFW для комплексной защиты.</li>
          <li><strong>Suricata:</strong> Высокопроизводительное решение с поддержкой многопоточности.</li>
        </ul>

        <h3>Рекомендации по внедрению IDS/IPS</h3>
        <ol>
          <li>Разместите IDS/IPS на ключевых точках сети (например, на периметре и в DMZ).</li>
          <li>Регулярно обновляйте сигнатуры для обнаружения новых угроз.</li>
          <li>Настройте аномальный анализ для выявления неизвестных атак.</li>
          <li>Интегрируйте с SIEM для централизованного мониторинга.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadWafContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>WAF (Web Application Firewall)</h1>
      <div class="theory-section">
        <h2>Теория WAF</h2>
        <p>WAF (Web Application Firewall) — это межсетевой экран для веб-приложений, который защищает их от атак на прикладном уровне (уровень 7 модели OSI). WAF фильтрует HTTP/HTTPS-трафик, обнаруживает и блокирует атаки, такие как SQL-инъекции, XSS (межсайтовый скриптинг) и CSRF (межсайтовая подделка запросов).</p>

        <h3>Принципы работы WAF</h3>
        <ul>
          <li><strong>Сигнатурный анализ:</strong> Сравнивает запросы с базой известных атак (например, OWASP Top 10).</li>
          <li><strong>Поведенческий анализ:</strong> Выявляет аномалии в запросах (например, необычно длинные параметры в URL).</li>
          <li><strong>Белые/чёрные списки:</strong> Разрешает или блокирует запросы на основе правил (например, блокировка IP из определённых стран).</li>
          <li><strong>Виртуальные патчи:</strong> Блокирует атаки на известные уязвимости приложений до их исправления.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>SQL-инъекции:</strong> Внедрение вредоносного SQL-кода через веб-формы.</li>
          <li><strong>XSS-атаки:</strong> Внедрение скриптов для выполнения на стороне клиента.</li>
          <li><strong>Обход защиты:</strong> Использование кодировок или обфускации для обхода фильтров.</li>
        </ul>

        <h3>Схема работы WAF</h3>
        <div class="waf-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">WAF</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Фильтрация HTTP/HTTPS</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Блокировка атак (SQL, XSS)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Веб-приложение</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (SIEM)</div>
          </div>
        </div>

        <h3>Примеры WAF</h3>
        <ul>
          <li><strong>Cloudflare WAF:</strong> Облачное решение для защиты веб-приложений.</li>
          <li><strong>Imperva:</strong> Поддерживает поведенческий анализ и виртуальные патчи.</li>
          <li><strong>NGINX App Protect:</strong> Интегрируется с NGINX для защиты приложений.</li>
        </ul>

        <h3>Рекомендации по внедрению WAF</h3>
        <ol>
          <li>Настройте WAF для фильтрации всего HTTP/HTTPS-трафика.</li>
          <li>Используйте правила OWASP Top 10 для защиты от распространённых атак.</li>
          <li>Настройте поведенческий анализ для выявления новых угроз.</li>
          <li>Интегрируйте WAF с SIEM для мониторинга и анализа логов.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadEdrContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>EDR (Endpoint Detection and Response)</h1>
      <div class="theory-section">
        <h2>Теория EDR</h2>
        <p>EDR (Endpoint Detection and Response) — это решение для обнаружения, анализа и реагирования на угрозы на конечных устройствах (рабочих станциях, серверах). EDR фокусируется на мониторинге активности, выявлении аномалий и предоставлении инструментов для расследования инцидентов.</p>

        <h3>Принципы работы EDR</h3>
        <ul>
          <li><strong>Мониторинг:</strong> Собирает данные о процессах, сетевой активности, изменениях файлов и реестра.</li>
          <li><strong>Обнаружение:</strong> Использует сигнатурный, поведенческий и аномальный анализ для выявления угроз (например, ransomware).</li>
          <li><strong>Реагирование:</strong> Позволяет изолировать устройство, останавливать процессы или восстанавливать файлы.</li>
          <li><strong>Расследование:</strong> Предоставляет временную шкалу событий для анализа инцидентов.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Вредоносное ПО:</strong> Вирусы, трояны, ransomware (например, WannaCry).</li>
          <li><strong>APT-атаки:</strong> Целенаправленные атаки, использующие сложные техники (например, fileless malware).</li>
          <li><strong>Инсайдерские угрозы:</strong> Действия сотрудников, которые могут быть выявлены через аномальное поведение.</li>
        </ul>

        <h3>Схема работы EDR</h3>
        <div class="edr-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Конечное устройство</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">EDR-агент</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Мониторинг (процессы, сеть)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">EDR-сервер</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Анализ и реагирование</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Изоляция устройства</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (интеграция)</div>
          </div>
        </div>

        <h3>Примеры EDR</h3>
        <ul>
          <li><strong>CrowdStrike Falcon:</strong> Облачное решение с поведенческим анализом.</li>
          <li><strong>SentinelOne:</strong> Поддерживает автономное реагирование на угрозы.</li>
          <li><strong>Kaspersky EDR:</strong> Российское решение с интеграцией с антивирусами.</li>
        </ul>

        <h3>Рекомендации по внедрению EDR</h3>
        <ol>
          <li>Установите EDR-агенты на все конечные устройства (рабочие станции, серверы).</li>
          <li>Настройте поведенческий анализ для выявления новых угроз.</li>
          <li>Интегрируйте EDR с SIEM и SOAR для автоматизации реагирования.</li>
          <li>Обучайте сотрудников распознаванию угроз (например, фишинг).</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadXdrContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>XDR (Extended Detection and Response)</h1>
      <div class="theory-section">
        <h2>Теория XDR</h2>
        <p>XDR (Extended Detection and Response) — это расширенное решение для обнаружения и реагирования на угрозы, которое объединяет данные с различных источников (конечные устройства, сети, облака, email) для комплексного анализа и автоматизации реагирования. XDR является эволюцией EDR, добавляя интеграцию с другими системами безопасности.</p>

        <h3>Принципы работы XDR</h3>
        <ul>
          <li><strong>Интеграция данных:</strong> Собирает данные с EDR, NDR (Network Detection and Response), облачных систем и других источников.</li>
          <li><strong>Корреляция:</strong> Анализирует данные для выявления сложных атак (например, APT).</li>
          <li><strong>Автоматизация:</strong> Автоматически реагирует на угрозы (например, изолирует устройство, блокирует IP).</li>
          <li><strong>Аналитика:</strong> Использует машинное обучение для обнаружения новых угроз.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Сложные атаки:</strong> APT-атаки, которые охватывают несколько уровней (сеть, устройства, облако).</li>
          <li><strong>Недостаток интеграции:</strong> Разрозненные системы безопасности могут пропустить угрозы.</li>
          <li><strong>Медленное реагирование:</strong> Ручное реагирование может быть недостаточно быстрым.</li>
        </ul>

        <h3>Схема работы XDR</h3>
        <div class="xdr-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Источники (EDR, NDR, облако)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">XDR-платформа</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Корреляция данных</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Аналитика (ML)</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Автоматизация (SOAR)</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Реагирование (изоляция, блокировка)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (интеграция)</div>
          </div>
        </div>

        <h3>Примеры XDR</h3>
        <ul>
          <li><strong>Palo Alto Cortex XDR:</strong> Интегрируется с NGFW и облачными системами.</li>
          <li><strong>Microsoft Defender XDR:</strong> Объединяет данные с Microsoft 365 и Azure.</li>
          <li><strong>Trend Micro Vision One:</strong> Поддерживает анализ и автоматизацию.</li>
        </ul>

        <h3>Рекомендации по внедрению XDR</h3>
        <ol>
          <li>Интегрируйте XDR с существующими системами (EDR, NDR, SIEM).</li>
          <li>Настройте корреляцию для выявления сложных атак.</li>
          <li>Используйте автоматизацию для быстрого реагирования.</li>
          <li>Обучайте аналитиков работе с XDR-платформой.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadSoarContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>SOAR (Security Orchestration, Automation, and Response)</h1>
      <div class="theory-section">
        <h2>Теория SOAR</h2>
        <p>SOAR (Security Orchestration, Automation, and Response) — это платформа для оркестрации, автоматизации и реагирования на инциденты безопасности. SOAR помогает автоматизировать рутинные задачи, координировать действия между системами (SIEM, EDR, XDR) и ускорять реагирование на угрозы.</p>

        <h3>Принципы работы SOAR</h3>
        <ul>
          <li><strong>Оркестрация:</strong> Интегрирует различные системы безопасности (SIEM, EDR, NGFW) для обмена данными.</li>
          <li><strong>Автоматизация:</strong> Выполняет рутинные задачи (например, блокировка IP, изоляция устройства) по заранее заданным сценариям (playbooks).</li>
          <li><strong>Реагирование:</strong> Координирует действия аналитиков, предоставляя рекомендации и автоматизируя шаги.</li>
          <li><strong>Аналитика:</strong> Собирает данные об инцидентах для улучшения процессов.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Медленное реагирование:</strong> Ручное реагирование может быть недостаточно быстрым для сложных атак.</li>
          <li><strong>Перегрузка аналитиков:</strong> Большое количество оповещений может привести к пропуску угроз.</li>
          <li><strong>Отсутствие интеграции:</strong> Разрозненные системы затрудняют координацию.</li>
        </ul>

        <h3>Схема работы SOAR</h3>
        <div class="soar-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">SIEM (оповещение)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">SOAR-платформа</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Оркестрация (EDR, NGFW)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Playbook</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Автоматизация (блокировка IP)</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Реагирование (аналитик)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Аналитика (отчёты)</div>
          </div>
        </div>

        <h3>Примеры SOAR</h3>
        <ul>
          <li><strong>IBM Resilient:</strong> Поддерживает автоматизацию и интеграцию с SIEM.</li>
          <li><strong>Splunk SOAR:</strong> Интегрируется со Splunk SIEM для автоматизации.</li>
          <li><strong>Swimlane:</strong> Гибкое решение для автоматизации процессов.</li>
        </ul>

        <h3>Рекомендации по внедрению SOAR</h3>
        <ol>
          <li>Интегрируйте SOAR с существующими системами (SIEM, EDR, XDR).</li>
          <li>Разработайте playbooks для типичных сценариев (например, фишинг, ransomware).</li>
          <li>Настройте автоматизацию для рутинных задач (например, блокировка IP).</li>
          <li>Обучайте аналитиков работе с SOAR-платформой.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadPamContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>PAM (Privileged Access Management)</h1>
      <div class="theory-section">
        <h2>Теория PAM</h2>
        <p>PAM (Privileged Access Management) — это система управления привилегированным доступом, которая защищает учетные записи с повышенными правами (администраторы, сервисные аккаунты). PAM минимизирует риски, связанные с компрометацией привилегированных учетных записей, которые часто становятся целью атак.</p>

        <h3>Принципы работы PAM</h3>
        <ul>
          <li><strong>Хранение учетных данных:</strong> Хранит пароли и ключи в зашифрованном виде в защищённом хранилище.</li>
          <li><strong>Контроль доступа:</strong> Предоставляет доступ только авторизованным пользователям через временные сессии.</li>
          <li><strong>Мониторинг:</strong> Записывает действия привилегированных пользователей (например, команды в терминале).</li>
          <li><strong>Ротация паролей:</strong> Автоматически меняет пароли после использования или по расписанию.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Компрометация учетных данных:</strong> Злоумышленники могут получить доступ к привилегированным аккаунтам через фишинг или утечки.</li>
          <li><strong>Инсайдерские угрозы:</strong> Администраторы могут злоупотреблять правами.</li>
          <li><strong>Статические пароли:</strong> Использование неизменяемых паролей увеличивает риск компрометации.</li>
        </ul>

        <h3>Схема работы PAM</h3>
        <div class="pam-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Администратор</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">PAM-сервер</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Хранилище паролей</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Контроль сессий</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Целевой сервер</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (SIEM)</div>
          </div>
        </div>

        <h3>Примеры PAM</h3>
        <ul>
          <li><strong>CyberArk:</strong> Лидер в области управления привилегированным доступом.</li>
          <li><strong>BeyondTrust:</strong> Поддерживает ротацию паролей и мониторинг сессий.</li>
          <li><strong>Wallix:</strong> Решение с акцентом на европейские стандарты.</li>
        </ul>

        <h3>Рекомендации по внедрению PAM</h3>
        <ol>
          <li>Определите все привилегированные учетные записи в организации.</li>
          <li>Настройте ротацию паролей и контроль сессий.</li>
          <li>Интегрируйте PAM с SIEM для мониторинга и анализа логов.</li>
          <li>Обучайте сотрудников безопасному использованию привилегированного доступа.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadIamContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>IAM (Identity and Access Management)</h1>
      <div class="theory-section">
        <h2>Теория IAM</h2>
        <p>IAM (Identity and Access Management) — это система управления идентификацией и доступом, которая обеспечивает контроль над тем, кто имеет доступ к ресурсам (приложениям, данным, системам) и какие действия может выполнять. IAM помогает соблюдать принцип наименьших привилегий (Least Privilege).</p>

        <h3>Принципы работы IAM</h3>
        <ul>
          <li><strong>Идентификация:</strong> Подтверждает, кто пользователь (например, через логин и пароль).</li>
          <li><strong>Аутентификация:</strong> Проверяет подлинность пользователя (например, через MFA — многофакторную аутентификацию).</li>
          <li><strong>Авторизация:</strong> Определяет, к каким ресурсам пользователь имеет доступ (например, через роли RBAC).</li>
          <li><strong>Управление жизненным циклом:</strong> Автоматизирует создание, изменение и удаление учетных записей.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Слабая аутентификация:</strong> Использование простых паролей или отсутствие MFA.</li>
          <li><strong>Избыточные права:</strong> Пользователи могут иметь доступ к ресурсам, которые им не нужны.</li>
          <li><strong>Утечка учетных данных:</strong> Фишинг или кража паролей.</li>
        </ul>

        <h3>Схема работы IAM</h3>
        <div class="iam-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">IAM-система</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Аутентификация (MFA)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Авторизация (RBAC)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Ресурсы (приложения, данные)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (SIEM)</div>
          </div>
        </div>

        <h3>Примеры IAM</h3>
        <ul>
          <li><strong>Okta:</strong> Облачное решение для управления доступом.</li>
          <li><strong>Microsoft Azure AD:</strong> Интегрируется с экосистемой Microsoft.</li>
          <li><strong>SailPoint:</strong> Фокусируется на управлении идентификацией.</li>
        </ul>

        <h3>Рекомендации по внедрению IAM</h3>
        <ol>
          <li>Внедрите MFA для всех пользователей.</li>
          <li>Используйте RBAC для управления доступом на основе ролей.</li>
          <li>Автоматизируйте управление жизненным циклом учетных записей.</li>
          <li>Интегрируйте IAM с SIEM для мониторинга активности.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadVpnContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>VPN (Virtual Private Network)</h1>
      <div class="theory-section">
        <h2>Теория VPN</h2>
        <p>VPN (Virtual Private Network) — это технология, которая создаёт защищённый туннель между устройством пользователя и целевой сетью через интернет. VPN шифрует трафик, обеспечивая конфиденциальность и защиту данных, особенно при работе через публичные сети (например, Wi-Fi в кафе).</p>

        <h3>Принципы работы VPN</h3>
        <ul>
          <li><strong>Шифрование:</strong> Использует протоколы (например, OpenVPN, IPsec) для шифрования трафика.</li>
          <li><strong>Туннелирование:</strong> Создаёт виртуальный туннель между клиентом и сервером.</li>
          <li><strong>Аутентификация:</strong> Проверяет подлинность пользователя (например, через сертификаты или пароли).</li>
          <li><strong>Маскировка IP:</strong> Скрывает реальный IP-адрес пользователя, заменяя его IP-адресом VPN-сервера.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Перехват данных:</strong> В публичных сетях злоумышленники могут перехватить незашифрованный трафик.</li>
          <li><strong>Слабые протоколы:</strong> Устаревшие протоколы (например, PPTP) уязвимы к атакам.</li>
          <li><strong>Утечка DNS:</strong> Запросы DNS могут "утечь" за пределы VPN-туннеля.</li>
        </ul>

        <h3>Схема работы VPN</h3>
        <div class="vpn-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">VPN-клиент</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Шифрование (IPsec/OpenVPN)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">VPN-сервер</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Туннель</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Корпоративная сеть</div>
          </div>
        </div>

        <h3>Примеры VPN</h3>
        <ul>
          <li><strong>NordVPN:</strong> Популярное решение для защиты конфиденциальности.</li>
          <li><strong>Cisco AnyConnect:</strong> Корпоративный VPN с поддержкой MFA.</li>
          <li><strong>FortiClient:</strong> Интегрируется с Fortinet NGFW.</li>
        </ul>

        <h3>Рекомендации по внедрению VPN</h3>
        <ol>
          <li>Используйте современные протоколы (OpenVPN, WireGuard, IPsec).</li>
          <li>Внедрите MFA для аутентификации пользователей.</li>
          <li>Настройте защиту от утечек DNS.</li>
          <li>Регулярно обновляйте VPN-серверы и клиентское ПО.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadNacContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>NAC (Network Access Control)</h1>
      <div class="theory-section">
        <h2>Теория NAC</h2>
        <p>NAC (Network Access Control) — это система контроля доступа к сети, которая проверяет устройства перед их подключением к сети. NAC обеспечивает соответствие устройств политикам безопасности (например, наличие антивируса, обновлений) и ограничивает доступ для несанкционированных устройств.</p>

        <h3>Принципы работы NAC</h3>
        <ul>
          <li><strong>Идентификация устройств:</strong> Определяет устройства, подключающиеся к сети (например, через MAC-адрес).</li>
          <li><strong>Проверка соответствия:</strong> Проверяет устройства на наличие антивируса, обновлений и других требований.</li>
          <li><strong>Контроль доступа:</strong> Предоставляет или ограничивает доступ (например, через VLAN или блокировку).</li>
          <li><strong>Мониторинг:</strong> Отслеживает поведение устройств в сети.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Несанкционированный доступ:</strong> Устройства без антивируса или с уязвимостями могут подключиться к сети.</li>
          <li><strong>BYOD-риски:</strong> Личные устройства сотрудников могут быть скомпрометированы.</li>
          <li><strong>Сетевые атаки:</strong> Злоумышленники могут использовать уязвимые устройства для атак.</li>
        </ul>

        <h3>Схема работы NAC</h3>
        <div class="nac-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Устройство</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">NAC-сервер</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Проверка (антивирус, обновления)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Сеть</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Доступ (VLAN)</div>
            </div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (SIEM)</div>
          </div>
        </div>

        <h3>Примеры NAC</h3>
        <ul>
          <li><strong>Cisco ISE:</strong> Интегрируется с сетевым оборудованием Cisco.</li>
          <li><strong>Aruba ClearPass:</strong> Поддерживает BYOD и контроль доступа.</li>
          <li><strong>FortiNAC:</strong> Решение от Fortinet для контроля сети.</li>
        </ul>

        <h3>Рекомендации по внедрению NAC</h3>
        <ol>
          <li>Определите политики соответствия для устройств (антивирус, обновления).</li>
          <li>Настройте сегментацию сети (VLAN) для ограничения доступа.</li>
          <li>Интегрируйте NAC с IAM для управления идентификацией.</li>
          <li>Мониторьте подключения через SIEM.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadAntivirusContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Антивирус</h1>
      <div class="theory-section">
        <h2>Теория Антивирус</h2>
        <p>Антивирус — это программное обеспечение, предназначенное для обнаружения, блокировки и удаления вредоносных программ (вирусов, троянов, ransomware). Современные антивирусы также используют поведенческий анализ и машинное обучение для защиты от новых угроз.</p>

        <h3>Принципы работы Антивируса</h3>
        <ul>
          <li><strong>Сигнатурный анализ:</strong> Сравнивает файлы с базой известных сигнатур вредоносного ПО.</li>
          <li><strong>Поведенческий анализ:</strong> Отслеживает подозрительное поведение (например, шифрование файлов).</li>
          <li><strong>Эвристический анализ:</strong> Выявляет потенциальные угрозы на основе их характеристик.</li>
          <li><strong>Облачный анализ:</strong> Отправляет подозрительные файлы в облако для проверки.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Вредоносное ПО:</strong> Вирусы, трояны, ransomware (например, WannaCry).</li>
          <li><strong>Новые угрозы:</strong> Zero-day атаки, которые не имеют сигнатур.</li>
          <li><strong>Фишинг:</strong> Вредоносные ссылки или вложения в письмах.</li>
        </ul>

        <h3>Схема работы Антивируса</h3>
        <div class="antivirus-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Устройство</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Антивирус</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Сигнатурный анализ</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Поведенческий анализ</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Карантин/Удаление</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Облако (анализ)</div>
          </div>
        </div>

        <h3>Примеры Антивирусов</h3>
        <ul>
          <li><strong>Kaspersky:</strong> Российское решение с поддержкой поведенческого анализа.</li>
          <li><strong>ESET NOD32:</strong> Лёгкий антивирус с высокой производительностью.</li>
          <li><strong>Microsoft Defender:</strong> Встроенный антивирус для Windows.</li>
        </ul>

        <h3>Рекомендации по внедрению Антивируса</h3>
        <ol>
          <li>Установите антивирус на все устройства (рабочие станции, серверы).</li>
          <li>Регулярно обновляйте сигнатурные базы.</li>
          <li>Настройте поведенческий анализ для защиты от новых угроз.</li>
          <li>Интегрируйте с EDR для расширенного мониторинга.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadHsmContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>HSM (Hardware Security Module)</h1>
      <div class="theory-section">
        <h2>Теория HSM</h2>
        <p>HSM (Hardware Security Module) — это аппаратный модуль безопасности, предназначенный для управления криптографическими ключами, шифрования, подписи и аутентификации. HSM обеспечивает высокий уровень защиты ключей, предотвращая их утечку или компрометацию.</p>

        <h3>Принципы работы HSM</h3>
        <ul>
          <li><strong>Хранение ключей:</strong> Хранит криптографические ключи в защищённой аппаратной среде.</li>
          <li><strong>Криптографические операции:</strong> Выполняет шифрование, дешифрование, подпись (например, для TLS-сертификатов).</li>
          <li><strong>Защита от атак:</strong> Устойчив к физическим и программным атакам (например, вскрытие устройства приводит к уничтожению ключей).</li>
          <li><strong>Соответствие стандартам:</strong> Поддерживает стандарты, такие как FIPS 140-2/3.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Утечка ключей:</strong> Компрометация ключей может привести к расшифровке данных.</li>
          <li><strong>Физические атаки:</strong> Попытки извлечь ключи из устройства.</li>
          <li><strong>Неправильное управление:</strong> Ошибки в управлении ключами могут привести к их утрате.</li>
        </ul>

        <h3>Схема работы HSM</h3>
        <div class="hsm-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Приложение</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">HSM</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Хранилище ключей</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Шифрование/Подпись</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Защищённые данные</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (SIEM)</div>
          </div>
        </div>

        <h3>Примеры HSM</h3>
        <ul>
          <li><strong>Thales Luna HSM:</strong> Поддерживает широкий спектр криптографических операций.</li>
          <li><strong>Gemalto SafeNet:</strong> Используется для защиты ключей в облаке.</li>
          <li><strong>Yubico HSM:</strong> Компактное решение для малого бизнеса.</li>
        </ul>

        <h3>Рекомендации по внедрению HSM</h3>
        <ol>
          <li>Используйте HSM для хранения ключей шифрования (например, для TLS, VPN).</li>
          <li>Настройте резервное копирование ключей в защищённой среде.</li>
          <li>Обеспечьте физическую безопасность HSM (например, в дата-центре).</li>
          <li>Интегрируйте с SIEM для мониторинга операций.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadSandboxingContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Sandboxing</h1>
      <div class="theory-section">
        <h2>Теория Sandboxing</h2>
        <p>Sandboxing (песочница) — это технология изоляции, которая позволяет запускать подозрительные файлы или программы в виртуальной среде для анализа их поведения. Песочницы помогают выявлять вредоносное ПО, которое может быть пропущено сигнатурным анализом.</p>

        <h3>Принципы работы Sandboxing</h3>
        <ul>
          <li><strong>Изоляция:</strong> Запускает файлы в виртуальной машине, изолированной от основной системы.</li>
          <li><strong>Мониторинг:</strong> Отслеживает действия файла (например, попытки шифрования, сетевые подключения).</li>
          <li><strong>Анализ:</strong> Определяет, является ли файл вредоносным, на основе его поведения.</li>
          <li><strong>Интеграция:</strong> Передаёт результаты анализа другим системам (например, антивирусу, SIEM).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Zero-day угрозы:</strong> Новые вредоносные программы, не имеющие сигнатур.</li>
          <li><strong>Обход песочницы:</strong> Вредоносное ПО может определять, что оно в песочнице, и не проявлять активность.</li>
          <li><strong>Фишинг:</strong> Вредоносные вложения в письмах.</li>
        </ul>

        <h3>Схема работы Sandboxing</h3>
        <div class="sandboxing-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Подозрительный файл</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Песочница</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Виртуальная машина</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Мониторинг поведения</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Результат (вредоносный/безопасный)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (интеграция)</div>
          </div>
        </div>

        <h3>Примеры Sandboxing</h3>
        <ul>
          <li><strong>FireEye (Mandiant):</strong> Облачная песочница для анализа угроз.</li>
          <li><strong>Cuckoo Sandbox:</strong> Бесплатное решение с открытым исходным кодом.</li>
          <li><strong>Kaspersky Sandbox:</strong> Интегрируется с антивирусами Kaspersky.</li>
        </ul>

        <h3>Рекомендации по внедрению Sandboxing</h3>
        <ol>
          <li>Настройте песочницу для анализа всех подозрительных файлов.</li>
          <li>Используйте облачные песочницы для масштабируемости.</li>
          <li>Интегрируйте с антивирусом и SIEM для автоматизации.</li>
          <li>Регулярно обновляйте виртуальные машины в песочнице.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadThreatIntelligenceContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Threat Intelligence</h1>
      <div class="theory-section">
        <h2>Теория Threat Intelligence</h2>
        <p>Threat Intelligence (разведка угроз) — это процесс сбора, анализа и распространения информации об угрозах и уязвимостях. Threat Intelligence помогает организациям предвидеть атаки, обновлять защитные меры и принимать проактивные решения.</p>

        <h3>Принципы работы Threat Intelligence</h3>
        <ul>
          <li><strong>Сбор данных:</strong> Собирает информацию из открытых источников (OSINT), даркнета, форумов хакеров.</li>
          <li><strong>Анализ:</strong> Обрабатывает данные для выявления индикаторов компрометации (IoC), таких как IP-адреса, хэши файлов.</li>
          <li><strong>Распространение:</strong> Передаёт IoC другим системам (NGFW, SIEM) для блокировки угроз.</li>
          <li><strong>Прогнозирование:</strong> Использует аналитику для предсказания будущих атак.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>APT-атаки:</strong> Целенаправленные атаки, использующие сложные техники.</li>
          <li><strong>Zero-day уязвимости:</strong> Угрозы, для которых нет патчей.</li>
          <li><strong>Недостаток информации:</strong> Отсутствие данных о новых угрозах.</li>
        </ul>

        <h3>Схема работы Threat Intelligence</h3>
        <div class="threat-intelligence-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Источники (OSINT, даркнет)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Threat Intelligence</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Анализ (IoC)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Интеграция</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">NGFW/SIEM (блокировка)</div>
            </div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Отчёты (аналитика)</div>
          </div>
        </div>

        <h3>Примеры Threat Intelligence</h3>
        <ul>
          <li><strong>Recorded Future:</strong> Платформа для анализа угроз в реальном времени.</li>
          <li><strong>ThreatConnect:</strong> Поддерживает интеграцию с SIEM и NGFW.</li>
          <li><strong>Kaspersky Threat Intelligence:</strong> Российское решение с акцентом на APT.</li>
        </ul>

        <h3>Рекомендации по внедрению Threat Intelligence</h3>
        <ol>
          <li>Подпишитесь на Threat Intelligence-фиды для получения актуальных IoC.</li>
          <li>Интегрируйте с NGFW, SIEM и EDR для автоматизации.</li>
          <li>Настройте аналитику для прогнозирования атак.</li>
          <li>Обучайте аналитиков работе с данными Threat Intelligence.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadVulnerabilityManagementContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Vulnerability Management</h1>
      <div class="theory-section">
        <h2>Теория Vulnerability Management</h2>
        <p>Vulnerability Management (управление уязвимостями) — это процесс обнаружения, оценки, приоритизации и устранения уязвимостей в системах, приложениях и сетях. Цель — минимизировать риски эксплуатации уязвимостей злоумышленниками.</p>

        <h3>Принципы работы Vulnerability Management</h3>
        <ul>
          <li><strong>Сканирование:</strong> Проводит сканирование систем и приложений для выявления уязвимостей (например, через Nessus).</li>
          <li><strong>Оценка:</strong> Присваивает уязвимостям уровень критичности (например, по CVSS).</li>
          <li><strong>Приоритизация:</strong> Определяет, какие уязвимости нужно устранить в первую очередь.</li>
          <li><strong>Устранение:</strong> Применяет патчи, изменяет конфигурации или использует виртуальные патчи (например, через WAF).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Zero-day уязвимости:</strong> Уязвимости, для которых нет патчей (например, Log4j CVE-2021-44228).</li>
          <li><strong>Устаревшее ПО:</strong> Системы без обновлений становятся мишенью для атак.</li>
          <li><strong>Неправильные конфигурации:</strong> Ошибки в настройках (например, открытые порты).</li>
        </ul>

        <h3>Схема работы Vulnerability Management</h3>
        <div class="vulnerability-management-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Системы/Приложения</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Сканер уязвимостей</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Сканирование (Nessus)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Оценка (CVSS)</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Приоритизация</div>
            </div>
            <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px;">Устранение (патчи)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (отчёты)</div>
          </div>
        </div>

        <h3>Примеры Vulnerability Management</h3>
        <ul>
          <li><strong>Tenable Nessus:</strong> Популярный сканер уязвимостей.</li>
          <li><strong>Qualys:</strong> Облачное решение для управления уязвимостями.</li>
          <li><strong>Rapid7 InsightVM:</strong> Поддерживает приоритизацию и устранение.</li>
        </ul>

        <h3>Рекомендации по внедрению Vulnerability Management</h3>
        <ol>
          <li>Проводите регулярное сканирование всех систем и приложений.</li>
          <li>Используйте CVSS для приоритизации уязвимостей.</li>
          <li>Автоматизируйте применение патчей через системы управления (например, SCCM).</li>
          <li>Интегрируйте с SIEM для мониторинга и отчётности.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadSegContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Secure Email Gateway</h1>
      <div class="theory-section">
        <h2>Теория Secure Email Gateway</h2>
        <p>Secure Email Gateway (SEG) — это решение для защиты электронной почты от угроз, таких как фишинг, спам, вредоносные вложения и утечки данных. SEG фильтрует входящие и исходящие письма, предотвращая атаки и утечки конфиденциальной информации.</p>

        <h3>Принципы работы Secure Email Gateway</h3>
        <ul>
          <li><strong>Фильтрация спама:</strong> Использует чёрные списки и репутационные базы для блокировки спама.</li>
          <li><strong>Анализ вложений:</strong> Проверяет вложения на наличие вредоносного ПО (например, через песочницу).</li>
          <li><strong>Защита от фишинга:</strong> Выявляет подозрительные ссылки и поддельные домены.</li>
          <li><strong>DLP-функции:</strong> Предотвращает утечку данных через исходящие письма (например, блокирует отправку PII).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Фишинг:</strong> Поддельные письма, направленные на кражу учетных данных.</li>
          <li><strong>Вредоносные вложения:</strong> Файлы с троянами или ransomware.</li>
          <li><strong>Утечка данных:</strong> Случайная отправка конфиденциальной информации.</li>
        </ul>

        <h3>Схема работы Secure Email Gateway</h3>
        <div class="secure-email-gateway-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Входящее письмо</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Secure Email Gateway</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Фильтрация (спам, фишинг)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Анализ вложений</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Почтовый сервер</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (логи)</div>
          </div>
        </div>

        <h3>Примеры Secure Email Gateway</h3>
        <ul>
          <li><strong>Proofpoint:</strong> Лидер в области защиты электронной почты.</li>
          <li><strong>Mimecast:</strong> Поддерживает DLP и защиту от фишинга.</li>
          <li><strong>Barracuda Email Security:</strong> Решение с акцентом на простоту внедрения.</li>
        </ul>

        <h3>Рекомендации по внедрению Secure Email Gateway</h3>
        <ol>
          <li>Настройте фильтрацию спама и фишинга.</li>
          <li>Интегрируйте с песочницей для анализа вложений.</li>
          <li>Настройте DLP-политики для исходящих писем.</li>
          <li>Обучайте сотрудников распознаванию фишинговых писем.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadCasbContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>CASB (Cloud Access Security Broker)</h1>
      <div class="theory-section">
        <h2>Теория CASB</h2>
        <p>CASB (Cloud Access Security Broker) — это решение для обеспечения безопасности облачных сервисов. CASB выступает посредником между пользователями и облачными приложениями, обеспечивая видимость, контроль и защиту данных в облаке.</p>

        <h3>Принципы работы CASB</h3>
        <ul>
          <li><strong>Видимость:</strong> Обнаруживает использование облачных сервисов (например, Shadow IT).</li>
          <li><strong>Контроль доступа:</strong> Применяет политики доступа (например, через IAM).</li>
          <li><strong>Защита данных:</strong> Использует DLP для предотвращения утечек в облаке.</li>
          <li><strong>Обнаружение угроз:</strong> Анализирует поведение пользователей для выявления аномалий.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Shadow IT:</strong> Использование несанкционированных облачных сервисов.</li>
          <li><strong>Утечка данных:</strong> Случайная или умышленная передача данных в облако.</li>
          <li><strong>Компрометация учетных данных:</strong> Доступ злоумышленников к облачным аккаунтам.</li>
        </ul>

        <h3>Схема работы CASB</h3>
        <div class="casb-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">CASB</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Контроль доступа</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">DLP (облако)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Облако (Google Drive)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (логи)</div>
          </div>
        </div>

        <h3>Примеры CASB</h3>
        <ul>
          <li><strong>Microsoft Defender for Cloud Apps:</strong> Интегрируется с Microsoft 365.</li>
          <li><strong>Netscope:</strong> Поддерживает видимость и DLP.</li>
          <li><strong>McAfee MVISION Cloud:</strong> Решение для защиты облачных данных.</li>
        </ul>

        <h3>Рекомендации по внедрению CASB</h3>
        <ol>
          <li>Обнаружьте все используемые облачные сервисы (Shadow IT).</li>
          <li>Настройте DLP-политики для облачных данных.</li>
          <li>Интегрируйте с IAM для контроля доступа.</li>
          <li>Мониторьте поведение пользователей через SIEM.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadSaseContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>SASE (Secure Access Service Edge)</h1>
      <div class="theory-section">
        <h2>Теория SASE</h2>
        <p>SASE (Secure Access Service Edge) — это архитектура, которая объединяет сетевые и защитные функции (SD-WAN, NGFW, CASB, ZTNA) в единую облачную платформу. SASE обеспечивает безопасный доступ к ресурсам для распределённых пользователей и устройств.</p>

        <h3>Принципы работы SASE</h3>
        <ul>
          <li><strong>Облачная доставка:</strong> Предоставляет услуги через облако, минимизируя задержки.</li>
          <li><strong>SD-WAN:</strong> Оптимизирует сетевой трафик для удалённых пользователей.</li>
          <li><strong>Безопасность:</strong> Интегрирует NGFW, CASB, ZTNA для защиты трафика.</li>
          <li><strong>Zero Trust:</strong> Проверяет всех пользователей и устройства перед предоставлением доступа.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Удалённый доступ:</strong> Угрозы для удалённых сотрудников (например, через публичные Wi-Fi).</li>
          <li><strong>Недостаток видимости:</strong> Трафик к облачным сервисам может быть неконтролируемым.</li>
          <li><strong>Сложность управления:</strong> Разрозненные решения усложняют защиту.</li>
        </ul>

        <h3>Схема работы SASE</h3>
        <div class="sase-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Удалённый пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">SASE (облако)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">SD-WAN</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">NGFW/CASB/ZTNA</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Ресурсы (облако, сеть)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (логи)</div>
          </div>
        </div>

        <h3>Примеры SASE</h3>
        <ul>
          <li><strong>Palo Alto Prisma Access:</strong> Полнофункциональное SASE-решение.</li>
          <li><strong>Cisco Umbrella:</strong> Интегрирует SD-WAN и безопасность.</li>
          <li><strong>Zscaler:</strong> Облачная платформа для SASE.</li>
        </ul>

        <h3>Рекомендации по внедрению SASE</h3>
        <ol>
          <li>Перейдите на облачную архитектуру для масштабируемости.</li>
          <li>Интегрируйте SD-WAN для оптимизации трафика.</li>
          <li>Внедрите Zero Trust для контроля доступа.</li>
          <li>Мониторьте трафик через SIEM.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadZtnaContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>ZTNA (Zero Trust Network Access)</h1>
      <div class="theory-section">
        <h2>Теория ZTNA</h2>
        <p>ZTNA (Zero Trust Network Access) — это подход к обеспечению безопасности, основанный на принципе "нулевого доверия". ZTNA предоставляет доступ к ресурсам только после строгой проверки идентичности, контекста и состояния устройства, независимо от того, находится ли пользователь внутри или вне корпоративной сети. Этот подход особенно полезен для удалённого доступа и защиты облачных приложений.</p>

        <h3>Принципы работы ZTNA</h3>
        <ul>
          <li><strong>Проверка идентичности:</strong> Использует многофакторную аутентификацию (MFA) для подтверждения личности пользователя.</li>
          <li><strong>Контекстный доступ:</strong> Учитывает устройство, местоположение, время и поведение пользователя перед предоставлением доступа.</li>
          <li><strong>Микросегментация:</strong> Ограничивает доступ только к необходимым ресурсам, минимизируя поверхность атаки.</li>
          <li><strong>Шифрование:</strong> Все соединения шифруются для защиты данных в движении.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Несанкционированный доступ:</strong> Злоумышленники могут использовать украденные учетные данные для доступа к ресурсам.</li>
          <li><strong>Угрозы от удалённых пользователей:</strong> Устройства вне корпоративной сети могут быть скомпрометированы.</li>
          <li><strong>Отсутствие видимости:</strong> Традиционные VPN не обеспечивают достаточного контроля над доступом.</li>
        </ul>

        <h3>Схема работы ZTNA</h3>
        <div class="ztna-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Удалённый пользователь</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">ZTNA-шлюз</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Проверка (MFA, контекст)</div>
            </div>
            <div style="border: 2px solid #ffeb3b; padding: 10px; border-radius: 5px; width: 300px;">
              <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 5px; border-radius: 5px;">Ресурсы (приложения)</div>
              <div style="background-color: #fff176; color: #1a1a1a; padding: 5px; border-radius: 5px; margin-top: 5px;">Микросегментация</div>
            </div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (логи)</div>
          </div>
        </div>

        <h3>Примеры ZTNA</h3>
        <ul>
          <li><strong>Zscaler Private Access:</strong> Облачное решение для ZTNA с поддержкой приложений в облаке и локально.</li>
          <li><strong>Fortinet ZTNA:</strong> Интегрируется с FortiGate NGFW для комплексной защиты.</li>
        </ul>

        <h3>Рекомендации по внедрению ZTNA</h3>
        <ol>
          <li>Внедрите ZTNA для всех удалённых подключений, заменив традиционные VPN.</li>
          <li>Используйте в связке с IAM (Identity and Access Management) и NAC (Network Access Control).</li>
          <li>Настройте микросегментацию для ограничения доступа к ресурсам.</li>
          <li>Регулярно проверяйте и обновляйте политики доступа.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadDdosContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>DDoS Protection</h1>
      <div class="theory-section">
        <h2>Теория DDoS Protection</h2>
        <p>DDoS Protection (Distributed Denial of Service Protection) — это набор решений для защиты от распределённых атак типа "отказ в обслуживании". Такие атаки направлены на перегрузку сети, серверов или приложений, чтобы сделать их недоступными для легитимных пользователей.</p>

        <h3>Принципы работы DDoS Protection</h3>
        <ul>
          <li><strong>Обнаружение аномалий:</strong> Анализирует трафик для выявления необычного роста запросов (например, резкий всплеск).</li>
          <li><strong>Фильтрация:</strong> Блокирует вредоносный трафик на основе сигнатур, IP-адресов или поведения.</li>
          <li><strong>Распределение нагрузки:</strong> Использует CDN (Content Delivery Network) для распределения трафика и смягчения атаки.</li>
          <li><strong>Ограничение скорости:</strong> Ограничивает количество запросов с одного IP для предотвращения перегрузки.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Объёмные атаки:</strong> Перегрузка сети большим объёмом трафика (например, UDP-флуд).</li>
          <li><strong>Атаки на уровне приложений:</strong> Перегрузка веб-серверов (например, HTTP-флуд).</li>
          <li><strong>Атаки на протоколы:</strong> Использование уязвимостей протоколов (например, SYN-флуд).</li>
        </ul>

        <h3>Схема работы DDoS Protection</h3>
        <div class="ddos-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Атакующий (ботнет)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">DDoS Protection</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Обнаружение аномалий</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Фильтрация трафика</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Целевой сервер</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">CDN (распределение)</div>
          </div>
        </div>

        <h3>Примеры DDoS Protection</h3>
        <ul>
          <li><strong>Cloudflare DDoS Protection:</strong> Использует глобальную сеть для фильтрации атак.</li>
          <li><strong>Imperva DDoS Protection:</strong> Защита на уровне приложений и сети.</li>
        </ul>

        <h3>Рекомендации по внедрению DDoS Protection</h3>
        <ol>
          <li>Используйте облачные решения для защиты от масштабных атак.</li>
          <li>Настройте мониторинг трафика для раннего обнаружения атак.</li>
          <li>Интегрируйте с NGFW и WAF для комплексной защиты.</li>
          <li>Регулярно тестируйте устойчивость системы к DDoS-атакам.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadEncryptionContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Encryption Tools</h1>
      <div class="theory-section">
        <h2>Теория Encryption Tools</h2>
        <p>Encryption Tools (Инструменты шифрования) — это программные или аппаратные решения, которые защищают данные путём их шифрования. Они предотвращают несанкционированный доступ к данным в покое (на дисках), в движении (при передаче по сети) и в использовании (во время обработки).</p>

        <h3>Принципы работы Encryption Tools</h3>
        <ul>
          <li><strong>Шифрование данных:</strong> Использует алгоритмы (например, AES-256, RSA) для преобразования данных в нечитаемый вид.</li>
          <li><strong>Управление ключами:</strong> Генерирует, хранит и управляет ключами шифрования.</li>
          <li><strong>Шифрование на разных уровнях:</strong> Поддерживает шифрование файлов, дисков, сообщений и сетевого трафика.</li>
          <li><strong>Соответствие стандартам:</strong> Обеспечивает соответствие требованиям (например, GDPR, PCI DSS).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Кража данных:</strong> Злоумышленники могут получить доступ к незашифрованным данным.</li>
          <li><strong>Перехват трафика:</strong> Данные, передаваемые по незащищённым каналам, могут быть перехвачены.</li>
          <li><strong>Утрата устройств:</strong> Утерянные устройства (например, ноутбуки) могут содержать конфиденциальные данные.</li>
        </ul>

        <h3>Схема работы Encryption Tools</h3>
        <div class="encryption-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Данные (в покое, в движении)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Encryption Tool</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Шифрование (AES, RSA)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Зашифрованные данные</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">HSM (управление ключами)</div>
          </div>
        </div>

        <h3>Примеры Encryption Tools</h3>
        <ul>
          <li><strong>VeraCrypt:</strong> Бесплатное решение для шифрования дисков и файлов.</li>
          <li><strong>GPG (GnuPG):</strong> Инструмент для шифрования сообщений и файлов.</li>
        </ul>

        <h3>Рекомендации по внедрению Encryption Tools</h3>
        <ol>
          <li>Используйте шифрование для всех конфиденциальных данных (диски, файлы, трафик).</li>
          <li>Храните ключи шифрования в HSM (Hardware Security Module) для повышения безопасности.</li>
          <li>Регулярно обновляйте алгоритмы шифрования, чтобы соответствовать новым стандартам.</li>
          <li>Обучайте сотрудников правильному использованию инструментов шифрования.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadBackupContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Backup & Recovery</h1>
      <div class="theory-section">
        <h2>Теория Backup & Recovery</h2>
        <p>Backup & Recovery (Резервное копирование и восстановление) — это решения для создания резервных копий данных и их восстановления в случае потери из-за атак (например, ransomware), сбоев оборудования или человеческого фактора. Эти инструменты обеспечивают непрерывность бизнеса и защиту данных.</p>

        <h3>Принципы работы Backup & Recovery</h3>
        <ul>
          <li><strong>Резервное копирование:</strong> Автоматически создаёт копии данных (полные, инкрементальные, дифференциальные).</li>
          <li><strong>Шифрование:</strong> Шифрует резервные копии для защиты от несанкционированного доступа.</li>
          <li><strong>Хранение:</strong> Сохраняет копии в изолированных средах (локально, в облаке, на лентах).</li>
          <li><strong>Восстановление:</strong> Позволяет быстро восстановить данные после инцидента.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Ransomware:</strong> Вредоносное ПО может зашифровать данные, делая их недоступными.</li>
          <li><strong>Сбои оборудования:</strong> Выход из строя дисков или серверов может привести к потере данных.</li>
          <li><strong>Человеческий фактор:</strong> Случайное удаление данных сотрудниками.</li>
        </ul>

        <h3>Схема работы Backup & Recovery</h3>
        <div class="backup-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Данные (серверы, ПК)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Backup Tool</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Резервное копирование</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Шифрование копий</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Хранилище (облако, ленты)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Восстановление</div>
          </div>
        </div>

        <h3>Примеры Backup & Recovery</h3>
        <ul>
          <li><strong>Veeam:</strong> Решение для резервного копирования и восстановления в виртуальных средах.</li>
          <li><strong>Acronis Cyber Backup:</strong> Защита от ransomware и быстрое восстановление.</li>
        </ul>

        <h3>Рекомендации по внедрению Backup & Recovery</h3>
        <ol>
          <li>Создавайте регулярные резервные копии всех критически важных данных.</li>
          <li>Храните копии в изолированной среде (например, оффлайн или в облаке с ограниченным доступом).</li>
          <li>Шифруйте резервные копии для защиты от утечек.</li>
          <li>Регулярно тестируйте процесс восстановления данных.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadPatchContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Patch Management</h1>
      <div class="theory-section">
        <h2>Теория Patch Management</h2>
        <p>Patch Management (Управление патчами) — это процесс управления обновлениями программного обеспечения для устранения уязвимостей и повышения безопасности. Эти решения автоматизируют сканирование, установку и мониторинг патчей, снижая риск эксплуатации уязвимостей.</p>

        <h3>Принципы работы Patch Management</h3>
        <ul>
          <li><strong>Сканирование:</strong> Выявляет устаревшее ПО и отсутствующие патчи.</li>
          <li><strong>Приоритизация:</strong> Оценивает критичность уязвимостей (например, по CVSS).</li>
          <li><strong>Развертывание:</strong> Автоматически устанавливает патчи на устройства.</li>
          <li><strong>Мониторинг:</strong> Отслеживает статус обновлений и генерирует отчёты.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Эксплуатация уязвимостей:</strong> Злоумышленники могут использовать известные уязвимости (например, EternalBlue).</li>
          <li><strong>Устаревшее ПО:</strong> Непропатченные системы становятся мишенью для атак.</li>
          <li><strong>Отсутствие автоматизации:</strong> Ручное обновление может быть медленным и неэффективным.</li>
        </ul>

        <h3>Схема работы Patch Management</h3>
        <div class="patch-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Системы (серверы, ПК)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Patch Management</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Сканирование уязвимостей</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Установка патчей</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Обновлённые системы</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (отчёты)</div>
          </div>
        </div>

        <h3>Примеры Patch Management</h3>
        <ul>
          <li><strong>Microsoft SCCM:</strong> Управление обновлениями для Windows.</li>
          <li><strong>Ivanti Patch Management:</strong> Поддержка разных операционных систем.</li>
        </ul>

        <h3>Рекомендации по внедрению Patch Management</h3>
        <ol>
          <li>Настройте автоматическое обновление для критических систем.</li>
          <li>Тестируйте патчи перед массовым развертыванием, чтобы избежать сбоев.</li>
          <li>Интегрируйте с Vulnerability Management для приоритизации обновлений.</li>
          <li>Создайте расписание для регулярного сканирования и обновления.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadMdmContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>MDM (Mobile Device Management)</h1>
      <div class="theory-section">
        <h2>Теория MDM</h2>
        <p>MDM (Mobile Device Management) — это решение для управления мобильными устройствами (смартфонами, планшетами), используемыми в корпоративной среде. MDM обеспечивает безопасность устройств, контроль приложений и данных, а также соответствие корпоративным политикам.</p>

        <h3>Принципы работы MDM</h3>
        <ul>
          <li><strong>Управление устройствами:</strong> Позволяет удалённо настраивать, блокировать или стирать данные на устройствах.</li>
          <li><strong>Контроль приложений:</strong> Управляет установкой и использованием приложений (например, блокирует нежелательные).</li>
          <li><strong>Шифрование:</strong> Обеспечивает шифрование данных на устройстве.</li>
          <li><strong>Соответствие политикам:</strong> Проверяет устройства на соответствие требованиям (например, наличие пароля).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Утрата устройств:</strong> Утерянные устройства могут содержать конфиденциальные данные.</li>
          <li><strong>Небезопасные приложения:</strong> Установка вредоносных приложений из сторонних источников.</li>
          <li><strong>BYOD-риски:</strong> Личные устройства сотрудников могут быть менее защищёнными.</li>
        </ul>

        <h3>Схема работы MDM</h3>
        <div class="mdm-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Мобильное устройство</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">MDM-сервер</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Управление (политики)</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Шифрование данных</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Корпоративные ресурсы</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Удалённое стирание</div>
          </div>
        </div>

        <h3>Примеры MDM</h3>
        <ul>
          <li><strong>VMware Workspace ONE:</strong> Управление устройствами и приложениями.</li>
          <li><strong>Microsoft Intune:</strong> Интеграция с Azure AD для управления устройствами.</li>
        </ul>

        <h3>Рекомендации по внедрению MDM</h3>
        <ol>
          <li>Внедрите MDM для всех корпоративных мобильных устройств.</li>
          <li>Настройте политики для BYOD (Bring Your Own Device) сценариев.</li>
          <li>Используйте шифрование и функции удалённого стирания данных.</li>
          <li>Регулярно проверяйте устройства на соответствие политикам.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadWhitelistingContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Application Whitelisting</h1>
      <div class="theory-section">
        <h2>Теория Application Whitelisting</h2>
        <p>Application Whitelisting (Белые списки приложений) — это подход к безопасности, при котором разрешается запуск только доверенных приложений, а всё остальное блокируется. Это эффективный способ предотвращения выполнения вредоносного ПО.</p>

        <h3>Принципы работы Application Whitelisting</h3>
        <ul>
          <li><strong>Создание белого списка:</strong> Формирует список разрешённых приложений (по имени, хэшу или пути).</li>
          <li><strong>Блокировка:</strong> Запрещает запуск любых приложений, не входящих в белый список.</li>
          <li><strong>Мониторинг:</strong> Отслеживает попытки запуска запрещённых приложений.</li>
          <li><strong>Обновление:</strong> Позволяет добавлять новые приложения в список после проверки.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Вредоносное ПО:</strong> Вирусы, трояны и ransomware могут запускаться без контроля.</li>
          <li><strong>Несанкционированные приложения:</strong> Сотрудники могут устанавливать нежелательное ПО.</li>
          <li><strong>Zero-day угрозы:</strong> Новые вредоносные программы могут обойти традиционные антивирусы.</li>
        </ul>

        <h3>Схема работы Application Whitelisting</h3>
        <div class="whitelisting-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Приложение</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Whitelisting Tool</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Проверка (белый список)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Запуск (разрешено/запрещено)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (логи)</div>
          </div>
        </div>

        <h3>Примеры Application Whitelisting</h3>
        <ul>
          <li><strong>Microsoft AppLocker:</strong> Управление приложениями в Windows.</li>
          <li><strong>Carbon Black App Control:</strong> Защита на основе белых списков.</li>
        </ul>

        <h3>Рекомендации по внедрению Application Whitelisting</h3>
        <ol>
          <li>Создайте белый список для критически важных систем.</li>
          <li>Регулярно обновляйте список разрешённых приложений.</li>
          <li>Используйте в связке с EDR для мониторинга и анализа.</li>
          <li>Обучайте сотрудников избегать установки непроверенного ПО.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadFimContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>File Integrity Monitoring</h1>
      <div class="theory-section">
        <h2>Теория File Integrity Monitoring</h2>
        <p>File Integrity Monitoring (FIM) — это технология, которая отслеживает изменения в критически важных файлах, папках и реестре, чтобы обнаружить несанкционированные модификации, которые могут указывать на атаку или нарушение безопасности.</p>

        <h3>Принципы работы FIM</h3>
        <ul>
          <li><strong>Базовая линия:</strong> Создаёт эталонный снимок файлов (хэши, атрибуты).</li>
          <li><strong>Мониторинг:</strong> Сравнивает текущие файлы с базовой линией для выявления изменений.</li>
          <li><strong>Оповещения:</strong> Генерирует уведомления о подозрительных изменениях.</li>
          <li><strong>Соответствие:</strong> Помогает соответствовать стандартам (например, PCI DSS).</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Вредоносное ПО:</strong> Вирусы или трояны могут изменять системные файлы.</li>
          <li><strong>Инсайдерские угрозы:</strong> Сотрудники могут умышленно или случайно изменить критические файлы.</li>
          <li><strong>APT-атаки:</strong> Злоумышленники могут модифицировать файлы для скрытия следов.</li>
        </ul>

        <h3>Схема работы FIM</h3>
        <div class="fim-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Критические файлы</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">FIM Tool</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Мониторинг изменений</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Оповещения (изменения)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (интеграция)</div>
          </div>
        </div>

        <h3>Примеры FIM</h3>
        <ul>
          <li><strong>Tripwire:</strong> Мониторинг целостности файлов.</li>
          <li><strong>OSSEC:</strong> Open-source решение для FIM.</li>
        </ul>

        <h3>Рекомендации по внедрению FIM</h3>
        <ol>
          <li>Настройте FIM для системных файлов и конфигураций.</li>
          <li>Интегрируйте с SIEM для анализа событий.</li>
          <li>Регулярно проверяйте отчёты FIM на предмет аномалий.</li>
          <li>Создайте политики для реагирования на изменения.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadNtaContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Network Traffic Analysis</h1>
      <div class="theory-section">
        <h2>Теория Network Traffic Analysis</h2>
        <p>Network Traffic Analysis (NTA) — это технология анализа сетевого трафика для обнаружения аномалий, угроз и подозрительного поведения. NTA помогает выявить такие угрозы, как командно-контрольный (C2) трафик, утечки данных и атаки на сеть.</p>

        <h3>Принципы работы NTA</h3>
        <ul>
          <li><strong>Сбор данных:</strong> Собирает данные о сетевом трафике (пакеты, метаданные).</li>
          <li><strong>Анализ:</strong> Использует машинное обучение и поведенческий анализ для выявления аномалий.</li>
          <li><strong>Обнаружение угроз:</strong> Выявляет подозрительный трафик (например, C2-соединения).</li>
          <li><strong>Оповещения:</strong> Генерирует уведомления о потенциальных угрозах.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Скрытые атаки:</strong> Злоумышленники могут использовать шифрованный трафик для C2-соединений.</li>
          <li><strong>Утечка данных:</strong> Несанкционированная передача данных может остаться незамеченной.</li>
          <li><strong>DoS-атаки:</strong> Аномальный трафик может указывать на атаку.</li>
        </ul>

        <h3>Схема работы NTA</h3>
        <div class="nta-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Сетевой трафик</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">NTA Tool</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Анализ (ML, поведение)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Обнаружение (C2, утечки)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (оповещения)</div>
          </div>
        </div>

        <h3>Примеры NTA</h3>
        <ul>
          <li><strong>Darktrace:</strong> Использует AI для анализа трафика.</li>
          <li><strong>ExtraHop:</strong> Обнаружение угроз в реальном времени.</li>
        </ul>

        <h3>Рекомендации по внедрению NTA</h3>
        <ol>
          <li>Разверните NTA на ключевых участках сети (например, на периметре).</li>
          <li>Используйте в связке с SIEM для корреляции данных.</li>
          <li>Настройте оповещения для аномального трафика.</li>
          <li>Регулярно обновляйте модели машинного обучения.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadDeceptionContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Deception Technology</h1>
      <div class="theory-section">
        <h2>Теория Deception Technology</h2>
        <p>Deception Technology (Технологии обмана) — это подход к безопасности, который использует ловушки (honeypots, honeytokens) для привлечения злоумышленников. Это позволяет обнаружить атаки на ранней стадии и собрать информацию о методах атакующих.</p>

        <h3>Принципы работы Deception Technology</h3>
        <ul>
          <li><strong>Создание ловушек:</strong> Разворачивает ложные активы (серверы, файлы, учётные записи).</li>
          <li><strong>Мониторинг:</strong> Отслеживает взаимодействие с ловушками.</li>
          <li><strong>Обнаружение:</strong> Выявляет злоумышленников на основе их активности.</li>
          <li><strong>Анализ:</strong> Собирает данные о методах и целях атакующих.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>APT-атаки:</strong> Целенаправленные атаки могут оставаться незамеченными.</li>
          <li><strong>Инсайдерские угрозы:</strong> Сотрудники могут пытаться получить доступ к ложным данным.</li>
          <li><strong>Скрытые атаки:</strong> Злоумышленники могут использовать сложные техники для обхода защиты.</li>
        </ul>

        <h3>Схема работы Deception Technology</h3>
        <div class="deception-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Злоумышленник</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Deception Tool</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Ловушки (honeypots)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Обнаружение (активность)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">SIEM (анализ)</div>
          </div>
        </div>

        <h3>Примеры Deception Technology</h3>
        <ul>
          <li><strong>Attivo Networks:</strong> Комплексные решения для обмана.</li>
          <li><strong>DeceptionGrid:</strong> Защита от внутренних и внешних угроз.</li>
        </ul>

        <h3>Рекомендации по внедрению Deception Technology</h3>
        <ol>
          <li>Разверните ловушки в критически важных сегментах сети.</li>
          <li>Интегрируйте с SIEM для анализа событий.</li>
          <li>Регулярно обновляйте ловушки для повышения эффективности.</li>
          <li>Используйте данные из ловушек для улучшения общей защиты.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}



function loadPersonalFirewallContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Локальный межсетевой экран</h1>
      <div class="theory-section">
        <h2>Теория Локального межсетевого экрана</h2>
        <p>Локальный межсетевой экран (Personal Firewall) — это программное обеспечение, установленное на рабочих станциях, которое контролирует входящий и исходящий сетевой трафик на основе заданных правил. Оно защищает устройство от несанкционированных подключений и сетевых атак.</p>

        <h3>Принципы работы Локального межсетевого экрана</h3>
        <ul>
          <li><strong>Фильтрация трафика:</strong> Проверяет пакеты данных на соответствие правилам (например, по IP, портам).</li>
          <li><strong>Блокировка:</strong> Запрещает несанкционированные подключения или подозрительный трафик.</li>
          <li><strong>Мониторинг приложений:</strong> Контролирует сетевую активность программ.</li>
          <li><strong>Оповещения:</strong> Уведомляет пользователя о подозрительных действиях.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Сетевые атаки:</strong> Попытки эксплуатации уязвимостей через открытые порты.</li>
          <li><strong>Несанкционированный доступ:</strong> Злоумышленники могут пытаться подключиться к устройству.</li>
          <li><strong>Утечка данных:</strong> Подозрительные приложения могут отправлять данные в сеть.</li>
        </ul>

        <h3>Схема работы Локального межсетевого экрана</h3>
        <div class="firewall-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Сетевой трафик</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Локальный Firewall</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Фильтрация (правила)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Действие (разрешить/блокировать)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (мониторинг)</div>
          </div>
        </div>

        <h3>Примеры Локального межсетевого экрана</h3>
        <ul>
          <li><strong>Windows Defender Firewall:</strong> Встроенный межсетевой экран в Windows.</li>
          <li><strong>Comodo Firewall:</strong> Бесплатное решение с функциями HIPS.</li>
        </ul>

        <h3>Рекомендации по внедрению Локального межсетевого экрана</h3>
        <ol>
          <li>Настройте строгие правила для входящего и исходящего трафика.</li>
          <li>Регулярно проверяйте логи межсетевого экрана на предмет подозрительной активности.</li>
          <li>Используйте в связке с корпоративным NGFW для комплексной защиты.</li>
          <li>Обучайте сотрудников не отключать межсетевой экран.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadAntiSpywareContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Антишпионское ПО</h1>
      <div class="theory-section">
        <h2>Теория Антишпионского ПО</h2>
        <p>Антишпионское ПО защищает рабочие станции от шпионских программ, которые собирают конфиденциальные данные, такие как пароли, история браузера или личная информация, и передают их злоумышленникам.</p>

        <h3>Принципы работы Антишпионского ПО</h3>
        <ul>
          <li><strong>Сканирование:</strong> Проверяет систему на наличие шпионских программ.</li>
          <li><strong>Мониторинг поведения:</strong> Отслеживает подозрительные действия, такие как кейлоггинг.</li>
          <li><strong>Удаление:</strong> Удаляет обнаруженные шпионские программы.</li>
          <li><strong>Защита в реальном времени:</strong> Предотвращает установку шпионского ПО.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Кейлоггеры:</strong> Программы, записывающие нажатия клавиш для кражи паролей.</li>
          <li><strong>Шпионское ПО:</strong> Собирает данные и передаёт их злоумышленникам.</li>
          <li><strong>Adware:</strong> Отображает нежелательную рекламу и собирает данные о пользователе.</li>
        </ul>

        <h3>Схема работы Антишпионского ПО</h3>
        <div class="antispyware-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Система (файлы, процессы)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Антишпионское ПО</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Сканирование (поведение)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Действие (удаление)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Оповещения</div>
          </div>
        </div>

        <h3>Примеры Антишпионского ПО</h3>
        <ul>
          <li><strong>Malwarebytes:</strong> Эффективное решение для защиты от шпионского ПО.</li>
          <li><strong>SuperAntiSpyware:</strong> Специализированное ПО для удаления шпионских программ.</li>
        </ul>

        <h3>Рекомендации по внедрению Антишпионского ПО</h3>
        <ol>
          <li>Регулярно сканируйте рабочие станции на наличие шпионского ПО.</li>
          <li>Используйте антишпионское ПО в связке с антивирусом.</li>
          <li>Обучайте сотрудников избегать подозрительных загрузок и ссылок.</li>
          <li>Настройте защиту в реальном времени для предотвращения заражений.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadAntiRootkitContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Антируткит</h1>
      <div class="theory-section">
        <h2>Теория Антируткита</h2>
        <p>Антируткит-программы предназначены для обнаружения и удаления руткитов — вредоносных программ, которые скрывают своё присутствие в системе, получая привилегированный доступ и обходя традиционные средства защиты.</p>

        <h3>Принципы работы Антируткита</h3>
        <ul>
          <li><strong>Глубокое сканирование:</strong> Проверяет скрытые процессы, файлы и записи реестра.</li>
          <li><strong>Сравнение:</strong> Сравнивает системные вызовы с ожидаемым поведением.</li>
          <li><strong>Удаление:</strong> Удаляет руткиты, минимизируя повреждение системы.</li>
          <li><strong>Мониторинг:</strong> Отслеживает изменения в реальном времени.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Скрытые руткиты:</strong> Могут маскировать вредоносные процессы.</li>
          <li><strong>Привилегированный доступ:</strong> Руткиты могут предоставить злоумышленникам полный контроль.</li>
          <li><strong>Обход защиты:</strong> Руткиты могут отключать антивирусы.</li>
        </ul>

        <h3>Схема работы Антируткита</h3>
        <div class="antirootkit-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Система (процессы, реестр)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Антируткит</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Сканирование (глубокое)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Действие (удаление)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (мониторинг)</div>
          </div>
        </div>

        <h3>Примеры Антируткита</h3>
        <ul>
          <li><strong>TDSSKiller (Kaspersky):</strong> Инструмент для удаления руткитов семейства TDSS.</li>
          <li><strong>GMER:</strong> Бесплатное решение для обнаружения руткитов.</li>
        </ul>

        <h3>Рекомендации по внедрению Антируткита</h3>
        <ol>
          <li>Используйте антируткит для глубокого сканирования системы.</li>
          <li>Запускайте сканирование в безопасном режиме для повышения эффективности.</li>
          <li>Обновляйте антируткит для защиты от новых угроз.</li>
          <li>Интегрируйте с EDR для анализа сложных угроз.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadExploitProtectionContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Защита от эксплойтов</h1>
      <div class="theory-section">
        <h2>Теория Защиты от эксплойтов</h2>
        <p>Инструменты защиты от эксплойтов предотвращают использование уязвимостей в программном обеспечении для выполнения вредоносного кода. Они защищают рабочие станции от атак, использующих уязвимости в приложениях или операционной системе.</p>

        <h3>Принципы работы Защиты от эксплойтов</h3>
        <ul>
          <li><strong>Мониторинг поведения:</strong> Отслеживает подозрительные действия приложений.</li>
          <li><strong>Блокировка эксплойтов:</strong> Предотвращает выполнение вредоносного кода через уязвимости.</li>
          <li><strong>Защита памяти:</strong> Предотвращает атаки, использующие переполнение буфера.</li>
          <li><strong>Обнаружение zero-day:</strong> Выявляет новые эксплойты без сигнатур.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Zero-day эксплойты:</strong> Атаки, использующие неизвестные уязвимости.</li>
          <li><strong>Переполнение буфера:</strong> Злоумышленники могут внедрить вредоносный код.</li>
          <li><strong>Уязвимости приложений:</strong> Непропатченные программы становятся мишенью.</li>
        </ul>

        <h3>Схема работы Защиты от эксплойтов</h3>
        <div class="exploit-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Приложение (уязвимость)</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Защита от эксплойтов</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Мониторинг (поведение)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Действие (блокировка)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Оповещения</div>
          </div>
        </div>

        <h3>Примеры Защиты от эксплойтов</h3>
        <ul>
          <li><strong>Microsoft Defender Exploit Guard:</strong> Встроенная защита от эксплойтов в Windows.</li>
          <li><strong>HitmanPro.Alert:</strong> Защита от эксплойтов и криптоджекинга.</li>
        </ul>

        <h3>Рекомендации по внедрению Защиты от эксплойтов</h3>
        <ol>
          <li>Включите защиту от эксплойтов на всех рабочих станциях.</li>
          <li>Обновляйте ПО для минимизации уязвимостей.</li>
          <li>Используйте в связке с антивирусом и EDR.</li>
          <li>Настройте оповещения для анализа подозрительных действий.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadAppControlContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Контроль приложений</h1>
      <div class="theory-section">
        <h2>Теория Контроля приложений</h2>
        <p>Контроль приложений позволяет управлять тем, какие программы могут запускаться на рабочих станциях, предотвращая выполнение несанкционированного или вредоносного ПО. Это достигается через создание белых и чёрных списков приложений.</p>

        <h3>Принципы работы Контроля приложений</h3>
        <ul>
          <li><strong>Белые списки:</strong> Разрешает запуск только доверенных приложений.</li>
          <li><strong>Чёрные списки:</strong> Блокирует известные вредоносные программы.</li>
          <li><strong>Мониторинг:</strong> Отслеживает попытки запуска запрещённых приложений.</li>
          <li><strong>Обновление:</strong> Позволяет добавлять новые приложения в списки после проверки.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Вредоносное ПО:</strong> Несанкционированные программы могут нанести вред.</li>
          <li><strong>Shadow IT:</strong> Сотрудники могут устанавливать непроверенное ПО.</li>
          <li><strong>Zero-day угрозы:</strong> Новые вредоносные программы могут обойти традиционные антивирусы.</li>
        </ul>

        <h3>Схема работы Контроля приложений</h3>
        <div class="appcontrol-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Приложение</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Контроль приложений</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Проверка (белый/чёрный список)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Действие (разрешить/блокировать)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Логи (мониторинг)</div>
          </div>
        </div>

        <h3>Примеры Контроля приложений</h3>
        <ul>
          <li><strong>Microsoft AppLocker:</strong> Контроль приложений в Windows.</li>
          <li><strong>McAfee Application Control:</strong> Защита на основе белых списков.</li>
        </ul>

        <h3>Рекомендации по внедрению Контроля приложений</h3>
        <ol>
          <li>Создайте белый список для всех рабочих станций.</li>
          <li>Регулярно обновляйте списки разрешённых приложений.</li>
          <li>Интегрируйте с EDR для мониторинга и анализа.</li>
          <li>Обучайте сотрудников избегать установки непроверенного ПО.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadDiskEncryptionContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Шифрование дисков</h1>
      <div class="theory-section">
        <h2>Теория Шифрования дисков</h2>
        <p>Шифрование дисков защищает данные на рабочих станциях, шифруя весь диск или отдельные разделы, чтобы предотвратить несанкционированный доступ в случае утери устройства или кражи данных.</p>

        <h3>Принципы работы Шифрования дисков</h3>
        <ul>
          <li><strong>Полное шифрование диска (FDE):</strong> Шифрует весь диск, включая ОС.</li>
          <li><strong>Шифрование разделов:</strong> Шифрует отдельные разделы или файлы.</li>
          <li><strong>Управление ключами:</strong> Генерирует и хранит ключи шифрования.</li>
          <li><strong>Аутентификация:</strong> Требует пароль или ключ для доступа к данным.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Утрата устройств:</strong> Утерянные ноутбуки могут содержать конфиденциальные данные.</li>
          <li><strong>Физический доступ:</strong> Злоумышленники могут извлечь данные с диска.</li>
          <li><strong>Кража данных:</strong> Данные могут быть скопированы без шифрования.</li>
        </ul>

        <h3>Схема работы Шифрования дисков</h3>
        <div class="diskencryption-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Данные на диске</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Шифрование дисков</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Шифрование (AES)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Зашифрованные данные</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Управление ключами</div>
          </div>
        </div>

        <h3>Примеры Шифрования дисков</h3>
        <ul>
          <li><strong>BitLocker:</strong> Встроенное решение для шифрования дисков в Windows.</li>
          <li><strong>VeraCrypt:</strong> Бесплатное решение для шифрования дисков и разделов.</li>
        </ul>

        <h3>Рекомендации по внедрению Шифрования дисков</h3>
        <ol>
          <li>Включите шифрование дисков на всех рабочих станциях.</li>
          <li>Используйте надёжные пароли для доступа к зашифрованным данным.</li>
          <li>Храните ключи восстановления в безопасном месте.</li>
          <li>Регулярно проверяйте состояние шифрования на устройствах.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}

function loadAntiPhishingContent(container) {
  container.innerHTML = `
    <div class="security-tools-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Антифишинг</h1>
      <div class="theory-section">
        <h2>Теория Антифишинга</h2>
        <p>Антифишинговые инструменты защищают пользователей от фишинговых атак, которые пытаются украсть конфиденциальные данные, такие как пароли, данные банковских карт или учетные записи, через поддельные сайты или email-сообщения.</p>

        <h3>Принципы работы Антифишинга</h3>
        <ul>
          <li><strong>Анализ URL:</strong> Проверяет ссылки на наличие признаков фишинга.</li>
          <li><strong>Фильтрация email:</strong> Обнаруживает фишинговые письма и блокирует их.</li>
          <li><strong>Предупреждения:</strong> Уведомляет пользователей о подозрительных сайтах.</li>
          <li><strong>Базы данных:</strong> Использует базы известных фишинговых ресурсов.</li>
        </ul>

        <h3>Основные угрозы</h3>
        <ul>
          <li><strong>Фишинговые сайты:</strong> Поддельные сайты, имитирующие легитимные ресурсы.</li>
          <li><strong>Фишинговые письма:</strong> Сообщения, побуждающие раскрыть конфиденциальные данные.</li>
          <li><strong>Социальная инженерия:</strong> Злоумышленники манипулируют пользователями.</li>
        </ul>

        <h3>Схема работы Антифишинга</h3>
        <div class="antiphishing-diagram" style="margin: 20px 0; padding: 20px; border-radius: 8px; text-align: center; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
            <div style="background-color: #2e7d32; padding: 10px; border-radius: 5px; width: 200px;">Email/Сайт</div>
            <div style="border: 2px solid #66bb6a; padding: 10px; border-radius: 5px; width: 250px;">
              <div style="background-color: #388e3c; padding: 5px; border-radius: 5px;">Антифишинг</div>
              <div style="background-color: #66bb6a; padding: 5px; border-radius: 5px; margin-top: 5px;">Анализ (URL, email)</div>
            </div>
            <div style="background-color: #ffeb3b; color: #1a1a1a; padding: 10px; border-radius: 5px; width: 200px;">Действие (блокировка)</div>
            <div style="position: absolute; bottom: 10px; right: 10px; background-color: #2a2f3b; padding: 10px; border-radius: 5px;">Предупреждения</div>
          </div>
        </div>

        <h3>Примеры Антифишинга</h3>
        <ul>
          <li><strong>Microsoft Defender SmartScreen:</strong> Встроенная защита от фишинга в Windows и Edge.</li>
          <li><strong>Bitdefender Anti-Phishing:</strong> Защита от фишинга в браузерах.</li>
        </ul>

        <h3>Рекомендации по внедрению Антифишинга</h3>
        <ol>
          <li>Включите антифишинговую защиту в браузерах и email-клиентах.</li>
          <li>Обучайте сотрудников распознавать фишинговые письма.</li>
          <li>Используйте в связке с Secure Email Gateway для комплексной защиты.</li>
          <li>Регулярно обновляйте базы данных фишинговых ресурсов.</li>
        </ol>
      </div>
    </div>
  `;
  document.querySelector('.back-btn').addEventListener('click', () => loadSecurityToolsContent(container));
}