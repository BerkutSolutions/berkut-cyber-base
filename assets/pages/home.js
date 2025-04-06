function loadHomeContent(targetArea) {
  targetArea.innerHTML = `
    <h1>Главная</h1>
    <div class="description">
      <p><strong>Berkut Cyber Base</strong> — это локальная библиотека знаний, разработанная специально для специалистов по информационной безопасности и защиты информации. Программа представляет собой удобный инструмент для изучения, анализа и применения ключевых концепций в области кибербезопасности.</p>
      <p>Приложение объединяет в себе обширный набор тем, включая модель OSI, уязвимости, построение сетей, криптографию, электронные подписи и инфраструктуру открытых ключей (PKI), инструменты информационной безопасности, защиту структур, правовые нормы, локальные нормативные акты, моделирование угроз, а также модули обучения и тестирования.</p>
      <p><strong>Для чего нужна программа?</strong></p>
      <ul>
        <li><strong>Обучение и повышение квалификации:</strong> предоставляет структурированные материалы для освоения основ и углубленного изучения тем ИБ.</li>
        <li><strong>Практическое применение:</strong> помогает специалистам быстро находить информацию и применять её в реальных задачах.</li>
        <li><strong>Локальность и безопасность:</strong> работает оффлайн, обеспечивая конфиденциальность данных и независимость от интернета.</li>
        <li><strong>Удобство:</strong> интуитивно понятный интерфейс и быстрый доступ к нужным разделам.</li>
      </ul>
    </div>
    <hr class="section-divider">
    <div class="home-sections">
      <div class="column">
        <button class="section-btn" data-section="osi">Модель OSI</button>
        <button class="section-btn" data-section="vulnerabilities">Уязвимости</button>
        <button class="section-btn" data-section="malware-analysis">Анализ ВПО</button>
        <button class="section-btn" data-section="pentesting">Пентестинг</button>
        <button class="section-btn" data-section="social-engineering">Социальная инженерия</button>
        <button class="section-btn" data-section="osint">OSINT</button>
      </div>
      <div class="column">
        <button class="section-btn" data-section="forensics">Форензика</button>
        <button class="section-btn" data-section="network-building">Построение сетей</button>
        <button class="section-btn" data-section="cryptography">Криптография</button>
        <button class="section-btn" data-section="ep-pki">ЭП и PKI</button>
        <button class="section-btn" data-section="ib-tools">Инструменты ИБ</button>
        <button class="section-btn" data-section="russian-szi">Российские СЗИ</button>
      </div>
      <div class="column">
        <button class="section-btn" data-section="structure-security">Защита структур</button>
        <button class="section-btn" data-section="legal-regulations">Правовые нормы</button>
        <button class="section-btn" data-section="lna-lnd">ЛНА и ЛНД</button>
        <button class="section-btn" data-section="threat-model">Модель угроз</button>
        <button class="section-btn" data-section="certificates">Сертификаты</button>
        <button class="section-btn" data-section="teams-threat-intel">Команды ИБ и Threat Intelligence</button>
      </div>
    </div>
  `;

  document.querySelectorAll('.section-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const section = btn.getAttribute('data-section');
      window.loadPage(section);
    });
    btn.setAttribute('title', getTooltipText(btn.getAttribute('data-section')));
  });

  function getTooltipText(section) {
    const tooltips = {
      osi: 'Модель OSI (Open Systems Interconnection) — это стандартная структура, описывающая взаимодействие сетевых компонентов. Делит процесс передачи данных на семь уровней, от физического до прикладного.',
      vulnerabilities: 'Изучение уязвимостей в системах и приложениях: типы, обнаружение и методы защиты для повышения безопасности IT-инфраструктуры.',
      'malware-analysis': 'Анализ вредоносных программ (ВПО): методы выявления, изучения и нейтрализации вирусов, троянов и других угроз.',
      pentesting: 'Пентестинг — моделирование атак для выявления слабых мест в системах, с практическими рекомендациями по защите.',
      'social-engineering': 'Методы манипуляции людьми для получения данных. Научитесь избегать атак и защищать организацию.',
      osint: 'OSINT (Open Source Intelligence) — сбор и анализ данных из открытых источников для разведки и безопасности.',
      forensics: 'Компьютерная форензика: сбор, анализ и сохранение цифровых доказательств для расследования кибератак.',
      'network-building': 'Проектирование, настройка и защита компьютерных сетей: топологии, протоколы и инструменты.',
      cryptography: 'Криптография: шифрование данных, хеширование и обеспечение конфиденциальности.',
      'ep-pki': 'Электронная подпись (ЭП) и PKI: аутентификация и безопасность данных.',
      'ib-tools': 'Инструменты ИБ: сканеры уязвимостей, анализаторы трафика и мониторинг.',
      'russian-szi': 'Российские СЗИ: технологии и стандарты для защиты информации согласно законодательству.',
      'structure-security': 'Защита структур: методы обеспечения безопасности корпоративных и государственных систем.',
      'legal-regulations': 'Правовые нормы: законодательные акты и требования в области информационной безопасности.',
      'lna-lnd': 'ЛНА и ЛНД: разработка и применение внутренних правил организаций.',
      'threat-model': 'Модель угроз: анализ рисков и стратегии защиты систем.',
      training: 'Обучение и тестирование: модули для повышения квалификации в ИБ.',
      certificates: 'Обзор сертификатов для специалистов ИБ: как получить, для чего нужны и какие навыки подтверждают.',
      'teams-threat-intel': 'Обзор команд ИБ (Blue Team, Red Team, Purple Team) и процессов Threat Hunting и Threat Intelligence для защиты и анализа угроз.'
    };
    return tooltips[section] || '';
  }
}