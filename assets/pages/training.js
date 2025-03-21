function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function loadTrainingContent(container) {
  container.innerHTML = `
    <div class="training-container">
      <h1>Тестирование</h1>
      <p>Выберите уровень сложности теста:</p>
      <div class="training-options">
        <select id="test-level">
          <option value="easy">Легкий</option>
          <option value="medium">Средний</option>
          <option value="hard">Сложный</option>
        </select>
        <button class="start-btn" id="start-test-btn">Начать</button>
      </div>
      <div class="osi-description">
        <h2>О тестах</h2>
        <p>Тесты предназначены для проверки ваших знаний в области информационной безопасности и сетевых технологий. Вы можете выбрать один из трёх уровней сложности:</p>
        <ul>
          <li><strong>Легкий уровень:</strong> Подходит для новичков. Включает базовые вопросы, например, о модели OSI и её роли в сетевых взаимодействиях.</li>
          <li><strong>Средний уровень:</strong> Для тех, кто уже знаком с основами. Вопросы касаются известных уязвимостей и атак, таких как WannaCry (CVE-2017-0144).</li>
          <li><strong>Сложный уровень:</strong> Для профессионалов. Проверяет знания современных методов защиты, таких как мониторинг аномалий через UEBA в архитектуре Zero Trust.</li>
        </ul>
        <p>Каждый тест состоит из 20 вопросов с тремя вариантами ответа. Выберите уровень и начните тестирование, чтобы оценить свои знания!</p>
      </div>
    </div>
  `;

  document.getElementById('start-test-btn').addEventListener('click', () => {
      const level = document.getElementById('test-level').value;
      loadTestContent(container, level);
  });
}

const questions = {
  easy: [
      { question: "Что такое модель OSI?", answers: [{ text: "Концептуальная модель сетевых взаимодействий", correct: true }, { text: "Программное обеспечение для маршрутизации", correct: false }, { text: "Язык программирования", correct: false }] },
      { question: "Сколько уровней в модели OSI?", answers: [{ text: "7", correct: true }, { text: "5", correct: false }, { text: "9", correct: false }] },
      { question: "Какой уровень отвечает за передачу битов?", answers: [{ text: "Физический", correct: true }, { text: "Сетевой", correct: false }, { text: "Прикладной", correct: false }] },
      { question: "Какой протокол работает на канальном уровне?", answers: [{ text: "Ethernet", correct: true }, { text: "HTTP", correct: false }, { text: "TCP", correct: false }] },
      { question: "Что такое IP-адрес?", answers: [{ text: "Логический адрес в сети", correct: true }, { text: "Физический адрес устройства", correct: false }, { text: "Название протокола", correct: false }] },
      { question: "Какой уровень модели OSI отвечает за маршрутизацию?", answers: [{ text: "Сетевой", correct: true }, { text: "Транспортный", correct: false }, { text: "Канальный", correct: false }] },
      { question: "TCP обеспечивает надежную передачу данных?", answers: [{ text: "Да", correct: true }, { text: "Нет", correct: false }, { text: "Иногда", correct: false }] },
      { question: "UDP быстрее TCP?", answers: [{ text: "Да", correct: true }, { text: "Нет", correct: false }, { text: "Зависит от сети", correct: false }] },
      { question: "Какой уровень отвечает за шифрование данных?", answers: [{ text: "Уровень представления", correct: true }, { text: "Сеансовый", correct: false }, { text: "Физический", correct: false }] },
      { question: "Что такое MAC-адрес?", answers: [{ text: "Физический адрес устройства", correct: true }, { text: "Логический адрес сети", correct: false }, { text: "Адрес электронной почты", correct: false }] },
      { question: "Какой протокол используется для отправки email?", answers: [{ text: "SMTP", correct: true }, { text: "FTP", correct: false }, { text: "DNS", correct: false }] },
      { question: "HTTPS использует шифрование?", answers: [{ text: "Да", correct: true }, { text: "Нет", correct: false }, { text: "Только на сервере", correct: false }] },
      { question: "Что делает коммутатор?", answers: [{ text: "Пересылает данные по MAC-адресам", correct: true }, { text: "Маршрутизирует данные между сетями", correct: false }, { text: "Шифрует данные", correct: false }] },
      { question: "Какой уровень отвечает за установку соединения между приложениями?", answers: [{ text: "Сеансовый", correct: true }, { text: "Физический", correct: false }, { text: "Сетевой", correct: false }] },
      { question: "Что такое DNS?", answers: [{ text: "Преобразует доменные имена в IP-адреса", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Маршрутизирует пакеты", correct: false }] },
      { question: "Какой протокол работает на прикладном уровне?", answers: [{ text: "HTTP", correct: true }, { text: "IP", correct: false }, { text: "ARP", correct: false }] },
      { question: "ARP связывает IP с чем?", answers: [{ text: "MAC-адресом", correct: true }, { text: "Портом", correct: false }, { text: "Доменом", correct: false }] },
      { question: "Какой уровень отвечает за сжатие данных?", answers: [{ text: "Уровень представления", correct: true }, { text: "Транспортный", correct: false }, { text: "Канальный", correct: false }] },
      { question: "Что делает маршрутизатор?", answers: [{ text: "Маршрутизирует данные между сетями", correct: true }, { text: "Пересылает данные всем портам", correct: false }, { text: "Шифрует трафик", correct: false }] },
      { question: "Какой протокол используется для проверки доступности?", answers: [{ text: "ICMP", correct: true }, { text: "UDP", correct: false }, { text: "FTP", correct: false }] },
      { question: "Что такое AES?", answers: [{ text: "Симметричный шифр", correct: true }, { text: "Асимметричный шифр", correct: false }, { text: "Протокол маршрутизации", correct: false }] },
      { question: "RSA — это симметричный алгоритм?", answers: [{ text: "Нет", correct: true }, { text: "Да", correct: false }, { text: "Зависит от реализации", correct: false }] },
      { question: "Что такое PKI?", answers: [{ text: "Инфраструктура открытых ключей", correct: true }, { text: "Протокол маршрутизации", correct: false }, { text: "Система управления базами данных", correct: false }] },
      { question: "Электронная подпись подтверждает подлинность?", answers: [{ text: "Да", correct: true }, { text: "Нет", correct: false }, { text: "Только в HTTPS", correct: false }] },
      { question: "Какой стандарт регулирует цифровые сертификаты?", answers: [{ text: "X.509", correct: true }, { text: "ISO 27001", correct: false }, { text: "IEEE 802.3", correct: false }] },
      { question: "Что такое HSM?", answers: [{ text: "Аппаратный модуль безопасности", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Программное обеспечение для маршрутизации", correct: false }] },
      { question: "Какой закон регулирует ЭП в России?", answers: [{ text: "ФЗ-63", correct: true }, { text: "ФЗ-149", correct: false }, { text: "ФЗ-187", correct: false }] },
      { question: "GDPR защищает персональные данные?", answers: [{ text: "Да", correct: true }, { text: "Нет", correct: false }, { text: "Только в США", correct: false }] },
      { question: "Что такое ISO/IEC 27001?", answers: [{ text: "Стандарт управления ИБ", correct: true }, { text: "Протокол шифрования", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "PCI DSS относится к чему?", answers: [{ text: "Защите данных банковских карт", correct: true }, { text: "Защите медицинских данных", correct: false }, { text: "Шифрованию трафика", correct: false }] },
      { question: "Что такое DLP?", answers: [{ text: "Система предотвращения утечек данных", correct: true }, { text: "Межсетевой экран", correct: false }, { text: "Антивирус", correct: false }] },
      { question: "Какой инструмент защищает веб-приложения?", answers: [{ text: "WAF", correct: true }, { text: "NGFW", correct: false }, { text: "SIEM", correct: false }] },
      { question: "SIEM собирает данные из каких источников?", answers: [{ text: "Логи и события", correct: true }, { text: "Только сеть", correct: false }, { text: "Только приложения", correct: false }] },
      { question: "Что делает антивирус?", answers: [{ text: "Обнаруживает и удаляет вредоносное ПО", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Анализирует сетевой трафик", correct: false }] },
      { question: "Какой инструмент защищает конечные устройства?", answers: [{ text: "EDR", correct: true }, { text: "IDS", correct: false }, { text: "VPN", correct: false }] },
      { question: "NGFW использует DPI для чего?", answers: [{ text: "Анализа содержимого пакетов", correct: true }, { text: "Шифрования трафика", correct: false }, { text: "Блокировки IP", correct: false }] },
      { question: "Что такое VPN?", answers: [{ text: "Виртуальная частная сеть", correct: true }, { text: "Система управления доступом", correct: false }, { text: "Антишпионское ПО", correct: false }] },
      { question: "Какой инструмент помогает автоматизировать реагирование?", answers: [{ text: "SOAR", correct: true }, { text: "PAM", correct: false }, { text: "CASB", correct: false }] },
      { question: "IDS обнаруживает угрозы, а IPS их…?", answers: [{ text: "Блокирует", correct: true }, { text: "Шифрует", correct: false }, { text: "Логирует", correct: false }] },
      { question: "Что защищает шифрование дисков?", answers: [{ text: "Данные на устройстве", correct: true }, { text: "Сетевой трафик", correct: false }, { text: "Приложения", correct: false }] },
      { question: "Какой уровень иерархической модели отвечает за подключение рабочих станций?", answers: [{ text: "Уровень доступа (Access)", correct: true }, { text: "Уровень агрегации (Distribution)", correct: false }, { text: "Уровень ядра (Core)", correct: false }] },
      { question: "Что делает VLAN в сети?", answers: [{ text: "Разделяет трафик на логические подсети", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Ускоряет маршрутизацию", correct: false }] },
      { question: "Какой протокол используется для автоматического назначения IP-адресов?", answers: [{ text: "DHCP", correct: true }, { text: "OSPF", correct: false }, { text: "SNMP", correct: false }] },
      { question: "Что обеспечивает протокол VRRP?", answers: [{ text: "Резервирование шлюза по умолчанию", correct: true }, { text: "Шифрование трафика", correct: false }, { text: "Мониторинг сети", correct: false }] },
      { question: "Какой протокол приоритизирует трафик, например, VoIP?", answers: [{ text: "QoS", correct: true }, { text: "BGP", correct: false }, { text: "IPsec", correct: false }] },
      { question: "Что такое структурная безопасность?", answers: [{ text: "Комплексный подход к защите всех уровней ИТ-инфраструктуры", correct: true }, { text: "Шифрование данных в облаке", correct: false }, { text: "Защита только операционных систем", correct: false }] },
      { question: "Какой принцип требует, чтобы пользователи имели доступ только к необходимым ресурсам?", answers: [{ text: "Принцип минимальных привилегий", correct: true }, { text: "Многоуровневая защита", correct: false }, { text: "Сегментация", correct: false }] },
      { question: "Как называется подход, использующий несколько слоёв защиты?", answers: [{ text: "Defense-in-Depth", correct: true }, { text: "Zero Trust", correct: false }, { text: "SIEM", correct: false }] },
      { question: "Что делает VLAN в контексте безопасности АСУТП?", answers: [{ text: "Изолирует сеть АСУТП от корпоративной сети", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Ускоряет передачу данных", correct: false }] },
      { question: "Какой федеральный закон регулирует безопасность КИИ в России?", answers: [{ text: "ФЗ-187", correct: true }, { text: "ФЗ-149", correct: false }, { text: "ГОСТ Р ИСО/МЭК 27001", correct: false }] },
      { question: "Что защищает IPsec в сетях?", answers: [{ text: "Данные при передаче", correct: true }, { text: "Физический доступ к оборудованию", correct: false }, { text: "Приложения от DDoS", correct: false }] },
      { question: "Какой уровень модели Purdue отвечает за SCADA-системы?", answers: [{ text: "Уровень 2", correct: true }, { text: "Уровень 0", correct: false }, { text: "Уровень 4", correct: false }] },
      { question: "Что такое гостайна?", answers: [{ text: "Сведения, разглашение которых угрожает безопасности РФ", correct: true }, { text: "Данные в облаке", correct: false }, { text: "Информация о сетях АСУТП", correct: false }] },
      { question: "Какой инструмент используется для мониторинга событий безопасности?", answers: [{ text: "SIEM", correct: true }, { text: "DLP", correct: false }, { text: "WAF", correct: false }] },
      { question: "Что защищает шумогенератор?", answers: [{ text: "От акустических утечек", correct: true }, { text: "От DDoS-атак", correct: false }, { text: "От перехвата трафика", correct: false }] },
      { question: "Что такое уязвимость в контексте информационной безопасности?", answers: [{ text: "Слабое место в системе, которое может быть использовано злоумышленником", correct: true }, { text: "Вирус, распространяющийся через сеть", correct: false }, { text: "Ошибка в настройке сети", correct: false }] },
      { question: "Какой стандарт используется для оценки критичности уязвимостей?", answers: [{ text: "CVSS", correct: true }, { text: "CWE", correct: false }, { text: "MITRE ATT&CK", correct: false }] },
      { question: "Что такое CVE?", answers: [{ text: "Уникальный идентификатор известных уязвимостей", correct: true }, { text: "Система классификации слабостей кода", correct: false }, { text: "Методика реагирования на инциденты", correct: false }] },
      { question: "Какой подход помогает выявить уязвимости через имитацию атак?", answers: [{ text: "Пентест", correct: true }, { text: "Threat Modeling", correct: false }, { text: "Анализ CVE", correct: false }] },
      { question: "Что означает принцип Zero Trust?", answers: [{ text: "Никогда не доверяй, всегда проверяй", correct: true }, { text: "Доверяй всем внутри сети", correct: false }, { text: "Шифруй все данные", correct: false }] },
      { question: "Какой этап Incident Response включает создание плана реагирования?", answers: [{ text: "Подготовка", correct: true }, { text: "Сдерживание", correct: false }, { text: "Восстановление", correct: false }] },
      { question: "Что делает OWASP Top 10?", answers: [{ text: "Описывает наиболее критичные уязвимости веб-приложений", correct: true }, { text: "Классифицирует слабости кода", correct: false }, { text: "Оценивает критичность уязвимостей", correct: false }] },
      { question: "Как называется база данных угроз и уязвимостей от ФСТЭК?", answers: [{ text: "БДУ ФСТЭК", correct: true }, { text: "NVD", correct: false }, { text: "MITRE ATT&CK", correct: false }] },
      { question: "Что такое Log4Shell?", answers: [{ text: "Уязвимость в библиотеке Log4j (CVE-2021-44228)", correct: true }, { text: "Техника атаки из MITRE ATT&CK", correct: false }, { text: "Слабость в коде (CWE)", correct: false }] },
      { question: "Какой инструмент помогает обнаружить попытки эксплуатации уязвимостей через логи?", answers: [{ text: "SIEM", correct: true }, { text: "WAF", correct: false }, { text: "IDS", correct: false }] },
  ],
  medium: [
      { question: "Какой уровень OSI использует протокол IPv4?", answers: [{ text: "Сетевой", correct: true }, { text: "Транспортный", correct: false }, { text: "Физический", correct: false }] },
      { question: "Сколько пакетов нужно для установки TCP-соединения?", answers: [{ text: "3", correct: true }, { text: "2", correct: false }, { text: "4", correct: false }] },
      { question: "Какой протокол на транспортном уровне ненадёжен?", answers: [{ text: "UDP", correct: true }, { text: "TCP", correct: false }, { text: "ICMP", correct: false }] },
      { question: "Какой уровень отвечает за физическую адресацию?", answers: [{ text: "Канальный", correct: true }, { text: "Сетевой", correct: false }, { text: "Прикладной", correct: false }] },
      { question: "Что такое NGFW?", answers: [{ text: "Межсетевой экран нового поколения", correct: true }, { text: "Веб-приложение", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой протокол преобразует IP в MAC?", answers: [{ text: "ARP", correct: true }, { text: "DNS", correct: false }, { text: "DHCP", correct: false }] },
      { question: "Какой уровень использует SSL/TLS?", answers: [{ text: "Уровень представления", correct: true }, { text: "Сетевой", correct: false }, { text: "Канальный", correct: false }] },
      { question: "Какой алгоритм использует эллиптические кривые?", answers: [{ text: "ECDSA", correct: true }, { text: "RSA", correct: false }, { text: "AES", correct: false }] },
      { question: "Что такое гомоморфное шифрование?", answers: [{ text: "Шифрование с вычислениями над данными", correct: true }, { text: "Симметричное шифрование", correct: false }, { text: "Асимметричное шифрование", correct: false }] },
      { question: "Какой режим AES уязвим к анализу?", answers: [{ text: "ECB", correct: true }, { text: "CBC", correct: false }, { text: "GCM", correct: false }] },
      { question: "Какой протокол обеспечивает аутентификацию в AES?", answers: [{ text: "GCM", correct: true }, { text: "ECB", correct: false }, { text: "CTR", correct: false }] },
      { question: "Что такое QKD?", answers: [{ text: "Квантовое распределение ключей", correct: true }, { text: "Симметричный шифр", correct: false }, { text: "Протокол маршрутизации", correct: false }] },
      { question: "Какой стандарт заменил Оранжевую книгу?", answers: [{ text: "Common Criteria", correct: true }, { text: "ISO 27001", correct: false }, { text: "PCI DSS", correct: false }] },
      { question: "Какой уровень Оранжевой книги использует мандатное управление?", answers: [{ text: "B", correct: true }, { text: "C", correct: false }, { text: "A", correct: false }] },
      { question: "Что такое CRL в PKI?", answers: [{ text: "Список отозванных сертификатов", correct: true }, { text: "Протокол проверки", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "Какой протокол используется для проверки статуса сертификата?", answers: [{ text: "OCSP", correct: true }, { text: "SMTP", correct: false }, { text: "FTP", correct: false }] },
      { question: "Какой закон регулирует КИИ в России?", answers: [{ text: "ФЗ-187", correct: true }, { text: "ФЗ-63", correct: false }, { text: "ФЗ-149", correct: false }] },
      { question: "Что такое госСОПКА?", answers: [{ text: "Система защиты от кибератак", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Программное обеспечение", correct: false }] },
      { question: "Какой орган выдает лицензии на защиту информации в РФ?", answers: [{ text: "ФСТЭК", correct: true }, { text: "Роскомнадзор", correct: false }, { text: "ФСБ", correct: false }] },
      { question: "Что такое S/MIME?", answers: [{ text: "Протокол шифрования email", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Алгоритм шифрования", correct: false }] },
      { question: "Какой алгоритм основан на факторизации?", answers: [{ text: "RSA", correct: true }, { text: "AES", correct: false }, { text: "ECDSA", correct: false }] },
      { question: "Что такое CA в PKI?", answers: [{ text: "Удостоверяющий центр", correct: true }, { text: "Список сертификатов", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой стандарт регулирует защиту АСУТП?", answers: [{ text: "ISO/IEC 62443", correct: true }, { text: "GDPR", correct: false }, { text: "ISO 27001", correct: false }] },
      { question: "Что делает WAF?", answers: [{ text: "Защищает веб-приложения", correct: true }, { text: "Маршрутизирует данные", correct: false }, { text: "Шифрует трафик", correct: false }] },
      { question: "Какой протокол используется в HTTPS?", answers: [{ text: "TLS", correct: true }, { text: "IP", correct: false }, { text: "UDP", correct: false }] },
      { question: "Что такое PKCS #7?", answers: [{ text: "Формат сообщений с подписью", correct: true }, { text: "Протокол маршрутизации", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "Какой уровень OSI использует WebSocket?", answers: [{ text: "Прикладной", correct: true }, { text: "Канальный", correct: false }, { text: "Сетевой", correct: false }] },
      { question: "Что такое Blowfish?", answers: [{ text: "Симметричный шифр", correct: true }, { text: "Асимметричный шифр", correct: false }, { text: "Протокол маршрутизации", correct: false }] },
      { question: "Какой закон регулирует персональные данные в ЕС?", answers: [{ text: "GDPR", correct: true }, { text: "HIPAA", correct: false }, { text: "ФЗ-152", correct: false }] },
      { question: "Что такое NIST SP 800-53?", answers: [{ text: "Стандарт безопасности США", correct: true }, { text: "Протокол шифрования", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "Какой уровень данных защищает DLP?", answers: [{ text: "Данные в движении, в покое и в использовании", correct: true }, { text: "Только данные в движении", correct: false }, { text: "Только данные в покое", correct: false }] },
      { question: "Что делает корреляция в SIEM?", answers: [{ text: "Выявляет связи между событиями", correct: true }, { text: "Шифрует логи", correct: false }, { text: "Блокирует трафик", correct: false }] },
      { question: "Какую атаку блокирует WAF?", answers: [{ text: "SQL-инъекции", correct: true }, { text: "DDoS", correct: false }, { text: "Фишинг", correct: false }] },
      { question: "Что анализирует EDR на конечных устройствах?", answers: [{ text: "Процессы и сетевую активность", correct: true }, { text: "Только файлы", correct: false }, { text: "Только реестр", correct: false }] },
      { question: "Какой инструмент использует ловушки для обнаружения атак?", answers: [{ text: "Deception Technology", correct: true }, { text: "NTA", correct: false }, { text: "XDR", correct: false }] },
      { question: "NGFW может проверять шифрованный трафик?", answers: [{ text: "Да", correct: true }, { text: "Нет", correct: false }, { text: "Только HTTPS", correct: false }] },
      { question: "Что такое XDR?", answers: [{ text: "Расширенное обнаружение и реагирование", correct: true }, { text: "Система управления доступом", correct: false }, { text: "Межсетевой экран", correct: false }] },
      { question: "Какой инструмент управляет привилегированным доступом?", answers: [{ text: "PAM", correct: true }, { text: "IAM", correct: false }, { text: "HSM", correct: false }] },
      { question: "Что проверяет File Integrity Monitoring (FIM)?", answers: [{ text: "Изменения в файлах и реестре", correct: true }, { text: "Сетевой трафик", correct: false }, { text: "Приложения", correct: false }] },
      { question: "Какой инструмент защищает облачные приложения?", answers: [{ text: "CASB", correct: true }, { text: "ZTNA", correct: false }, { text: "SASE", correct: false }] },
      { question: "Какой протокол маршрутизации использует алгоритм Dijkstra?", answers: [{ text: "OSPF", correct: true }, { text: "RIP", correct: false }, { text: "EIGRP", correct: false }] },
      { question: "Что делает NetFlow в корпоративной сети?", answers: [{ text: "Анализирует сетевой трафик для обнаружения аномалий", correct: true }, { text: "Назначает IP-адреса", correct: false }, { text: "Шифрует данные", correct: false }] },
      { question: "Какую роль выполняет уровень агрегации (Distribution) в сети?", answers: [{ text: "Агрегирует трафик и поддерживает маршрутизацию между VLAN", correct: true }, { text: "Подключает конечные устройства", correct: false }, { text: "Обеспечивает высокоскоростную маршрутизацию", correct: false }] },
      { question: "Для чего используется протокол IPsec?", answers: [{ text: "Шифрование и аутентификация данных в VPN", correct: true }, { text: "Предотвращение петель в сети", correct: false }, { text: "Синхронизация времени", correct: false }] },
      { question: "Какой протокол предотвращает петли на канальном уровне?", answers: [{ text: "STP", correct: true }, { text: "HSRP", correct: false }, { text: "MPLS", correct: false }] },
      { question: "Что включает модель разделяемой ответственности в облаке?", answers: [{ text: "Провайдер защищает инфраструктуру, клиент — данные и приложения", correct: true }, { text: "Клиент отвечает за всё", correct: false }, { text: "Провайдер отвечает за всё", correct: false }] },
      { question: "Какой протокол используется для контроля доступа к сети АСУТП?", answers: [{ text: "802.1X", correct: true }, { text: "SNMP", correct: false }, { text: "BGP", correct: false }] },
      { question: "Что делает система IDS в сети?", answers: [{ text: "Обнаруживает вторжения", correct: true }, { text: "Шифрует трафик", correct: false }, { text: "Фильтрует входящие запросы", correct: false }] },
      { question: "Какой стандарт регулирует управление информационной безопасностью?", answers: [{ text: "ГОСТ Р ИСО/МЭК 27001", correct: true }, { text: "ФЗ-187", correct: false }, { text: "Приказ ФСТЭК № 239", correct: false }] },
      { question: "Что такое DMZ в контексте сегментации сети?", answers: [{ text: "Промежуточная зона между IT и OT", correct: true }, { text: "Основная сеть АСУТП", correct: false }, { text: "Внешняя сеть", correct: false }] },
      { question: "Какой метод предотвращает утечки через USB-носители?", answers: [{ text: "DLP-системы", correct: true }, { text: "Шумогенераторы", correct: false }, { text: "IPsec", correct: false }] },
      { question: "Какой уровень OSI защищает от ARP-спуфинга?", answers: [{ text: "Канальный уровень", correct: true }, { text: "Сетевой уровень", correct: false }, { text: "Прикладной уровень", correct: false }] },
      { question: "Что такое аттестация помещений?", answers: [{ text: "Проверка на соответствие требованиям защиты от утечек", correct: true }, { text: "Обновление ПО", correct: false }, { text: "Шифрование данных", correct: false }] },
      { question: "Какой протокол используется для аутентификации в корпоративных сетях?", answers: [{ text: "Kerberos", correct: true }, { text: "IPsec", correct: false }, { text: "TLS", correct: false }] },
      { question: "Что защищает WAF в облаке?", answers: [{ text: "Веб-приложения от атак", correct: true }, { text: "Физический доступ", correct: false }, { text: "Сетевой трафик", correct: false }] },
      { question: "Какой метод предотвращения указан в OWASP Top 10 для защиты от инъекций (A03)?", answers: [{ text: "Использовать подготовленные выражения (Prepared Statements)", correct: true }, { text: "Шифровать данные", correct: false }, { text: "Ограничить доступ к API", correct: false }] },
      { question: "Что делает MITRE ATT&CK техника T1190?", answers: [{ text: "Использует уязвимости публичных приложений для начального доступа", correct: true }, { text: "Выполняет команды через PowerShell", correct: false }, { text: "Собирает информацию о системе", correct: false }] },
      { question: "Какой CVSS-рейтинг считается критическим и требует немедленного устранения?", answers: [{ text: "9.0–10.0", correct: true }, { text: "5.0–6.9", correct: false }, { text: "3.0–4.9", correct: false }] },
      { question: "Какой этап жизненного цикла уязвимости включает выпуск патча вендором?", answers: [{ text: "Исправление", correct: true }, { text: "Обнаружение", correct: false }, { text: "Эксплуатация", correct: false }] },
      { question: "Что помогает предотвратить уязвимость Broken Object Level Authorization (BOLA) в OWASP API Security?", answers: [{ text: "Проверка прав доступа на серверной стороне", correct: true }, { text: "Использование HTTPS", correct: false }, { text: "Логирование всех запросов", correct: false }] },
      { question: "Какой стандарт описывает этапы реагирования на инциденты, включая NIST SP 800-61?", answers: [{ text: "NIST SP 800-61", correct: true }, { text: "ISO/IEC 27001", correct: false }, { text: "OWASP Top 10", correct: false }] },
      { question: "Что такое CWE-79?", answers: [{ text: "Слабость, связанная с XSS (межсайтовым скриптингом)", correct: true }, { text: "Переполнение буфера", correct: false }, { text: "Утечка данных", correct: false }] },
      { question: "Какой метод ZTA ограничивает боковое перемещение злоумышленников?", answers: [{ text: "Микросегментация", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Логирование активности", correct: false }] },
      { question: "Какую роль играет БДУ ФСТЭК в разработке моделей угроз?", answers: [{ text: "Предоставляет данные об актуальных угрозах и уязвимостях", correct: true }, { text: "Оценивает критичность уязвимостей", correct: false }, { text: "Генерирует эксплойты", correct: false }] },
      { question: "Какой пример атаки связан с уязвимостью CVE-2017-0144?", answers: [{ text: "WannaCry", correct: true }, { text: "SolarWinds", correct: false }, { text: "Log4Shell", correct: false }] },
  ],
  hard: [
      { question: "Какой протокол на канальном уровне поддерживает LLC?", answers: [{ text: "IEEE 802.2", correct: true }, { text: "PPP", correct: false }, { text: "ARP", correct: false }] },
      { question: "Что такое SCTP?", answers: [{ text: "Протокол с многопотоковой передачей", correct: true }, { text: "Симметричный шифр", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "Какой алгоритм PQC основан на решётках?", answers: [{ text: "CRYSTALS-Kyber", correct: true }, { text: "SPHINCS+", correct: false }, { text: "FALCON", correct: false }] },
      { question: "Что делает протокол DCCP?", answers: [{ text: "Передача с управлением перегрузки", correct: true }, { text: "Надёжная передача данных", correct: false }, { text: "Шифрование трафика", correct: false }] },
      { question: "Какой уровень OSI использует протокол gRPC?", answers: [{ text: "Сеансовый", correct: true }, { text: "Сетевой", correct: false }, { text: "Физический", correct: false }] },
      { question: "Что такое BB84?", answers: [{ text: "Протокол QKD", correct: true }, { text: "Алгоритм шифрования", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой режим AES сочетает шифрование и аутентификацию?", answers: [{ text: "GCM", correct: true }, { text: "ECB", correct: false }, { text: "CBC", correct: false }] },
      { question: "Что такое ElGamal?", answers: [{ text: "Асимметричный алгоритм", correct: true }, { text: "Симметричный шифр", correct: false }, { text: "Протокол маршрутизации", correct: false }] },
      { question: "Какой стандарт заменил DES?", answers: [{ text: "AES", correct: true }, { text: "RSA", correct: false }, { text: "Blowfish", correct: false }] },
      { question: "Что такое PKCS #10?", answers: [{ text: "Формат запроса сертификата", correct: true }, { text: "Протокол подписи", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "Какой уровень Оранжевой книги требует формальной верификации?", answers: [{ text: "A1", correct: true }, { text: "B2", correct: false }, { text: "C1", correct: false }] },
      { question: "Что такое OCSP Stapling?", answers: [{ text: "Ускорение проверки сертификата", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой закон РФ требует лицензирование защиты информации?", answers: [{ text: "ПП РФ № 79", correct: true }, { text: "ФЗ-149", correct: false }, { text: "ФЗ-63", correct: false }] },
      { question: "Что такое НКЦКИ?", answers: [{ text: "Национальный центр по инцидентам", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Программное обеспечение", correct: false }] },
      { question: "Какой стандарт регулирует защиту медицинских данных в США?", answers: [{ text: "HIPAA", correct: true }, { text: "GDPR", correct: false }, { text: "ISO 27001", correct: false }] },
      { question: "Что такое Twofish?", answers: [{ text: "Преемник Blowfish", correct: true }, { text: "Асимметричный алгоритм", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой протокол использует L2TP?", answers: [{ text: "IPsec", correct: true }, { text: "TCP", correct: false }, { text: "UDP", correct: false }] },
      { question: "Что делает SPHINCS+?", answers: [{ text: "Подпись на основе хэш-функций", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Маршрутизация", correct: false }] },
      { question: "Какой приказ ФСТЭК регулирует АСУТП?", answers: [{ text: "Приказ № 31", correct: true }, { text: "Приказ № 17", correct: false }, { text: "Приказ № 21", correct: false }] },
      { question: "Что такое Certificate Transparency?", answers: [{ text: "Мониторинг сертификатов", correct: true }, { text: "Протокол шифрования", correct: false }, { text: "Сетевой стандарт", correct: false }] },
      { question: "Какой уровень OSI использует MIDI?", answers: [{ text: "Уровень представления", correct: true }, { text: "Транспортный", correct: false }, { text: "Сетевой", correct: false }] },
      { question: "Что такое FALCON?", answers: [{ text: "PQC алгоритм подписи", correct: true }, { text: "Симметричный шифр", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой протокол заменяет NetBIOS?", answers: [{ text: "gRPC", correct: true }, { text: "L2TP", correct: false }, { text: "PPTP", correct: false }] },
      { question: "Что делает Diffie-Hellman?", answers: [{ text: "Обмен ключами", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Маршрутизация", correct: false }] },
      { question: "Какой стандарт регулирует платежные карты?", answers: [{ text: "PCI DSS", correct: true }, { text: "ISO/IEC 27001", correct: false }, { text: "GDPR", correct: false }] },
      { question: "Что такое SHA-256?", answers: [{ text: "Хэш-функция", correct: true }, { text: "Протокол маршрутизации", correct: false }, { text: "Симметричный шифр", correct: false }] },
      { question: "Какой уровень OSI использует RJ45?", answers: [{ text: "Физический", correct: true }, { text: "Канальный", correct: false }, { text: "Сетевой", correct: false }] },
      { question: "Что такое ГОСТ 28147-89?", answers: [{ text: "Российский блочный шифр", correct: true }, { text: "Асимметричный алгоритм", correct: false }, { text: "Сетевой протокол", correct: false }] },
      { question: "Какой приказ ФСБ регулирует госСОПКА?", answers: [{ text: "Приказ № 281", correct: true }, { text: "Приказ № 66", correct: false }, { text: "Приказ № 17", correct: false }] },
      { question: "Что такое SELinux?", answers: [{ text: "Система мандатного управления", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Программное обеспечение", correct: false }] },
      { question: "Какой метод анализа использует DLP для классификации данных?", answers: [{ text: "Шаблоны и машинное обучение", correct: true }, { text: "Только сигнатурный анализ", correct: false }, { text: "Только поведенческий анализ", correct: false }] },
      { question: "Что делает SOAR помимо автоматизации?", answers: [{ text: "Оркестрация систем безопасности", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Анализ трафика", correct: false }] },
      { question: "Какой стандарт требует использования FIM?", answers: [{ text: "PCI DSS", correct: true }, { text: "GDPR", correct: false }, { text: "ISO 27001", correct: false }] },
      { question: "Какой тип анализа использует NTA для обнаружения C2-трафика?", answers: [{ text: "Машинное обучение и поведенческий", correct: true }, { text: "Только сигнатурный", correct: false }, { text: "Только аномальный", correct: false }] },
      { question: "Что включает XDR помимо данных EDR?", answers: [{ text: "Данные NDR и облачных систем", correct: true }, { text: "Только сетевой трафик", correct: false }, { text: "Только логи SIEM", correct: false }] },
      { question: "Какой метод защиты применяет WAF против известных уязвимостей?", answers: [{ text: "Виртуальные патчи", correct: true }, { text: "Шифрование трафика", correct: false }, { text: "Белые списки", correct: false }] },
      { question: "Какой российский продукт поддерживает ГОСТ-шифрование в NGFW?", answers: [{ text: "Континент 4", correct: true }, { text: "InfoWatch", correct: false }, { text: "MaxPatrol", correct: false }] },
      { question: "Что делает Sandboxing для анализа угроз?", answers: [{ text: "Запускает файлы в изолированной среде", correct: true }, { text: "Шифрует подозрительные данные", correct: false }, { text: "Блокирует сетевой трафик", correct: false }] },
      { question: "Какой инструмент использует мандатное управление доступом?", answers: [{ text: "NAC", correct: true }, { text: "MDM", correct: false }, { text: "SASE", correct: false }] },
      { question: "Какой тип шифрования использует HSM для защиты ключей?", answers: [{ text: "Аппаратное шифрование", correct: true }, { text: "Программное шифрование", correct: false }, { text: "Гибридное шифрование", correct: false }] },
      { question: "Какую технологию использует VXLAN для создания оверлей-сетей?", answers: [{ text: "Инкапсуляцию кадров в UDP", correct: true }, { text: "Шифрование с помощью IPsec", correct: false }, { text: "Метки MPLS", correct: false }] },
      { question: "Какой протокол маршрутизации между автономными системами использует атрибуты AS Path и MED?", answers: [{ text: "BGP", correct: true }, { text: "OSPF", correct: false }, { text: "RIP", correct: false }] },
      { question: "Что делает 802.1X в корпоративной сети?", answers: [{ text: "Аутентифицирует устройства перед подключением с помощью EAP и RADIUS", correct: true }, { text: "Шифрует трафик между VLAN", correct: false }, { text: "Агрегирует каналы", correct: false }] },
      { question: "Какой протокол Cisco объединяет порты на разных коммутаторах в один канал, избегая STP-блокировок?", answers: [{ text: "VPC", correct: true }, { text: "LACP", correct: false }, { text: "HSRP", correct: false }] },
      { question: "Какую функцию выполняет MPLS в сетях провайдеров?", answers: [{ text: "Маршрутизацию на основе меток для создания изолированных VPN", correct: true }, { text: "Синхронизацию времени", correct: false }, { text: "Обнаружение соседних устройств", correct: false }] },
      { question: "Какую роль играет модель Purdue в защите АСУТП?", answers: [{ text: "Делит сеть на уровни с разными функциями и требованиями безопасности", correct: true }, { text: "Шифрует данные между уровнями", correct: false }, { text: "Определяет уязвимости оборудования", correct: false }] },
      { question: "Какой приказ ФСТЭК регулирует безопасность значимых объектов КИИ?", answers: [{ text: "Приказ № 239", correct: true }, { text: "Приказ № 77", correct: false }, { text: "Приказ № 31", correct: false }] },
      { question: "Что такое ПЭМИН и как от него защищаться?", answers: [{ text: "Побочные электромагнитные излучения; экранирование помещений", correct: true }, { text: "Перехват трафика; шифрование TLS", correct: false }, { text: "Фишинг; обучение персонала", correct: false }] },
      { question: "Какой алгоритм хэширования паролей рекомендуется для защиты учетных данных?", answers: [{ text: "bcrypt", correct: true }, { text: "MD5", correct: false }, { text: "SHA-1", correct: false }] },
      { question: "Что делает SOAR в структурной безопасности?", answers: [{ text: "Автоматизирует реагирование на инциденты", correct: true }, { text: "Шифрует трафик", correct: false }, { text: "Фильтрует запросы", correct: false }] },
      { question: "Какой уровень модели OSI защищает TLS?", answers: [{ text: "Транспортный уровень", correct: true }, { text: "Сетевой уровень", correct: false }, { text: "Физический уровень", correct: false }] },
      { question: "Что такое Zero Trust в контексте облачной безопасности?", answers: [{ text: "Принцип, требующий аутентификации каждого запроса", correct: true }, { text: "Шифрование данных в покое", correct: false }, { text: "Сегментация сети", correct: false }] },
      { question: "Какой российский стандарт регулирует порядок аттестации объектов информатизации?", answers: [{ text: "ГОСТ Р 56397-2015", correct: true }, { text: "ГОСТ Р ИСО/МЭК 62443", correct: false }, { text: "ФЗ-149", correct: false }] },
      { question: "Что делает CloudTrail в AWS?", answers: [{ text: "Логирует действия для аудита", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Защищает от DDoS", correct: false }] },
      { question: "Какой пример атаки на КИИ упомянут в документе?", answers: [{ text: "BlackEnergy (2015) на энергосистему Украины", correct: true }, { text: "Stuxnet (2010) на АСУТП", correct: false }, { text: "WannaCry (2017) на ОС", correct: false }] },
      { question: "Какой подход из раздела 'Уязвимости' использует STRIDE для выявления угроз?", answers: [{ text: "Threat Modeling", correct: true }, { text: "Анализ рисков", correct: false }, { text: "Пентест", correct: false }] },
      { question: "Что делает техника T1059 в MITRE ATT&CK, и как её можно обнаружить?", answers: [{ text: "Выполняет команды через интерпретаторы; мониторинг командных строк в SIEM", correct: true }, { text: "Собирает данные о системе; ограничение доступа", correct: false }, { text: "Использует RDP; блокировка портов", correct: false }] },
      { question: "Какой CVE из таблицы CVSS связан с утечкой данных из памяти OpenSSL?", answers: [{ text: "CVE-2014-0160 (Heartbleed)", correct: true }, { text: "CVE-2017-0144 (EternalBlue)", correct: false }, { text: "CVE-2019-0708 (BlueKeep)", correct: false }] },
      { question: "Какой метод предотвращения для API6 (Mass Assignment) из OWASP API Security Top 10 исключает автоматическую привязку данных?", answers: [{ text: "Использование строгих схем валидации", correct: true }, { text: "Шифрование токенов", correct: false }, { text: "Rate Limiting", correct: false }] },
      { question: "Какой этап Incident Response требует сохранения улик, таких как логи и дампы памяти?", answers: [{ text: "Сдерживание", correct: true }, { text: "Устранение", correct: false }, { text: "Анализ уроков", correct: false }] },
      { question: "Какую слабость из БДУ ФСТЭК (BDU:2020-05130) можно устранить с помощью безопасных функций обработки данных?", answers: [{ text: "Buffer Overflow (CWE-120)", correct: true }, { text: "XSS (CWE-79)", correct: false }, { text: "Information Disclosure (CWE-200)", correct: false }] },
      { question: "Какой стандарт формализовал принципы Zero Trust Architecture в 2020 году?", answers: [{ text: "NIST 800-207", correct: true }, { text: "ISO/IEC 27035", correct: false }, { text: "NIST SP 800-61", correct: false }] },
      { question: "Какой пример атаки из раздела 'История развития угроз' использовал несколько 0-day уязвимостей для атаки на промышленные системы?", answers: [{ text: "Stuxnet (2010)", correct: true }, { text: "SolarWinds (2020)", correct: false }, { text: "WannaCry (2017)", correct: false }] },
      { question: "Что делает анализ рисков (Risk Assessment) в управлении уязвимостями?", answers: [{ text: "Оценивает вероятность и воздействие угроз по формуле Risk = Вероятность × Воздействие", correct: true }, { text: "Проводит имитацию атак", correct: false }, { text: "Классифицирует слабости кода", correct: false }] },
      { question: "Какой метод защиты от T1003 (Credential Dumping) в ZTA включает использование поведенческой аналитики?", answers: [{ text: "Мониторинг аномалий через UEBA", correct: true }, { text: "Микросегментация сети", correct: false }, { text: "Шифрование данных в движении", correct: false }] },
    ]
};

function getRandomQuestions(level) {
  const allQuestions = questions[level];
  const shuffledQuestions = shuffleArray([...allQuestions]);
  const selectedQuestions = shuffledQuestions.slice(0, 20);

  selectedQuestions.forEach(question => {
      question.answers = shuffleArray([...question.answers]);
  });

  return selectedQuestions;
}

function loadTestContent(container, level) {
  const testQuestions = getRandomQuestions(level);
  let html = `
    <div class="test-container">
      <button class="abort-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Прервать тест
      </button>
      <h1>Тест: ${level === 'easy' ? 'Легкий' : level === 'medium' ? 'Средний' : 'Сложный'}</h1>
      <form id="test-form">
  `;

  testQuestions.forEach((q, index) => {
      html += `
        <div class="question">
          <p>${index + 1}. ${q.question}</p>
          <div class="answer-options">
            <label><input type="radio" name="q${index}" value="0"> ${q.answers[0].text}</label>
            <label><input type="radio" name="q${index}" value="1"> ${q.answers[1].text}</label>
            <label><input type="radio" name="q${index}" value="2"> ${q.answers[2].text}</label>
          </div>
        </div>
      `;
  });

  html += `
        <button type="submit" class="finish-btn">Завершить тест</button>
      </form>
    </div>
  `;

  container.innerHTML = html;

  document.querySelector('.abort-btn').addEventListener('click', () => {
      loadTrainingContent(container);
  });

  document.getElementById('test-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const answers = [];
      testQuestions.forEach((q, index) => {
          const selected = document.querySelector(`input[name="q${index}"]:checked`);
          answers.push({
              question: q.question,
              selected: selected ? q.answers[selected.value].text : "Не отвечено",
              correct: q.answers.find(a => a.correct).text,
              isCorrect: selected ? q.answers[selected.value].correct : false
          });
      });
      loadResultsContent(container, answers);
  });
}

function loadResultsContent(container, answers) {
  const correctCount = answers.filter(a => a.isCorrect).length;
  let html = `
    <div class="results-container">
      <h1>Результаты теста</h1>
      <p>Правильных ответов: ${correctCount} из 20</p>
      <h2>Ваши ответы:</h2>
  `;

  answers.forEach((a, index) => {
      html += `
        <div class="result-item">
          <p>${index + 1}. ${a.question}</p>
          <p>Ваш ответ: ${a.selected} — <span class="${a.isCorrect ? 'correct' : 'incorrect'}">${a.isCorrect ? 'Правильно' : 'Неправильно'}</span></p>
          ${!a.isCorrect ? `<p>Правильный ответ: ${a.correct}</p>` : ''}
        </div>
      `;
  });

  html += `
      <button class="back-to-main-btn">Вернуться на главную</button>
    </div>
  `;

  container.innerHTML = html;

  document.querySelector('.back-to-main-btn').addEventListener('click', () => {
      loadTrainingContent(container);
  });
}