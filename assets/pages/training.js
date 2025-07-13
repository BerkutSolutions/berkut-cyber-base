// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

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
        <p>Каждый тест состоит из 30 вопросов с тремя вариантами ответа. Выберите уровень и начните тестирование, чтобы оценить свои знания!</p>
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
    // Модель OSI
    { question: "Что описывает модель OSI?", answers: [{ text: "Концептуальную структуру сетевых взаимодействий", correct: true }, { text: "Программное обеспечение для маршрутизации", correct: false }, { text: "Язык программирования", correct: false }] },
    { question: "Сколько уровней в модели OSI?", answers: [{ text: "7", correct: true }, { text: "5", correct: false }, { text: "9", correct: false }] },
    { question: "Какой уровень модели OSI отвечает за физическое подключение?", answers: [{ text: "Физический", correct: true }, { text: "Сетевой", correct: false }, { text: "Прикладной", correct: false }] },
    { question: "Какой протокол работает на транспортном уровне модели OSI?", answers: [{ text: "TCP", correct: true }, { text: "Ethernet", correct: false }, { text: "HTTP", correct: false }] },
    { question: "Какой уровень модели TCP/IP соответствует сетевому уровню OSI?", answers: [{ text: "Интернет-уровень", correct: true }, { text: "Прикладной уровень", correct: false }, { text: "Канальный уровень", correct: false }] },

    // Уязвимости
    { question: "Что такое уязвимость в информационной безопасности?", answers: [{ text: "Слабое место, которое может быть использовано злоумышленником", correct: true }, { text: "Вирус, распространяющийся по сети", correct: false }, { text: "Ошибка в настройке оборудования", correct: false }] },
    { question: "Что описывает OWASP Top 10?", answers: [{ text: "Наиболее критичные уязвимости веб-приложений", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Методы шифрования", correct: false }] },
    { question: "Что такое CVE?", answers: [{ text: "Идентификатор известных уязвимостей", correct: true }, { text: "Система шифрования", correct: false }, { text: "Протокол маршрутизации", correct: false }] },
    { question: "Какой стандарт оценивает критичность уязвимостей?", answers: [{ text: "CVSS", correct: true }, { text: "ISO 27001", correct: false }, { text: "MITRE ATT&CK", correct: false }] },
    { question: "Что делает MITRE ATT&CK?", answers: [{ text: "Описывает тактики и техники атак", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Маршрутизирует трафик", correct: false }] },

    // Анализ ВПО
    { question: "Что такое ВПО в контексте кибербезопасности?", answers: [{ text: "Вредоносное программное обеспечение", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Система шифрования", correct: false }] },
    { question: "Какой тип анализа ВПО изучает код без его выполнения?", answers: [{ text: "Статический анализ", correct: true }, { text: "Динамический анализ", correct: false }, { text: "Гибридный анализ", correct: false }] },
    { question: "Какой инструмент часто используется для анализа ВПО?", answers: [{ text: "Wireshark", correct: true }, { text: "Metasploit", correct: false }, { text: "Nmap", correct: false }] },
    { question: "Что такое реверс-инжиниринг в анализе ВПО?", answers: [{ text: "Разборка кода для понимания его работы", correct: true }, { text: "Создание вируса", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой тип ВПО крадет данные пользователя?", answers: [{ text: "Шпионское ПО", correct: true }, { text: "Руткит", correct: false }, { text: "Червь", correct: false }] },

    // Пентестинг
    { question: "Что такое пентестинг?", answers: [{ text: "Тестирование на проникновение", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Анализ сетевого трафика", correct: false }] },
    { question: "Какой тип пентеста проводится без предварительной информации?", answers: [{ text: "Чёрный ящик", correct: true }, { text: "Белый ящик", correct: false }, { text: "Серый ящик", correct: false }] },
    { question: "Какой инструмент часто используется в пентестинге?", answers: [{ text: "Metasploit", correct: true }, { text: "Wireshark", correct: false }, { text: "IDA Pro", correct: false }] },
    { question: "Какой этап пентестинга включает сбор информации?", answers: [{ text: "Разведка", correct: true }, { text: "Эксплуатация", correct: false }, { text: "Анализ", correct: false }] },
    { question: "Какую уязвимость может выявить пентест?", answers: [{ text: "SQL-инъекцию", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Сетевой протокол", correct: false }] },

    // Социальная инженерия
    { question: "Что такое социальная инженерия?", answers: [{ text: "Манипуляция людьми для получения информации", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Анализ сетевого трафика", correct: false }] },
    { question: "Какой метод социальной инженерии использует поддельные письма?", answers: [{ text: "Фишинг", correct: true }, { text: "Предлог", correct: false }, { text: "Китобойный промысел", correct: false }] },
    { question: "Как защититься от социальной инженерии?", answers: [{ text: "Обучать сотрудников", correct: true }, { text: "Шифровать данные", correct: false }, { text: "Использовать VPN", correct: false }] },
    { question: "Как распознать фишинговое письмо?", answers: [{ text: "Подозрительные ссылки и ошибки в тексте", correct: true }, { text: "Официальный логотип компании", correct: false }, { text: "Длинный текст письма", correct: false }] },
    { question: "Что может быть целью социальной инженерии?", answers: [{ text: "Получение пароля", correct: true }, { text: "Ускорение сети", correct: false }, { text: "Шифрование данных", correct: false }] },

    // OSINT
    { question: "Что такое OSINT?", answers: [{ text: "Разведка на основе открытых источников", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },
    { question: "Какой инструмент используется для OSINT?", answers: [{ text: "Maltego", correct: true }, { text: "Metasploit", correct: false }, { text: "Wireshark", correct: false }] },
    { question: "Какой этап атаки OSINT включает сбор данных?", answers: [{ text: "Сбор информации о цели", correct: true }, { text: "Атака", correct: false }, { text: "Анализ данных", correct: false }] },
    { question: "Как противодействовать OSINT-атакам?", answers: [{ text: "Минимизировать цифровой след", correct: true }, { text: "Шифровать трафик", correct: false }, { text: "Использовать VPN", correct: false }] },
    { question: "Когда зародилась концепция OSINT?", answers: [{ text: "Во время Второй мировой войны", correct: true }, { text: "В 1990-х годах", correct: false }, { text: "В 2010-х годах", correct: false }] },

    // Форензика
    { question: "Что такое цифровая форензика?", answers: [{ text: "Расследование киберинцидентов", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Анализ сетевого трафика", correct: false }] },
    { question: "Какой этап форензики включает сбор улик?", answers: [{ text: "Сбор и анализ", correct: true }, { text: "Подготовка", correct: false }, { text: "Восстановление", correct: false }] },
    { question: "Какой инструмент используется в форензике?", answers: [{ text: "Autopsy", correct: true }, { text: "Metasploit", correct: false }, { text: "Nmap", correct: false }] },
    { question: "Какой плюс цифровой форензики?", answers: [{ text: "Помогает выявить злоумышленника", correct: true }, { text: "Ускоряет сеть", correct: false }, { text: "Шифрует данные", correct: false }] },
    { question: "Какой минус цифровой форензики?", answers: [{ text: "Сложность анализа больших данных", correct: true }, { text: "Низкая точность", correct: false }, { text: "Отсутствие инструментов", correct: false }] },

    // Построение сетей
    { question: "Что важно при построении корпоративной сети?", answers: [{ text: "Сегментация сети", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Использование VPN", correct: false }] },
    { question: "Какой протокол используется для маршрутизации?", answers: [{ text: "OSPF", correct: true }, { text: "HTTP", correct: false }, { text: "FTP", correct: false }] },
    { question: "Что делает DHCP в сети?", answers: [{ text: "Автоматически назначает IP-адреса", correct: true }, { text: "Шифрует трафик", correct: false }, { text: "Маршрутизирует данные", correct: false }] },
    { question: "Какой протокол предотвращает петли в сети?", answers: [{ text: "STP", correct: true }, { text: "BGP", correct: false }, { text: "DNS", correct: false }] },
    { question: "Что такое VLAN?", answers: [{ text: "Логическое разделение сети", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },

    // Криптография
    { question: "Что такое AES?", answers: [{ text: "Симметричный алгоритм шифрования", correct: true }, { text: "Асимметричный алгоритм", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Какой алгоритм использует два ключа?", answers: [{ text: "RSA", correct: true }, { text: "AES", correct: false }, { text: "SHA-256", correct: false }] },
    { question: "Что такое квантовое шифрование?", answers: [{ text: "Шифрование с использованием квантовых технологий", correct: true }, { text: "Симметричное шифрование", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Что делает хэш-функция?", answers: [{ text: "Создаёт уникальный отпечаток данных", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Маршрутизирует трафик", correct: false }] },
    { question: "Какой стандарт регулирует шифрование?", answers: [{ text: "FIPS 140-2", correct: true }, { text: "ISO 27001", correct: false }, { text: "GDPR", correct: false }] },

    // ЭП и PKI
    { question: "Что такое электронная подпись?", answers: [{ text: "Цифровой способ подтверждения подлинности", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод маршрутизации", correct: false }] },
    { question: "Что такое PKI?", answers: [{ text: "Инфраструктура открытых ключей", correct: true }, { text: "Система шифрования", correct: false }, { text: "Сетевой стандарт", correct: false }] },
    { question: "Какой компонент PKI выдаёт сертификаты?", answers: [{ text: "Удостоверяющий центр (CA)", correct: true }, { text: "Список отозванных сертификатов", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Какую угрозу для ЭП представляет компрометация ключа?", answers: [{ text: "Подделка подписи", correct: true }, { text: "Ускорение сети", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой стандарт регулирует цифровые сертификаты?", answers: [{ text: "X.509", correct: true }, { text: "ISO 27001", correct: false }, { text: "FIPS 140-2", correct: false }] },

    // Инструменты ИБ
    { question: "Какой инструмент защищает от утечек данных?", answers: [{ text: "DLP", correct: true }, { text: "SIEM", correct: false }, { text: "VPN", correct: false }] },
    { question: "Что делает WAF?", answers: [{ text: "Защищает веб-приложения", correct: true }, { text: "Шифрует трафик", correct: false }, { text: "Анализирует логи", correct: false }] },
    { question: "Какой инструмент защищает конечные устройства?", answers: [{ text: "EDR", correct: true }, { text: "NGFW", correct: false }, { text: "CASB", correct: false }] },
    { question: "Что делает Антивирус?", answers: [{ text: "Обнаруживает вредоносное ПО", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Маршрутизирует трафик", correct: false }] },
    { question: "Какой инструмент обеспечивает резервное копирование данных?", answers: [{ text: "Backup & Recovery", correct: true }, { text: "Patch Management", correct: false }, { text: "MDM", correct: false }] },
    // Защита структур
    { question: "Что такое Zero Trust?", answers: [{ text: "Принцип 'никогда не доверяй, всегда проверяй'", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },
    { question: "Как защитить операционную систему?", answers: [{ text: "Устанавливать обновления", correct: true }, { text: "Шифровать трафик", correct: false }, { text: "Использовать VPN", correct: false }] },
    { question: "Что защищает гостайну?", answers: [{ text: "Секретные данные государства", correct: true }, { text: "Сетевой трафик", correct: false }, { text: "Приложения", correct: false }] },
    { question: "Какой подход использует несколько слоёв защиты?", answers: [{ text: "Defense-in-Depth", correct: true }, { text: "Zero Trust", correct: false }, { text: "SIEM", correct: false }] },
    { question: "Что защищает DLP в облаке?", answers: [{ text: "Данные от утечек", correct: true }, { text: "Сетевой трафик", correct: false }, { text: "Физический доступ", correct: false }] },

    // Правовые нормы
    { question: "Какой закон регулирует безопасность КИИ в России?", answers: [{ text: "ФЗ-187", correct: true }, { text: "ФЗ-149", correct: false }, { text: "ФЗ-63", correct: false }] },
    { question: "Что регулирует GDPR?", answers: [{ text: "Защиту персональных данных в ЕС", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой орган в России регулирует защиту информации?", answers: [{ text: "ФСТЭК", correct: true }, { text: "Роскомнадзор", correct: false }, { text: "Минцифры", correct: false }] },
    { question: "Что такое Оранжевая книга?", answers: [{ text: "Стандарт безопасности США", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },
    { question: "Какой закон регулирует электронную подпись в России?", answers: [{ text: "ФЗ-63", correct: true }, { text: "ФЗ-187", correct: false }, { text: "ФЗ-149", correct: false }] },

    // ЛНА и ЛНД
    { question: "Что такое ЛНА в контексте ИБ?", answers: [{ text: "Локальные нормативные акты", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Методы шифрования", correct: false }] },
    { question: "Что регулируют ЛНД в организации?", answers: [{ text: "Правила и процедуры ИБ", correct: true }, { text: "Сетевой трафик", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой принцип важен при создании ЛНА?", answers: [{ text: "Соответствие законодательству", correct: true }, { text: "Ускорение сети", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Кто утверждает ЛНА в организации?", answers: [{ text: "Руководство", correct: true }, { text: "Сотрудники", correct: false }, { text: "Поставщики", correct: false }] },
    { question: "Для чего нужны ЛНД по ИБ?", answers: [{ text: "Обеспечение единых правил", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Маршрутизация трафика", correct: false }] },

    // Модель угроз
    { question: "Для чего нужна модель угроз?", answers: [{ text: "Для выявления потенциальных угроз", correct: true }, { text: "Для шифрования данных", correct: false }, { text: "Для маршрутизации трафика", correct: false }] },
    { question: "Какой элемент включается в модель угроз?", answers: [{ text: "Уязвимости системы", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Методы шифрования", correct: false }] },
    { question: "Какой этап разработки модели угроз включает анализ активов?", answers: [{ text: "Идентификация активов", correct: true }, { text: "Оценка рисков", correct: false }, { text: "Реализация мер", correct: false }] },
    { question: "Что помогает создать модель угроз?", answers: [{ text: "БДУ ФСТЭК", correct: true }, { text: "Wireshark", correct: false }, { text: "Metasploit", correct: false }] },
    { question: "Какой принцип важен при создании модели угроз?", answers: [{ text: "Актуальность данных", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Ускорение сети", correct: false }] },
  ],
  medium: [
    // Модель OSI
    { question: "Какой уровень OSI отвечает за маршрутизацию пакетов?", answers: [{ text: "Сетевой", correct: true }, { text: "Транспортный", correct: false }, { text: "Канальный", correct: false }] },
    { question: "Какой протокол работает на канальном уровне OSI?", answers: [{ text: "Ethernet", correct: true }, { text: "TCP", correct: false }, { text: "HTTP", correct: false }] },
    { question: "Какой уровень модели TCP/IP соответствует прикладному уровню OSI?", answers: [{ text: "Прикладной уровень", correct: true }, { text: "Транспортный уровень", correct: false }, { text: "Канальный уровень", correct: false }] },
    { question: "Какой уровень OSI использует SSL/TLS для шифрования?", answers: [{ text: "Уровень представления", correct: true }, { text: "Сетевой", correct: false }, { text: "Физический", correct: false }] },
    { question: "Какой уровень OSI отвечает за установку соединения между приложениями?", answers: [{ text: "Сеансовый", correct: true }, { text: "Транспортный", correct: false }, { text: "Канальный", correct: false }] },

    // Уязвимости
    { question: "Какой этап жизненного цикла уязвимости включает выпуск патча?", answers: [{ text: "Исправление", correct: true }, { text: "Обнаружение", correct: false }, { text: "Эксплуатация", correct: false }] },
    { question: "Какой CVSS-рейтинг считается критическим?", answers: [{ text: "9.0–10.0", correct: true }, { text: "5.0–6.9", correct: false }, { text: "3.0–4.9", correct: false }] },
    { question: "Какую уязвимость описывает CVE-2017-0144?", answers: [{ text: "WannaCry", correct: true }, { text: "Heartbleed", correct: false }, { text: "Log4Shell", correct: false }] },
    { question: "Что делает техника T1190 в MITRE ATT&CK?", answers: [{ text: "Использует уязвимости публичных приложений", correct: true }, { text: "Выполняет команды через PowerShell", correct: false }, { text: "Собирает данные о системе", correct: false }] },
    { question: "Какой метод предотвращает инъекции (A03) в OWASP Top 10?", answers: [{ text: "Использование подготовленных выражений", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Ограничение доступа", correct: false }] },

    // Анализ ВПО
    { question: "Какой тип анализа ВПО выполняется в изолированной среде?", answers: [{ text: "Динамический анализ", correct: true }, { text: "Статический анализ", correct: false }, { text: "Гибридный анализ", correct: false }] },
    { question: "Какой инструмент используется для реверс-инжиниринга ВПО?", answers: [{ text: "IDA Pro", correct: true }, { text: "Wireshark", correct: false }, { text: "Nmap", correct: false }] },
    { question: "Какой тип ВПО скрывает своё присутствие в системе?", answers: [{ text: "Руткит", correct: true }, { text: "Шпионское ПО", correct: false }, { text: "Червь", correct: false }] },
    { question: "Какой этап анализа ВПО включает декомпиляцию кода?", answers: [{ text: "Статический анализ", correct: true }, { text: "Динамический анализ", correct: false }, { text: "Сбор данных", correct: false }] },
    { question: "Какой тип ВПО распространяется по сети?", answers: [{ text: "Червь", correct: true }, { text: "Троян", correct: false }, { text: "Руткит", correct: false }] },

    // Пентестинг
    { question: "Какой тип пентеста предполагает частичную информацию о системе?", answers: [{ text: "Серый ящик", correct: true }, { text: "Чёрный ящик", correct: false }, { text: "Белый ящик", correct: false }] },
    { question: "Какой инструмент используется для сканирования уязвимостей?", answers: [{ text: "Nessus", correct: true }, { text: "Wireshark", correct: false }, { text: "IDA Pro", correct: false }] },
    { question: "Какой этап пентестинга включает использование эксплойтов?", answers: [{ text: "Эксплуатация", correct: true }, { text: "Разведка", correct: false }, { text: "Анализ", correct: false }] },
    { question: "Какую уязвимость может выявить пентест на веб-приложении?", answers: [{ text: "XSS (межсайтовый скриптинг)", correct: true }, { text: "ARP-спуфинг", correct: false }, { text: "DDoS-атака", correct: false }] },
    { question: "Какой этап пентестинга включает написание отчёта?", answers: [{ text: "Отчётность", correct: true }, { text: "Эксплуатация", correct: false }, { text: "Сбор данных", correct: false }] },

    // Социальная инженерия
    { question: "Какой метод социальной инженерии использует звонки?", answers: [{ text: "Вишинг", correct: true }, { text: "Фишинг", correct: false }, { text: "Смишинг", correct: false }] },
    { question: "Какой метод защиты от фишинга наиболее эффективен?", answers: [{ text: "Двухфакторная аутентификация", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Использование VPN", correct: false }] },
    { question: "Какой признак указывает на фишинговое письмо?", answers: [{ text: "Запрос пароля в письме", correct: true }, { text: "Официальный адрес отправителя", correct: false }, { text: "Длинный текст письма", correct: false }] },
    { question: "Что такое китобойный промысел в социальной инженерии?", answers: [{ text: "Атака на руководителей", correct: true }, { text: "Атака на сотрудников", correct: false }, { text: "Атака на клиентов", correct: false }] },
    { question: "Какой метод социальной инженерии использует поддельные SMS?", answers: [{ text: "Смишинг", correct: true }, { text: "Фишинг", correct: false }, { text: "Вишинг", correct: false }] },

    // OSINT
    { question: "Какой инструмент OSINT ищет устройства в интернете?", answers: [{ text: "Shodan", correct: true }, { text: "Maltego", correct: false }, { text: "SpiderFoot", correct: false }] },
    { question: "Какой этап противодействия OSINT включает аудит данных?", answers: [{ text: "Оценка цифрового следа", correct: true }, { text: "Мониторинг", correct: false }, { text: "Обучение сотрудников", correct: false }] },
    { question: "Какой инструмент OSINT проверяет утечки данных?", answers: [{ text: "Have I Been Pwned", correct: true }, { text: "Shodan", correct: false }, { text: "Maltego", correct: false }] },
    { question: "Какой пример OSINT-анализа связан с конфликтом на Украине?", answers: [{ text: "Анализ спутниковых снимков", correct: true }, { text: "Анализ кода вируса", correct: false }, { text: "Анализ сетевого трафика", correct: false }] },
    { question: "Какой закон в России ограничивает доступ к данным для OSINT?", answers: [{ text: "Суверенный интернет (2019)", correct: true }, { text: "ФЗ-63", correct: false }, { text: "ФЗ-187", correct: false }] },

    // Форензика
    { question: "Какой этап форензики включает подготовку инструментов?", answers: [{ text: "Подготовка и идентификация", correct: true }, { text: "Сбор и анализ", correct: false }, { text: "Отчёт и восстановление", correct: false }] },
    { question: "Какой инструмент форензики анализирует образы дисков?", answers: [{ text: "FTK Imager", correct: true }, { text: "Wireshark", correct: false }, { text: "Metasploit", correct: false }] },
    { question: "Как форензика помогает в ИБ?", answers: [{ text: "Выявляет источник атаки", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Ускоряет сеть", correct: false }] },
    { question: "Какой минус форензики связан с законодательством?", answers: [{ text: "Юридические ограничения на сбор данных", correct: true }, { text: "Низкая точность анализа", correct: false }, { text: "Отсутствие инструментов", correct: false }] },
    { question: "Какой этап форензики включает восстановление системы?", answers: [{ text: "Отчёт и восстановление", correct: true }, { text: "Сбор и анализ", correct: false }, { text: "Подготовка", correct: false }] },

    // Построение сетей
    { question: "Какой протокол маршрутизации использует алгоритм Dijkstra?", answers: [{ text: "OSPF", correct: true }, { text: "RIP", correct: false }, { text: "BGP", correct: false }] },
    { question: "Какой уровень иерархической модели сети подключает устройства?", answers: [{ text: "Уровень доступа", correct: true }, { text: "Уровень ядра", correct: false }, { text: "Уровень агрегации", correct: false }] },
    { question: "Какой протокол используется для синхронизации времени?", answers: [{ text: "NTP", correct: true }, { text: "DHCP", correct: false }, { text: "STP", correct: false }] },
    { question: "Что делает VRRP в сети?", answers: [{ text: "Резервирует шлюз по умолчанию", correct: true }, { text: "Шифрует трафик", correct: false }, { text: "Маршрутизирует данные", correct: false }] },
    { question: "Какой протокол приоритизирует трафик, например, VoIP?", answers: [{ text: "QoS", correct: true }, { text: "BGP", correct: false }, { text: "IPsec", correct: false }] },

    // Криптография
    { question: "Какой режим AES уязвим к анализу?", answers: [{ text: "ECB", correct: true }, { text: "CBC", correct: false }, { text: "GCM", correct: false }] },
    { question: "Какой алгоритм основан на факторизации чисел?", answers: [{ text: "RSA", correct: true }, { text: "AES", correct: false }, { text: "ECDSA", correct: false }] },
    { question: "Что такое QKD в квантовом шифровании?", answers: [{ text: "Квантовое распределение ключей", correct: true }, { text: "Симметричное шифрование", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Какой стандарт заменил DES?", answers: [{ text: "AES", correct: true }, { text: "RSA", correct: false }, { text: "Blowfish", correct: false }] },
    { question: "Какой алгоритм хэширования считается устаревшим?", answers: [{ text: "MD5", correct: true }, { text: "SHA-256", correct: false }, { text: "SHA-3", correct: false }] },

    // ЭП и PKI
    { question: "Какой протокол используется для проверки статуса сертификата?", answers: [{ text: "OCSP", correct: true }, { text: "SMTP", correct: false }, { text: "FTP", correct: false }] },
    { question: "Что такое CRL в PKI?", answers: [{ text: "Список отозванных сертификатов", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },
    { question: "Какую уязвимость PKI может вызвать компрометация CA?", answers: [{ text: "Выдача поддельных сертификатов", correct: true }, { text: "Ускорение сети", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой алгоритм используется для ЭП?", answers: [{ text: "RSA", correct: true }, { text: "AES", correct: false }, { text: "SHA-256", correct: false }] },
    { question: "Что такое S/MIME?", answers: [{ text: "Протокол шифрования email", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Алгоритм шифрования", correct: false }] },

    // Инструменты ИБ
    { question: "Какой инструмент использует ловушки для обнаружения атак?", answers: [{ text: "Deception Technology", correct: true }, { text: "Network Traffic Analysis", correct: false }, { text: "Threat Intelligence", correct: false }] },
    { question: "Что делает SOAR в ИБ?", answers: [{ text: "Автоматизирует реагирование на инциденты", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Анализирует сетевой трафик", correct: false }] },
    { question: "Какой инструмент защищает облачные приложения?", answers: [{ text: "CASB", correct: true }, { text: "ZTNA", correct: false }, { text: "SASE", correct: false }] },
    { question: "Что делает Vulnerability Management?", answers: [{ text: "Выявляет и устраняет уязвимости", correct: true }, { text: "Шифрует трафик", correct: false }, { text: "Обучает сотрудников", correct: false }] },
    { question: "Какой инструмент защищает от DDoS-атак?", answers: [{ text: "DDoS Protection", correct: true }, { text: "Secure Email Gateway", correct: false }, { text: "File Integrity Monitoring", correct: false }] },
    // Защита структур
    { question: "Какой метод Zero Trust ограничивает боковое перемещение?", answers: [{ text: "Микросегментация", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Логирование", correct: false }] },
    { question: "Как защитить сеть АСУТП?", answers: [{ text: "Использовать VLAN для изоляции", correct: true }, { text: "Шифровать данные", correct: false }, { text: "Использовать VPN", correct: false }] },
    { question: "Что защищает IPsec?", answers: [{ text: "Данные при передаче", correct: true }, { text: "Физический доступ", correct: false }, { text: "Приложения", correct: false }] },
    { question: "Какой принцип минимизирует доступ пользователей?", answers: [{ text: "Принцип минимальных привилегий", correct: true }, { text: "Многоуровневая защита", correct: false }, { text: "Сегментация", correct: false }] },
    { question: "Что защищает шумогенератор?", answers: [{ text: "От акустических утечек", correct: true }, { text: "От DDoS-атак", correct: false }, { text: "От перехвата трафика", correct: false }] },

    // Правовые нормы
    { question: "Какой приказ ФСТЭК регулирует безопасность КИИ?", answers: [{ text: "Приказ № 239", correct: true }, { text: "Приказ № 31", correct: false }, { text: "Приказ № 17", correct: false }] },
    { question: "Что регулирует HIPAA в США?", answers: [{ text: "Защиту медицинских данных", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой стандарт заменил Оранжевую книгу?", answers: [{ text: "Common Criteria", correct: true }, { text: "ISO 27001", correct: false }, { text: "PCI DSS", correct: false }] },
    { question: "Какой орган в России выдает лицензии на защиту информации?", answers: [{ text: "ФСТЭК", correct: true }, { text: "Роскомнадзор", correct: false }, { text: "Минцифры", correct: false }] },
    { question: "Что такое госСОПКА?", answers: [{ text: "Система защиты от кибератак", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Программное обеспечение", correct: false }] },

    // ЛНА и ЛНД
    { question: "Какой документ входит в ЛНА по ИБ?", answers: [{ text: "Политика безопасности", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },
    { question: "Какой этап создания ЛНА включает согласование?", answers: [{ text: "Утверждение документа", correct: true }, { text: "Разработка", correct: false }, { text: "Анализ", correct: false }] },
    { question: "Для чего нужны ЛНД в ИБ?", answers: [{ text: "Регулировать процессы защиты", correct: true }, { text: "Шифровать данные", correct: false }, { text: "Маршрутизировать трафик", correct: false }] },
    { question: "Какой принцип ЛНА обеспечивает их эффективность?", answers: [{ text: "Понятность и доступность", correct: true }, { text: "Сложность текста", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Кто разрабатывает ЛНА по ИБ?", answers: [{ text: "Специалисты по ИБ", correct: true }, { text: "Сотрудники", correct: false }, { text: "Поставщики", correct: false }] },

    // Модель угроз
    { question: "Какой этап разработки модели угроз включает оценку рисков?", answers: [{ text: "Анализ рисков", correct: true }, { text: "Идентификация активов", correct: false }, { text: "Реализация мер", correct: false }] },
    { question: "Что включает модель угроз?", answers: [{ text: "Потенциальные угрозы и уязвимости", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Методы шифрования", correct: false }] },
    { question: "Какой источник помогает при создании модели угроз?", answers: [{ text: "MITRE ATT&CK", correct: true }, { text: "Wireshark", correct: false }, { text: "Metasploit", correct: false }] },
    { question: "Какой принцип важен для модели угроз?", answers: [{ text: "Полнота анализа", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Ускорение сети", correct: false }] },
    { question: "Для чего нужна модель угроз в ИБ?", answers: [{ text: "Для планирования защиты", correct: true }, { text: "Для шифрования данных", correct: false }, { text: "Для маршрутизации трафика", correct: false }] },
  ],
  hard: [
    // Модель OSI
    { question: "Какой протокол на канальном уровне поддерживает LLC?", answers: [{ text: "IEEE 802.2", correct: true }, { text: "PPP", correct: false }, { text: "ARP", correct: false }] },
    { question: "Какой уровень OSI использует протокол gRPC?", answers: [{ text: "Сеансовый", correct: true }, { text: "Сетевой", correct: false }, { text: "Физический", correct: false }] },
    { question: "Какой уровень OSI использует MIDI для передачи данных?", answers: [{ text: "Уровень представления", correct: true }, { text: "Транспортный", correct: false }, { text: "Сетевой", correct: false }] },
    { question: "Что делает протокол SCTP на транспортном уровне?", answers: [{ text: "Поддерживает многопоточную передачу", correct: true }, { text: "Шифрует данные", correct: false }, { text: "Маршрутизирует пакеты", correct: false }] },
    { question: "Какой уровень модели TCP/IP использует MPLS?", answers: [{ text: "Канальный уровень", correct: true }, { text: "Интернет-уровень", correct: false }, { text: "Прикладной уровень", correct: false }] },

    // Уязвимости
    { question: "Какой метод предотвращения для API6 (Mass Assignment) из OWASP API Security исключает автоматическую привязку данных?", answers: [{ text: "Использование строгих схем валидации", correct: true }, { text: "Шифрование токенов", correct: false }, { text: "Rate Limiting", correct: false }] },
    { question: "Какой CVE связан с утечкой данных из памяти OpenSSL?", answers: [{ text: "CVE-2014-0160 (Heartbleed)", correct: true }, { text: "CVE-2017-0144 (EternalBlue)", correct: false }, { text: "CVE-2019-0708 (BlueKeep)", correct: false }] },
    { question: "Какой метод ZTA предотвращает T1003 (Credential Dumping)?", answers: [{ text: "Мониторинг аномалий через UEBA", correct: true }, { text: "Микросегментация", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какую слабость из БДУ ФСТЭК (BDU:2020-05130) устраняют безопасные функции?", answers: [{ text: "Buffer Overflow (CWE-120)", correct: true }, { text: "XSS (CWE-79)", correct: false }, { text: "Information Disclosure (CWE-200)", correct: false }] },
    { question: "Какой стандарт формализовал Zero Trust Architecture в 2020 году?", answers: [{ text: "NIST 800-207", correct: true }, { text: "ISO/IEC 27035", correct: false }, { text: "NIST SP 800-61", correct: false }] },

    // Анализ ВПО
    { question: "Какой инструмент анализа ВПО использует дизассемблирование?", answers: [{ text: "Ghidra", correct: true }, { text: "Wireshark", correct: false }, { text: "Autopsy", correct: false }] },
    { question: "Какой тип ВПО использует полиморфизм для изменения кода?", answers: [{ text: "Метаморфный вирус", correct: true }, { text: "Руткит", correct: false }, { text: "Троян", correct: false }] },
    { question: "Какой этап анализа ВПО включает мониторинг сетевой активности?", answers: [{ text: "Динамический анализ", correct: true }, { text: "Статический анализ", correct: false }, { text: "Сбор данных", correct: false }] },
    { question: "Какой инструмент анализа ВПО использует песочницу?", answers: [{ text: "Cuckoo Sandbox", correct: true }, { text: "IDA Pro", correct: false }, { text: "Nessus", correct: false }] },
    { question: "Какой тип ВПО использует шифрование для сокрытия?", answers: [{ text: "Криптор", correct: true }, { text: "Червь", correct: false }, { text: "Шпионское ПО", correct: false }] },

    // Пентестинг
    { question: "Какой инструмент пентестинга использует эксплойты для атаки?", answers: [{ text: "Metasploit", correct: true }, { text: "Burp Suite", correct: false }, { text: "Wireshark", correct: false }] },
    { question: "Какой этап пентестинга включает анализ собранных данных?", answers: [{ text: "Анализ уязвимостей", correct: true }, { text: "Эксплуатация", correct: false }, { text: "Разведка", correct: false }] },
    { question: "Какую уязвимость может выявить Burp Suite?", answers: [{ text: "CSRF (межсайтовая подделка запроса)", correct: true }, { text: "DDoS-атака", correct: false }, { text: "ARP-спуфинг", correct: false }] },
    { question: "Какой тип пентеста проверяет физическую безопасность?", answers: [{ text: "Физический пентест", correct: true }, { text: "Сетевой пентест", correct: false }, { text: "Веб-пентест", correct: false }] },
    { question: "Какой метод пентестинга использует социальную инженерию?", answers: [{ text: "Фишинговая атака", correct: true }, { text: "SQL-инъекция", correct: false }, { text: "DDoS-атака", correct: false }] },

    // Социальная инженерия
    { question: "Какой метод социальной инженерии использует поддельные звонки от техподдержки?", answers: [{ text: "Вишинг", correct: true }, { text: "Фишинг", correct: false }, { text: "Смишинг", correct: false }] },
    { question: "Какой метод защиты от социальной инженерии включает симуляции атак?", answers: [{ text: "Обучение сотрудников", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Использование VPN", correct: false }] },
    { question: "Какой тип атаки социальной инженерии нацелен на топ-менеджеров?", answers: [{ text: "Китобойный промысел", correct: true }, { text: "Фишинг", correct: false }, { text: "Смишинг", correct: false }] },
    { question: "Какой признак указывает на атаку социальной инженерии?", answers: [{ text: "Срочный запрос конфиденциальных данных", correct: true }, { text: "Официальный логотип", correct: false }, { text: "Длинный текст", correct: false }] },
    { question: "Какой метод социальной инженерии использует поддельные USB-носители?", answers: [{ text: "Baiting (приманка)", correct: true }, { text: "Фишинг", correct: false }, { text: "Вишинг", correct: false }] },

    // OSINT
    { question: "Какой инструмент OSINT автоматизирует сбор данных из сотен источников?", answers: [{ text: "SpiderFoot", correct: true }, { text: "Shodan", correct: false }, { text: "Maltego", correct: false }] },
    { question: "Какой этап атаки OSINT включает создание фишинговых писем?", answers: [{ text: "Подготовка атаки", correct: true }, { text: "Сбор информации", correct: false }, { text: "Анализ данных", correct: false }] },
    { question: "Какой метод противодействия OSINT включает использование псевдонимов?", answers: [{ text: "Минимизация утечек", correct: true }, { text: "Оценка цифрового следа", correct: false }, { text: "Мониторинг", correct: false }] },
    { question: "Какой инструмент OSINT предоставляет коллекцию ссылок?", answers: [{ text: "OSINT Framework", correct: true }, { text: "Shodan", correct: false }, { text: "Have I Been Pwned", correct: false }] },
    { question: "Какой пример OSINT-анализа связан с Bellingcat?", answers: [{ text: "Расследование военных преступлений", correct: true }, { text: "Анализ кода вируса", correct: false }, { text: "Анализ сетевого трафика", correct: false }] },

    // Форензика
    { question: "Какой инструмент форензики используется для анализа сетевого трафика?", answers: [{ text: "Wireshark", correct: true }, { text: "Autopsy", correct: false }, { text: "FTK Imager", correct: false }] },
    { question: "Какой этап форензики включает анализ дампов памяти?", answers: [{ text: "Сбор и анализ", correct: true }, { text: "Подготовка", correct: false }, { text: "Восстановление", correct: false }] },
    { question: "Какой плюс форензики помогает в судебных делах?", answers: [{ text: "Сохранение улик", correct: true }, { text: "Ускорение сети", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой минус форензики связан с антифорензикой?", answers: [{ text: "Сокрытие следов злоумышленником", correct: true }, { text: "Низкая точность", correct: false }, { text: "Отсутствие инструментов", correct: false }] },
    { question: "Какой инструмент форензики используется для анализа логов?", answers: [{ text: "Volatility", correct: true }, { text: "Wireshark", correct: false }, { text: "Metasploit", correct: false }] },

    // Построение сетей
    { question: "Какой протокол маршрутизации использует атрибуты AS Path?", answers: [{ text: "BGP", correct: true }, { text: "OSPF", correct: false }, { text: "RIP", correct: false }] },
    { question: "Какую технологию использует VXLAN для оверлей-сетей?", answers: [{ text: "Инкапсуляцию кадров в UDP", correct: true }, { text: "Шифрование с IPsec", correct: false }, { text: "Метки MPLS", correct: false }] },
    { question: "Какой протокол Cisco объединяет порты на разных коммутаторах?", answers: [{ text: "VPC", correct: true }, { text: "LACP", correct: false }, { text: "HSRP", correct: false }] },
    { question: "Какую функцию выполняет MPLS в сетях провайдеров?", answers: [{ text: "Маршрутизацию на основе меток", correct: true }, { text: "Синхронизацию времени", correct: false }, { text: "Обнаружение устройств", correct: false }] },
    { question: "Какой уровень модели Purdue отвечает за SCADA-системы?", answers: [{ text: "Уровень 2", correct: true }, { text: "Уровень 0", correct: false }, { text: "Уровень 4", correct: false }] },

    // Криптография
    { question: "Какой алгоритм PQC основан на решётках?", answers: [{ text: "CRYSTALS-Kyber", correct: true }, { text: "SPHINCS+", correct: false }, { text: "FALCON", correct: false }] },
    { question: "Что такое BB84 в квантовом шифровании?", answers: [{ text: "Протокол QKD", correct: true }, { text: "Алгоритм шифрования", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Какой алгоритм использует эллиптические кривые?", answers: [{ text: "ECDSA", correct: true }, { text: "RSA", correct: false }, { text: "AES", correct: false }] },
    { question: "Что такое ГОСТ 28147-89?", answers: [{ text: "Российский блочный шифр", correct: true }, { text: "Асимметричный алгоритм", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Какой алгоритм подписи устойчив к квантовым атакам?", answers: [{ text: "SPHINCS+", correct: true }, { text: "RSA", correct: false }, { text: "ECDSA", correct: false }] },

    // ЭП и PKI
    { question: "Что такое OCSP Stapling?", answers: [{ text: "Ускорение проверки сертификата", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Сетевой протокол", correct: false }] },
    { question: "Какой формат запроса сертификата используется в PKI?", answers: [{ text: "PKCS #10", correct: true }, { text: "PKCS #7", correct: false }, { text: "X.509", correct: false }] },
    { question: "Что такое Certificate Transparency?", answers: [{ text: "Мониторинг сертификатов", correct: true }, { text: "Протокол шифрования", correct: false }, { text: "Сетевой стандарт", correct: false }] },
    { question: "Какую угрозу для ЭП представляет слабый алгоритм хэширования?", answers: [{ text: "Коллизии хэша", correct: true }, { text: "Ускорение сети", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой уровень Оранжевой книги требует формальной верификации?", answers: [{ text: "A1", correct: true }, { text: "B2", correct: false }, { text: "C1", correct: false }] },

    // Инструменты ИБ
    { question: "Какой инструмент использует аппаратное шифрование для защиты ключей?", answers: [{ text: "HSM", correct: true }, { text: "Encryption Tools", correct: false }, { text: "PAM", correct: false }] },
    { question: "Какой метод защиты применяет WAF против известных уязвимостей?", answers: [{ text: "Виртуальные патчи", correct: true }, { text: "Шифрование трафика", correct: false }, { text: "Белые списки", correct: false }] },
    { question: "Что включает XDR помимо данных EDR?", answers: [{ text: "Данные NDR и облачных систем", correct: true }, { text: "Только сетевой трафик", correct: false }, { text: "Только логи SIEM", correct: false }] },
    { question: "Какой тип анализа использует Network Traffic Analysis для обнаружения C2-трафика?", answers: [{ text: "Машинное обучение и поведенческий", correct: true }, { text: "Только сигнатурный", correct: false }, { text: "Только аномальный", correct: false }] },
    { question: "Какой инструмент управляет мобильными устройствами в корпоративной сети?", answers: [{ text: "MDM", correct: true }, { text: "NAC", correct: false }, { text: "SASE", correct: false }] },
    // Защита структур
    { question: "Какой приказ ФСТЭК регулирует безопасность КИИ?", answers: [{ text: "Приказ № 239", correct: true }, { text: "Приказ № 31", correct: false }, { text: "Приказ № 17", correct: false }] },
    { question: "Что такое ПЭМИН и как от него защищаться?", answers: [{ text: "Побочные излучения; экранирование помещений", correct: true }, { text: "Перехват трафика; шифрование TLS", correct: false }, { text: "Фишинг; обучение персонала", correct: false }] },
    { question: "Какой уровень модели Purdue отвечает за SCADA?", answers: [{ text: "Уровень 2", correct: true }, { text: "Уровень 0", correct: false }, { text: "Уровень 4", correct: false }] },
    { question: "Какой метод защиты от утечек через USB-носители?", answers: [{ text: "DLP-системы", correct: true }, { text: "Шумогенераторы", correct: false }, { text: "IPsec", correct: false }] },
    { question: "Какой стандарт регулирует защиту АСУТП?", answers: [{ text: "ISO/IEC 62443", correct: true }, { text: "GDPR", correct: false }, { text: "ISO 27001", correct: false }] },

    // Правовые нормы
    { question: "Какой приказ ФСБ регулирует госСОПКА?", answers: [{ text: "Приказ № 281", correct: true }, { text: "Приказ № 66", correct: false }, { text: "Приказ № 17", correct: false }] },
    { question: "Какой стандарт регулирует защиту АСУТП?", answers: [{ text: "ISO/IEC 62443", correct: true }, { text: "GDPR", correct: false }, { text: "ISO 27001", correct: false }] },
    { question: "Какой российский стандарт регулирует аттестацию объектов?", answers: [{ text: "ГОСТ Р 56397-2015", correct: true }, { text: "ГОСТ Р ИСО/МЭК 62443", correct: false }, { text: "ФЗ-149", correct: false }] },
    { question: "Какой закон РФ требует лицензирование защиты информации?", answers: [{ text: "ПП РФ № 79", correct: true }, { text: "ФЗ-149", correct: false }, { text: "ФЗ-63", correct: false }] },
    { question: "Что такое НКЦКИ?", answers: [{ text: "Национальный центр по инцидентам", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Программное обеспечение", correct: false }] },

    // ЛНА и ЛНД
    { question: "Какой этап создания ЛНА включает анализ рисков?", answers: [{ text: "Разработка", correct: true }, { text: "Утверждение", correct: false }, { text: "Внедрение", correct: false }] },
    { question: "Какой документ ЛНА регулирует доступ к данным?", answers: [{ text: "Политика управления доступом", correct: true }, { text: "Сетевой протокол", correct: false }, { text: "Метод шифрования", correct: false }] },
    { question: "Какой принцип ЛНА обеспечивает их актуальность?", answers: [{ text: "Регулярное обновление", correct: true }, { text: "Сложность текста", correct: false }, { text: "Шифрование данных", correct: false }] },
    { question: "Какой этап внедрения ЛНД включает обучение сотрудников?", answers: [{ text: "Внедрение", correct: true }, { text: "Разработка", correct: false }, { text: "Анализ", correct: false }] },
    { question: "Для чего ЛНА по ИБ должны быть согласованы?", answers: [{ text: "Для соответствия законодательству", correct: true }, { text: "Для шифрования данных", correct: false }, { text: "Для маршрутизации трафика", correct: false }] },

    // Модель угроз
    { question: "Какой подход использует STRIDE для выявления угроз?", answers: [{ text: "Threat Modeling", correct: true }, { text: "Анализ рисков", correct: false }, { text: "Пентест", correct: false }] },
    { question: "Какой этап разработки модели угроз включает выбор мер защиты?", answers: [{ text: "Реализация мер", correct: true }, { text: "Анализ рисков", correct: false }, { text: "Идентификация активов", correct: false }] },
    { question: "Какой источник данных используется для модели угроз?", answers: [{ text: "БДУ ФСТЭК", correct: true }, { text: "Wireshark", correct: false }, { text: "Metasploit", correct: false }] },
    { question: "Какой принцип модели угроз учитывает новые угрозы?", answers: [{ text: "Динамичность", correct: true }, { text: "Шифрование данных", correct: false }, { text: "Ускорение сети", correct: false }] },
    { question: "Какой элемент модели угроз описывает злоумышленника?", answers: [{ text: "Модель нарушителя", correct: true }, { text: "Сетевые протоколы", correct: false }, { text: "Методы шифрования", correct: false }] },
  ]
};

function getRandomQuestions(level) {
  const allQuestions = questions[level];
  const shuffledQuestions = shuffleArray([...allQuestions]);
  const selectedQuestions = shuffledQuestions.slice(0, 30);

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
    setTimeout(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
      const contentArea = document.getElementById('content');
      if (contentArea) {
        contentArea.scrollTop = 0;
      }
    }, 0);
  });
}

function loadResultsContent(container, answers) {
  const correctCount = answers.filter(a => a.isCorrect).length;

  let html = `
    <div class="results-container">
      <button class="abort-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        На главную
      </button>
      <h1>Результаты теста</h1>
      <p>Правильных ответов: ${correctCount} из ${answers.length}</p>
      <div class="question-nav">
        <div class="nav-row">
  `;

  for (let i = 0; i < 15 && i < answers.length; i++) {
    html += `
      <a href="#q${i}" class="nav-item ${answers[i].isCorrect ? 'correct' : 'incorrect'}">${i + 1}</a>
    `;
  }

  html += `
        </div>
        <div class="nav-row">
  `;

  for (let i = 15; i < 30 && i < answers.length; i++) {
    html += `
      <a href="#q${i}" class="nav-item ${answers[i].isCorrect ? 'correct' : 'incorrect'}">${i + 1}</a>
    `;
  }

  html += `
        </div>
      </div>
      <h2>Ваши ответы:</h2>
  `;

  answers.forEach((a, index) => {
    html += `
      <div class="result-item" id="q${index}">
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

  requestAnimationFrame(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    const contentArea = document.getElementById('content');
    if (contentArea) {
      contentArea.scrollTop = 0;
    }
  });

  document.querySelector('.abort-btn').addEventListener('click', () => {
    loadTrainingContent(container);
  });

  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = item.getAttribute('href').substring(1);
      const targetElement = document.getElementById(targetId);
      if (targetElement) {
        targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  document.querySelector('.back-to-main-btn').addEventListener('click', () => {
    loadTrainingContent(container);
  });
}
