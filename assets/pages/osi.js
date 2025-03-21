function loadOsiContent(contentArea) {
  const initialContent = `
    <div class="osi-container">
      <h1>Модель OSI</h1>
      <div class="osi-description">
        <p><strong>Модель OSI</strong> (Open Systems Interconnection) — это концептуальная модель, разработанная Международной организацией по стандартизации (ISO) для стандартизации сетевых взаимодействий. Она делит процесс передачи данных на семь уровней, каждый из которых выполняет определённые функции. Модель OSI была создана в 1970-х годах с целью упрощения разработки, внедрения и эксплуатации сетевых систем, а также обеспечения совместимости между различными технологиями.</p>
        <p>Основная цель модели OSI — предоставить универсальный шаблон для понимания и проектирования сетей. Она помогает разработчикам и инженерам разделять сложные сетевые процессы на более простые и управляемые части. Каждый уровень модели взаимодействует с соседними уровнями, передавая данные вниз (при отправке) или вверх (при получении), а также использует определённые протоколы и стандарты.</p>
        <p>Модель OSI состоит из следующих уровней:</p>
        <ul>
          <li><strong>Физический уровень (Physical Layer):</strong> отвечает за передачу необработанных битов через физическую среду (кабели, оптоволокно, радиоволны).</li>
          <li><strong>Канальный уровень (Data Link Layer):</strong> обеспечивает передачу данных между соседними узлами и управление доступом к среде (например, Ethernet).</li>
          <li><strong>Сетевой уровень (Network Layer):</strong> управляет маршрутизацией и логической адресацией (например, IP).</li>
          <li><strong>Транспортный уровень (Transport Layer):</strong> обеспечивает надёжную передачу данных (например, TCP, UDP).</li>
          <li><strong>Сеансовый уровень (Session Layer):</strong> управляет сеансами связи между приложениями.</li>
          <li><strong>Уровень представления (Presentation Layer):</strong> отвечает за преобразование данных, шифрование и сжатие.</li>
          <li><strong>Прикладной уровень (Application Layer):</strong> предоставляет интерфейс для взаимодействия пользователя с сетью (например, HTTP, FTP).</li>
        </ul>
        <p>Модель OSI широко используется в обучении и проектировании сетей, так как она помогает понять, как различные технологии и протоколы взаимодействуют друг с другом. Хотя в реальной жизни чаще применяется модель TCP/IP, модель OSI остаётся важным теоретическим инструментом для анализа и стандартизации сетевых процессов.</p>
      </div>
      <div class="osi-buttons">
        <button class="osi-btn" id="faq-btn">Частые вопросы</button>
        <button class="osi-btn" id="model-btn">Модель</button>
      </div>
    </div>
  `;
  contentArea.innerHTML = initialContent;

  document.getElementById('faq-btn').addEventListener('click', () => {
    loadFaqContent(contentArea);
  });

  document.getElementById('model-btn').addEventListener('click', () => {
    loadModelContent(contentArea);
  });
}

function loadFaqContent(contentArea) {
  const faqContent = `
    <div class="osi-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Частые вопросы по модели OSI</h1>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Вопрос</th>
              <th>Ответ</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>На каком уровне модели OSI работает коммутатор?</td>
              <td>2-й уровень (канальный уровень)</td>
            </tr>
            <tr>
              <td>Сколько пакетов требуется для доставки UDP?</td>
              <td>Один пакет</td>
            </tr>
            <tr>
              <td>Сколько пакетов требуется для установки TCP соединения?</td>
              <td>Три пакета</td>
            </tr>
            <tr>
              <td>Какие семь уровней включает модель OSI?</td>
              <td>Прикладной, Представления, Сеансовый, Транспортный, Сетевой, Канальный, Физический</td>
            </tr>
            <tr>
              <td>Какова функция сетевого уровня?</td>
              <td>Маршрутизация и логическая адресация</td>
            </tr>
            <tr>
              <td>Какой протокол на транспортном уровне обеспечивает надежную передачу данных?</td>
              <td>TCP</td>
            </tr>
            <tr>
              <td>В чем разница между TCP и UDP?</td>
              <td>TCP — с установлением соединения, надежный; UDP — бессоединный, ненадежный</td>
            </tr>
            <tr>
              <td>Какой уровень отвечает за физическую адресацию?</td>
              <td>Канальный уровень</td>
            </tr>
            <tr>
              <td>Какое устройство работает на сетевом уровне?</td>
              <td>Маршрутизатор</td>
            </tr>
            <tr>
              <td>Какова цель уровня представления?</td>
              <td>Представление данных, шифрование, сжатие</td>
            </tr>
            <tr>
              <td>Какова роль сеансового уровня?</td>
              <td>Управление сеансами между приложениями</td>
            </tr>
            <tr>
              <td>В чем основное отличие модели OSI от модели TCP/IP?</td>
              <td>OSI имеет семь уровней, TCP/IP — четыре; OSI теоретическая, TCP/IP практическая</td>
            </tr>
            <tr>
              <td>Какой уровень отвечает за шифрование и расшифровку данных?</td>
              <td>Уровень представления</td>
            </tr>
            <tr>
              <td>Какова роль физического уровня?</td>
              <td>Обеспечение физического соединения и передачи сырых битов</td>
            </tr>
            <tr>
              <td>Что такое MAC-адрес, и на каком уровне он используется?</td>
              <td>Физический адрес, используется на канальном уровне</td>
            </tr>
            <tr>
              <td>Какова функция транспортного уровня?</td>
              <td>Обеспечение связи конец-точка, сегментация, надежность (для TCP)</td>
            </tr>
            <tr>
              <td>Какова цель сеансового уровня?</td>
              <td>Управление сеансами между приложениями</td>
            </tr>
            <tr>
              <td>Какой уровень отвечает за маршрутизацию?</td>
              <td>Сетевой уровень</td>
            </tr>
            <tr>
              <td>В чем разница между хабом и коммутатором?</td>
              <td>Хаб (1-й уровень) рассылает данные всем портам; коммутатор (2-й уровень) пересылает по MAC-адресам</td>
            </tr>
            <tr>
              <td>Какова роль маршрутизатора?</td>
              <td>Маршрутизация данных между сетями на основе IP-адресов (3-й уровень)</td>
            </tr>
            <tr>
              <td>Какова функция прикладного уровня?</td>
              <td>Предоставление сетевых услуг конечным пользовательским приложениям</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="faq-additional">
        <h2>Сравнение ключевых протоколов</h2>
        <ul>
          <li><strong>HTTP и HTTPS:</strong> HTTPS отличается от HTTP использованием шифрования SSL/TLS, что обеспечивает безопасность передаваемых данных.</li>
          <li><strong>TCP и UDP:</strong> TCP гарантирует надежную доставку данных, но работает медленнее из-за подтверждений; UDP быстрее, но не обеспечивает гарантии доставки.</li>
          <li><strong>IPv4 и IPv6:</strong> IPv4 использует 32-битные адреса (4.3 миллиарда), тогда как IPv6 — 128-битные, что позволяет поддерживать значительно большее количество устройств.</li>
          <li><strong>ARP:</strong> Этот протокол работает только в пределах локальной сети (LAN) и связывает IP-адреса с MAC-адресами.</li>
          <li><strong>ICMP:</strong> Используется исключительно для диагностики (например, команда ping), а не для передачи данных.</li>
        </ul>

        <h2>Часто задаваемые вопросы о протоколах</h2>
        <ul>
          <li><strong>Какую роль выполняет DNS?</strong> Преобразует доменные имена (например, google.com) в IP-адреса.</li>
          <li><strong>В чем разница между FTP и HTTP?</strong> FTP предназначен для передачи файлов, а HTTP — для загрузки веб-страниц.</li>
          <li><strong>Для чего нужен ARP?</strong> Связывает IP-адреса с физическими (MAC) адресами в локальной сети.</li>
          <li><strong>Когда стоит выбрать UDP вместо TCP?</strong> UDP предпочтителен для задач, где важна скорость, а потеря данных не критична, например, в стриминге или онлайн-играх.</li>
        </ul>

        <h2>Полезные рекомендации</h2>
        <ul>
          <li>Часто используемые связки протоколов: HTTP с TCP, DNS с UDP, FTP с TCP.</li>
          <li>Для защиты данных применяются SSL/TLS (на уровне представления) и IPsec (на сетевом уровне).</li>
          <li>Протоколы AppleTalk и NetBIOS устарели, но иногда упоминаются в историческом контексте.</li>
        </ul>
      </div>
    </div>
  `;
  contentArea.innerHTML = faqContent;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadOsiContent(contentArea);
  });
}

function loadModelContent(contentArea) {
  const modelContent = `
    <div class="osi-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Модель OSI</h1>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Номер</th>
              <th>Уровень</th>
              <th>Протокол</th>
              <th>Назначение</th>
              <th>Особенности</th>
              <th>Примеры использования</th>
            </tr>
          </thead>
          <tbody>
            <!-- Уровень 7: Прикладной (Application) -->
            <tr class="layer-7">
              <td rowspan="8">7</td>
              <td rowspan="8">Прикладной<br>(Application)</td>
              <td>HTTP</td>
              <td>Передача гипертекста (веб-страниц).</td>
              <td>Работает поверх TCP, используется для взаимодействия с веб-сайтами.</td>
              <td>Просмотр веб-страниц (например, через браузер).</td>
            </tr>
            <tr>
              <td>HTTPS</td>
              <td>Защищённая версия HTTP с шифрованием (SSL/TLS).</td>
              <td>Обеспечивает безопасность данных (например, паролей).</td>
              <td>Безопасные транзакции (онлайн-банкинг).</td>
            </tr>
            <tr>
              <td>FTP</td>
              <td>Передача файлов между хостами.</td>
              <td>Поддерживает команды для загрузки/скачивания файлов.</td>
              <td>Передача файлов на сервер (например, для веб-хостинга).</td>
            </tr>
            <tr>
              <td>SMTP</td>
              <td>Отправка электронной почты.</td>
              <td>Используется почтовыми серверами для отправки писем.</td>
              <td>Отправка email через почтовый клиент.</td>
            </tr>
            <tr>
              <td>POP3</td>
              <td>Получение электронной почты.</td>
              <td>Скачивает письма с сервера на устройство.</td>
              <td>Получение писем в почтовом клиенте (например, Outlook).</td>
            </tr>
            <tr>
              <td>IMAP</td>
              <td>Получение и синхронизация электронной почты.</td>
              <td>Позволяет работать с письмами на сервере без скачивания.</td>
              <td>Синхронизация почты между устройствами.</td>
            </tr>
            <tr>
              <td>DNS</td>
              <td>Преобразование доменных имен в IP-адреса.</td>
              <td>Работает как "телефонная книга" интернета.</td>
              <td>Запрос IP-адреса для сайта (например, google.com).</td>
            </tr>
            <tr>
              <td>WebSocket</td>
              <td>Двусторонняя связь между клиентом и сервером в реальном времени.</td>
              <td>Поддерживает постоянное соединение для чатов, игр.</td>
              <td>Онлайн-чаты, стриминговые платформы.</td>
            </tr>
            <!-- Уровень 6: Представления (Presentation) -->
            <tr class="layer-6">
              <td rowspan="5">6</td>
              <td rowspan="5">Уровень представления<br>(Presentation)</td>
              <td>SSL/TLS</td>
              <td>Шифрование данных для безопасной передачи.</td>
              <td>Обеспечивает конфиденциальность и целостность данных.</td>
              <td>HTTPS-соединения, VPN.</td>
            </tr>
            <tr>
              <td>ASCII</td>
              <td>Кодирование текста в двоичный формат.</td>
              <td>Стандарт для представления символов (например, букв, цифр).</td>
              <td>Текстовые файлы, веб-страницы.</td>
            </tr>
            <tr>
              <td>EBCDIC</td>
              <td>Кодирование текста (альтернатива ASCII, используется в мейнфреймах IBM).</td>
              <td>Применяется в корпоративных системах.</td>
              <td>Системы IBM.</td>
            </tr>
            <tr>
              <td>JPEG</td>
              <td>Сжатие изображений.</td>
              <td>Сжимает изображения с потерями для экономии места.</td>
              <td>Хранение и передача фотографий.</td>
            </tr>
            <tr>
              <td>MIDI</td>
              <td>Формат для передачи музыкальных данных.</td>
              <td>Используется для передачи нот и команд музыкальных инструментов.</td>
              <td>Синтезаторы, музыкальное ПО.</td>
            </tr>
            <!-- Уровень 5: Сеансовый (Session) -->
            <tr class="layer-5">
              <td rowspan="4">5</td>
              <td rowspan="4">Сеансовый<br>(Session)</td>
              <td>RPC</td>
              <td>Удалённый вызов процедур (вызов функций на другом устройстве).</td>
              <td>Позволяет программам взаимодействовать через сеть.</td>
              <td>Распределённые системы, сервер-клиент взаимодействие.</td>
            </tr>
            <tr>
              <td>L2TP</td>
              <td>Туннелирование на канальном уровне (для VPN).</td>
              <td>Часто используется с IPsec для шифрования.</td>
              <td>VPN-соединения.</td>
            </tr>
            <tr>
              <td>NetBIOS</td>
              <td>Обеспечение сеансов для взаимодействия приложений в локальной сети.</td>
              <td>Используется в старых системах Windows для обмена данными.</td>
              <td>Обмен файлами в локальной сети (Windows).</td>
            </tr>
            <tr>
              <td>gRPC</td>
              <td>Современный протокол удалённого вызова процедур.</td>
              <td>Высокопроизводительный, используется в микросервисах.</td>
              <td>Микросервисные архитектуры (например, в Google).</td>
            </tr>
            <!-- Уровень 4: Транспортный (Transport) -->
            <tr class="layer-4">
              <td rowspan="4">4</td>
              <td rowspan="4">Транспортный<br>(Transport)</td>
              <td>TCP</td>
              <td>Надёжная передача данных с установлением соединения.</td>
              <td>Гарантирует доставку, контроль ошибок, управление потоком.</td>
              <td>Веб-сайты (HTTP/HTTPS), передача файлов (FTP).</td>
            </tr>
            <tr>
              <td>UDP</td>
              <td>Быстрая передача данных без установления соединения.</td>
              <td>Нет гарантии доставки, но быстрее TCP (меньше накладных расходов).</td>
              <td>Стриминг, онлайн-игры, DNS-запросы.</td>
            </tr>
            <tr>
              <td>SCTP</td>
              <td>Комбинация преимуществ TCP и UDP (надёжность + мультикаст).</td>
              <td>Поддерживает многопотоковую передачу данных.</td>
              <td>Телекоммуникации (например, в сетях 4G/5G).</td>
            </tr>
            <tr>
              <td>DCCP</td>
              <td>Передача данных с управлением перегрузки, но без гарантии доставки.</td>
              <td>Используется для мультимедиа, где важна скорость.</td>
              <td>Видеостриминг, VoIP.</td>
            </tr>
            <!-- Уровень 3: Сетевой (Network) -->
            <tr class="layer-3">
              <td rowspan="5">3</td>
              <td rowspan="5">Сетевой<br>(Network)</td>
              <td>IPv4</td>
              <td>Логическая адресация (32-битные IP-адреса).</td>
              <td>Основной протокол интернета, но адреса заканчиваются.</td>
              <td>Большинство сетей (например, 192.168.1.1).</td>
            </tr>
            <tr>
              <td>IPv6</td>
              <td>Логическая адресация (128-битные IP-адреса).</td>
              <td>Решает проблему нехватки адресов IPv4, поддерживает новые функции (например, мультикаст).</td>
              <td>Современные сети, IoT-устройства.</td>
            </tr>
            <tr>
              <td>IPsec</td>
              <td>Защита данных на сетевом уровне (шифрование, аутентификация).</td>
              <td>Используется для VPN и безопасной передачи данных.</td>
              <td>VPN, защищённые корпоративные сети.</td>
            </tr>
            <tr>
              <td>ICMP</td>
              <td>Диагностика сети (сообщения об ошибках).</td>
              <td>Используется для проверки доступности (например, команда ping).</td>
              <td>Диагностика (ping, traceroute).</td>
            </tr>
            <tr>
              <td>AppleTalk</td>
              <td>Протокол для сетей Apple (устаревший).</td>
              <td>Использовался в старых системах Apple для сетевого взаимодействия.</td>
              <td>Старые сети Apple (до 2000-х).</td>
            </tr>
            <!-- Уровень 2: Канальный (Data Link) -->
            <tr class="layer-2">
              <td rowspan="5">2</td>
              <td rowspan="5">Канальный<br>(Data Link)</td>
              <td>Ethernet</td>
              <td>Передача данных в локальных сетях (LAN).</td>
              <td>Основной стандарт для проводных локальных сетей (IEEE 802.3).</td>
              <td>Локальные сети в офисах, домах.</td>
            </tr>
            <tr>
              <td>PPP</td>
              <td>Установление соединения точка-точка.</td>
              <td>Используется для прямых соединений (например, через модем).</td>
              <td>DSL-соединения, старые интернет-подключения.</td>
            </tr>
            <tr>
              <td>IEEE 802.2</td>
              <td>Поддержка LLC (управление логическим каналом).</td>
              <td>Обеспечивает управление потоком и обработку ошибок на канальном уровне.</td>
              <td>Локальные сети (Ethernet).</td>
            </tr>
            <tr>
              <td>ARP</td>
              <td>Связывание IP-адресов с MAC-адресами.</td>
              <td>Необходим для маршрутизации в локальной сети.</td>
              <td>Обнаружение устройств в одной сети.</td>
            </tr>
            <tr>
              <td>DSL</td>
              <td>Передача данных через телефонные линии.</td>
              <td>Используется для широкополосного интернета.</td>
              <td>Домашний интернет (ADSL).</td>
            </tr>
            <!-- Уровень 1: Физический (Physical) -->
            <tr class="layer-1">
              <td rowspan="3">1</td>
              <td rowspan="3">Физический<br>(Physical)</td>
              <td>USB</td>
              <td>Передача данных через физическое соединение (кабель USB).</td>
              <td>Стандарт для подключения периферийных устройств.</td>
              <td>Подключение мыши, клавиатуры, флешки.</td>
            </tr>
            <tr>
              <td>RJ45</td>
              <td>Стандарт для Ethernet-кабелей (витая пара).</td>
              <td>Используется для проводного подключения к сети.</td>
              <td>Подключение компьютера к роутеру.</td>
            </tr>
            <tr>
              <td>Оптоволокно</td>
              <td>Передача данных через световые сигналы.</td>
              <td>Высокая скорость и дальность передачи.</td>
              <td>Магистральные сети, интернет-провайдеры.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `;
  contentArea.innerHTML = modelContent;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadOsiContent(contentArea);
  });
}