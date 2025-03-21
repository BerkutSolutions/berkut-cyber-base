function loadCryptographyContent(container) {
    container.innerHTML = `
      <div class="cryptography-container">
        <h1>Криптография</h1>
        <p>Криптография — это наука о методах защиты информации с использованием математических алгоритмов. Она обеспечивает конфиденциальность, целостность, аутентификацию и неподделываемость данных. В этом разделе рассматриваются основные криптографические алгоритмы, методы управления ключами и современные подходы к шифрованию.</p>
  
        <!-- Аккордеон для таблиц -->
        <div class="accordion">
          <!-- Криптографические алгоритмы -->
          <div class="accordion-item">
            <button class="accordion-header">Криптографические алгоритмы</button>
            <div class="accordion-content">
              <div class="osi-table-container">
                <table class="osi-table">
                  <thead>
                    <tr>
                      <th>Алгоритм</th>
                      <th>Тип</th>
                      <th>Описание</th>
                      <th>Пример использования</th>
                      <th>Рекомендации</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Blowfish</td>
                      <td>Симметричный</td>
                      <td>Блочный шифр с длиной ключа до 448 бит, разработанный Брюсом Шнайером в 1993 году.</td>
                      <td>Шифрование данных в устаревших системах (например, в OpenSSL).</td>
                      <td>Использовать с длиной ключа 128+ бит, но предпочтительнее AES из-за скорости и стандартизации.</td>
                    </tr>
                    <tr>
                      <td>Twofish</td>
                      <td>Симметричный</td>
                      <td>Блочный шифр, преемник Blowfish, с длиной ключа до 256 бит, финалист конкурса AES.</td>
                      <td>Шифрование данных в некоторых VPN (например, OpenVPN).</td>
                      <td>Подходит для высокопроизводительных систем, но AES более распространён.</td>
                    </tr>
                    <tr>
                      <td>ГОСТ 28147-89</td>
                      <td>Симметричный</td>
                      <td>Российский стандарт блочного шифрования, использует 256-битный ключ и 64-битные блоки.</td>
                      <td>Шифрование в российских системах (например, в ГИС).</td>
                      <td>Использовать в соответствии с требованиями ФСБ, обеспечить безопасность ключей.</td>
                    </tr>
                    <tr>
                      <td>ElGamal</td>
                      <td>Асимметричный</td>
                      <td>Алгоритм шифрования и подписи, основанный на проблеме дискретного логарифма.</td>
                      <td>Шифрование сообщений в некоторых системах (например, GnuPG).</td>
                      <td>Использовать с длиной ключа 2048+ бит, но предпочтительнее ECDSA для подписи.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
  
          <!-- Управление ключами -->
          <div class="accordion-item">
            <button class="accordion-header">Управление ключами</button>
            <div class="accordion-content">
              <div class="osi-table-container">
                <table class="osi-table">
                  <thead>
                    <tr>
                      <th>Метод</th>
                      <th>Описание</th>
                      <th>Пример</th>
                      <th>Проблемы</th>
                      <th>Рекомендации</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Генерация ключей</td>
                      <td>Создание криптографических ключей с использованием генераторов случайных чисел.</td>
                      <td>Генерация ключей в OpenSSL (openssl genrsa).</td>
                      <td>Недостаточная энтропия может привести к предсказуемым ключам.</td>
                      <td>Использовать сертифицированные PRNG (например, /dev/urandom), HSM для генерации.</td>
                    </tr>
                    <tr>
                      <td>Хранение ключей</td>
                      <td>Безопасное хранение ключей для предотвращения утечек.</td>
                      <td>Хранение ключей в HSM (например, YubiHSM).</td>
                      <td>Утечка ключей из-за небезопасного хранения (например, в файлах).</td>
                      <td>Использовать HSM или TPM, шифровать ключи при хранении.</td>
                    </tr>
                    <tr>
                      <td>Обновление ключей</td>
                      <td>Периодическая замена ключей для снижения риска компрометации.</td>
                      <td>Обновление ключей в TLS-сертификатах каждые 90 дней (Let’s Encrypt).</td>
                      <td>Ошибки при обновлении могут привести к простоям.</td>
                      <td>Автоматизировать обновление (например, через ACME), тестировать процесс.</td>
                    </tr>
                    <tr>
                      <td>Распределение ключей</td>
                      <td>Безопасная передача ключей между сторонами.</td>
                      <td>Использование Diffie-Hellman для обмена ключами в TLS.</td>
                      <td>Перехват ключей при передаче по незащищённым каналам.</td>
                      <td>Использовать защищённые протоколы (TLS), применять QKD для высокой безопасности.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
  
        <!-- Кнопки для перехода к подстраницам -->
        <div class="cryptography-buttons">
          <button class="network-btn" id="algorithms-standards-btn">Алгоритмы и стандарты</button>
          <button class="network-btn" id="aes-encryption-btn">AES-шифрование</button>
          <button class="network-btn" id="quantum-encryption-btn">Квантовое шифрование</button>
        </div>
  
        <!-- Дополнительная информация -->
        <h2>Дополнительная информация</h2>
        <h3>Гомоморфное шифрование</h3>
        <p>Гомоморфное шифрование — это современный подход, который позволяет выполнять вычисления над зашифрованными данными без их расшифровки. Это особенно полезно для облачных вычислений, где данные нужно обрабатывать, не раскрывая их содержимое.</p>
        <ul>
          <li><strong>Принцип работы:</strong> Данные шифруются с использованием гомоморфного алгоритма (например, Paillier, Gentry). Сервер выполняет вычисления (например, сложение или умножение) над зашифрованными данными, а результат остаётся зашифрованным. После расшифровки клиент получает правильный результат.</li>
          <li><strong>Пример:</strong> В 2023 году Microsoft внедрила гомоморфное шифрование в Azure для обработки медицинских данных, позволяя анализировать зашифрованные данные пациентов без нарушения конфиденциальности.</li>
          <li><strong>Типы:</strong>
            <ul>
              <li>Частично гомоморфное (PHE): Поддерживает только одну операцию (например, сложение в Paillier).</li>
              <li>Некоторое гомоморфное (SHE): Поддерживает ограниченное число операций.</li>
              <li>Полностью гомоморфное (FHE): Поддерживает любые вычисления (например, Gentry’s FHE).</li>
            </ul>
          </li>
          <li><strong>Проблемы:</strong> Высокая вычислительная сложность и низкая производительность. FHE пока слишком медленно для массового применения.</li>
          <li><strong>Перспективы:</strong> Ожидается, что к 2030 году гомоморфное шифрование станет стандартом для защиты данных в облаке, особенно в здравоохранении и финансах.</li>
        </ul>
  
        <h3>История криптографии</h3>
        <p>Криптография имеет долгую историю, начиная с древних времён:</p>
        <ul>
          <li><strong>Древний мир:</strong> Шифр Цезаря (I век до н.э.) — простой шифр замены, где каждая буква сдвигается на фиксированное число позиций в алфавите.</li>
          <li><strong>Средние века:</strong> Арабский математик Аль-Кинди в IX веке разработал метод частотного анализа для взлома шифров замены.</li>
          <li><strong>XX век:</strong> Во время Второй мировой войны использовались машины шифрования, такие как Enigma (Германия). Союзники взломали Enigma с помощью Алана Тьюринга, что стало важным шагом в развитии криптоанализа.</li>
          <li><strong>Современность:</strong> Развитие симметричных (DES, AES) и асимметричных (RSA, Diffie-Hellman) алгоритмов, а также появление квантовой криптографии.</li>
        </ul>
      </div>
    `;
  
    document.querySelectorAll('.accordion-header').forEach(header => {
      header.addEventListener('click', () => {
        const content = header.nextElementSibling;
        const isOpen = content.style.display === 'block';
        document.querySelectorAll('.accordion-content').forEach(item => {
          item.style.display = 'none';
        });
        content.style.display = isOpen ? 'none' : 'block';
      });
    });
  
    document.getElementById('algorithms-standards-btn').addEventListener('click', () => {
      loadAlgorithmsStandardsContent(container);
    });
  
    document.getElementById('aes-encryption-btn').addEventListener('click', () => {
      loadAesEncryptionContent(container);
    });
  
    document.getElementById('quantum-encryption-btn').addEventListener('click', () => {
      loadQuantumEncryptionContent(container);
    });
  }
  
  function loadAlgorithmsStandardsContent(container) {
    container.innerHTML = `
      <div class="cryptography-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Алгоритмы и стандарты</h1>
        <h2>Алгоритмы и стандарты шифрования</h2>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Алгоритм/Стандарт</th>
                <th>Описание</th>
                <th>Особенности</th>
                <th>Пример использования</th>
                <th>Рекомендации</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>RSA</td>
                <td>Асимметричный алгоритм, основанный на сложности факторизации больших чисел.</td>
                <td>Используется для шифрования и подписи ключей 2048+ бит для безопасности (более эффективен, чем RSA).</td>
                <td>Подпись в SSL-сертификатах.</td>
                <td>Использовать ключи 2048+ бит, избегать устаревших длин ключей (1024 бит).</td>
              </tr>
              <tr>
                <td>ECDSA (Elliptic Curve Digital Signature Algorithm)</td>
                <td>Асимметричный алгоритм на основе эллиптических кривых.</td>
                <td>Меньше длина ключа 256 бит эквивалентна 3072 бит RSA.</td>
                <td>Подпись в сертификатах (например, TLS 1.3).</td>
                <td>Использовать кривые NIST P-256 или выше, избегать устаревших кривых (например, secp112r1).</td>
              </tr>
              <tr>
                <td>SHA-256</td>
                <td>Хэш-функция, используемая для создания хэшей в ЭП. Сопротивление коллизиям.</td>
                <td>Длина хэша 256 бит, устойчива к коллизиям (в отличие от SHA-1).</td>
                <td>Хэширование документа перед подписью.</td>
                <td>Использовать SHA-256 или SHA-3, избегать устаревших (MD5, SHA-1).</td>
              </tr>
              <tr>
                <td>X.509</td>
                <td>Стандарт для формата цифрового сертификата.</td>
                <td>Формат сертификата (включает ключ, данные владельца, CA).</td>
                <td>HTTPS-соединение.</td>
                <td>Проверять сертификаты на соответствие стандарту, использовать OCSP/CRL, проверять сроки действия.</td>
              </tr>
              <tr>
                <td>S/MIME</td>
                <td>Протокол для шифрования и подписи электронных писем.</td>
                <td>Используется для шифрования и подписи (с помощью сертификатов).</td>
                <td>Подпись и шифрование email в Outlook.</td>
                <td>Использовать S/MIME с надежными сертификатами.</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="theory-section">
          <p>Алгоритмы и стандарты, представленные в таблице, являются основой для обеспечения безопасности в системах шифрования. Асимметричные алгоритмы, такие как RSA и ECDSA, используются для создания и проверки цифровых подписей, а также для шифрования данных. RSA, основанный на сложности факторизации больших чисел, был одним из первых широко используемых алгоритмов, но требует больших длин ключей (2048+ бит) для обеспечения безопасности. ECDSA, использующий эллиптические кривые, более эффективен, так как обеспечивает тот же уровень безопасности с меньшими ключами (например, 256 бит эквивалентны 3072 бит RSA).</p>
          <p>Хэш-функции, такие как SHA-256, играют ключевую роль в создании цифровых подписей, обеспечивая целостность данных. Они генерируют уникальный хэш документа, который затем подписывается закрытым ключом. Стандарт X.509 определяет формат цифровых сертификатов, которые являются основой для аутентификации, а S/MIME обеспечивает защиту электронной почты, используя шифрование и подпись.</p>
          <p>Важно учитывать, что устаревшие алгоритмы (например, MD5, SHA-1, RSA с ключами менее 2048 бит) уязвимы к современным атакам, таким как атаки на коллизии или факторизацию. Поэтому рекомендуется использовать современные алгоритмы и следить за обновлениями стандартов, особенно с учётом угрозы квантовых вычислений, которые могут поставить под угрозу традиционные алгоритмы.</p>
        </div>
  
        <h2>Стандарты PKCS #7 и PKCS #10</h2>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Стандарт</th>
                <th>Описание</th>
                <th>Пример применения</th>
                <th>Особенности</th>
                <th>Рекомендации</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>PKCS #7</td>
                <td>Стандарт для формата сообщений с цифровой подписью или шифрованием (Cryptographic Message Syntax, CMS).</td>
                <td>Подпись и шифрование email-сообщений через S/MIME; сообщение подписывается с указанной сертификатной аутентификацией.</td>
                <td>- Поддержка подписи, шифрования и включение сертификатов.<br>- Используется в S/MIME, SSL/TLS (для цепочек сертификатов) — формат PEM (Base64), DER (бинарный).</td>
                <td>- Использовать для подписи и шифрования сообщений.<br>- Проверять целостность сертификатов при получении.<br>- Использовать (SHA-256), ECDSA.<br>- Хранить закрытый ключ в HSM.</td>
              </tr>
              <tr>
                <td>PKCS #10</td>
                <td>Стандарт для формата запроса на сертификат (Certificate Signing Request). Создание открытого ключа и данных владельца сертификата (CSR).</td>
                <td>Создание CSR для получения SSL-сертификата: алгоритм шифрования, открытый ключ и данные владельца сертификата (Let’s Encrypt).</td>
                <td>- Содержит открытый ключ (CN, O, C), подпись удостоверяющего центра, срок действия сертификата.<br>- Формат: PEM (Base64), DER (бинарный).</td>
                <td>- Генерировать CSR с надежным параметром (RSA 2048+ или ECDSA).<br>- Проверять данные в CSR перед передачей.<br>- Использовать HTTPS для передачи CSR.</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="theory-section">
          <p>Стандарты PKCS (Public-Key Cryptography Standards) были разработаны компанией RSA Security для унификации процессов, связанных с криптографией и управлением ключами. PKCS #7, также известный как CMS (Cryptographic Message Syntax), используется для создания сообщений с цифровой подписью или шифрованием. Этот стандарт широко применяется в S/MIME для защиты электронной почты, а также в SSL/TLS для передачи цепочек сертификатов. Он поддерживает различные форматы, такие как PEM (Base64) для текстового представления и DER (бинарный) для компактного хранения. PKCS #7 позволяет включать сертификаты в сообщение, что упрощает проверку подписи получателем.</p>
          <p>PKCS #10 определяет формат запроса на сертификат (CSR), который используется для получения цифрового сертификата от удостоверяющего центра (CA). CSR содержит открытый ключ, информацию о владельце (например, CN — общее имя, O — организация, C — страна) и подписывается закрытым ключом, чтобы CA мог проверить подлинность запроса. Этот стандарт также поддерживает форматы PEM и DER, что делает его универсальным для различных систем. Важно генерировать CSR с использованием надежных алгоритмов (например, RSA 2048+ или ECDSA) и передавать его по безопасным каналам (например, через HTTPS), чтобы избежать перехвата или подмены.</p>
          <p>Оба стандарта играют ключевую роль в криптографии, обеспечивая стандартизацию процессов подписи, шифрования и запроса сертификатов. Однако их безопасность зависит от правильного управления ключами и использования современных алгоритмов. Например, использование устаревших хэш-функций (MD5, SHA-1) в PKCS #7 может привести к уязвимостям, связанным с коллизиями, поэтому рекомендуется применять SHA-256 или выше.</p>
        </div>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadCryptographyContent(container);
    });
  }
  
  function loadAesEncryptionContent(container) {
    container.innerHTML = `
      <div class="cryptography-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>AES-шифрование</h1>
        <div class="theory-section">
          <h2>Что такое AES?</h2>
          <p>AES (Advanced Encryption Standard) — это симметричный блочный шифр, принятый в 2001 году Национальным институтом стандартов и технологий США (NIST) после конкурса. Он заменил устаревший стандарт DES и стал одним из самых распространённых алгоритмов шифрования в мире.</p>
  
          <h2>Основные характеристики AES</h2>
          <ul>
            <li><strong>Тип:</strong> Симметричный блочный шифр.</li>
            <li><strong>Длина ключа:</strong> 128, 192 или 256 бит.</li>
            <li><strong>Размер блока:</strong> 128 бит.</li>
            <li><strong>Раунды:</strong> 10 (для 128 бит), 12 (для 192 бит), 14 (для 256 бит).</li>
          </ul>
  
          <h2>Принцип работы AES</h2>
          <p>AES работает с блоками данных размером 128 бит, преобразуя их через несколько раундов шифрования. Каждый раунд включает следующие шаги:</p>
          <ol>
            <li><strong>SubBytes:</strong> Замена байтов с использованием таблицы подстановки (S-box).</li>
            <li><strong>ShiftRows:</strong> Циклический сдвиг строк в блоке.</li>
            <li><strong>MixColumns:</strong> Перемешивание столбцов для диффузии.</li>
            <li><strong>AddRoundKey:</strong> Добавление раундового ключа (генерируется из основного ключа).</li>
          </ol>
          <p>Первый и последний раунды немного отличаются: в первом нет MixColumns, а в последнем добавляется дополнительный AddRoundKey.</p>
  
          <h2>Режимы работы AES</h2>
          <div class="osi-table-container">
            <table class="osi-table">
              <thead>
                <tr>
                  <th>Режим</th>
                  <th>Описание</th>
                  <th>Пример использования</th>
                  <th>Проблемы</th>
                  <th>Рекомендации</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>ECB (Electronic Codebook)</td>
                  <td>Каждый блок шифруется независимо.</td>
                  <td>Шифрование небольших данных (устаревший режим).</td>
                  <td>Одинаковые блоки дают одинаковый шифротекст, что уязвимо для анализа.</td>
                  <td>Не использовать ECB для больших данных.</td>
                </tr>
                <tr>
                  <td>CBC (Cipher Block Chaining)</td>
                  <td>Каждый блок XOR-ится с предыдущим шифротекстом перед шифрованием.</td>
                  <td>Шифрование файлов (например, в OpenSSL).</td>
                  <td>Требуется вектор инициализации (IV), уязвим к атакам на IV.</td>
                  <td>Использовать случайный IV, не повторять IV.</td>
                </tr>
                <tr>
                  <td>GCM (Galois/Counter Mode)</td>
                  <td>Комбинирует шифрование с аутентификацией (AEAD).</td>
                  <td>Шифрование в TLS 1.3.</td>
                  <td>Повторение IV может привести к утечке ключа.</td>
                  <td>Использовать уникальный IV, применять для высокопроизводительных систем.</td>
                </tr>
              </tbody>
            </table>
          </div>
  
          <h2>Пример использования</h2>
          <p>AES широко используется в различных системах:</p>
          <ul>
            <li><strong>TLS/SSL:</strong> Шифрование HTTPS-трафика (например, в Chrome, Firefox).</li>
            <li><strong>VPN:</strong> Шифрование данных в IPsec или OpenVPN.</li>
            <li><strong>Дисковое шифрование:</strong> Защита данных на жёстких дисках (например, BitLocker).</li>
          </ul>
  
          <h2>Преимущества и недостатки</h2>
          <ul>
            <li><strong>Преимущества:</strong> Высокая скорость, безопасность, поддержка аппаратного ускорения (AES-NI в процессорах Intel/AMD).</li>
            <li><strong>Недостатки:</strong> Уязвимость к атакам на реализацию (например, атаки по сторонним каналам, такие как тайминг-атаки).</li>
          </ul>
  
          <h2>Рекомендации</h2>
          <ul>
            <li>Использовать AES-256 для максимальной безопасности.</li>
            <li>Выбирать режимы с аутентификацией (например, GCM).</li>
            <li>Обеспечить безопасное управление ключами (например, через HSM).</li>
            <li>Регулярно обновлять библиотеки (например, OpenSSL) для защиты от уязвимостей.</li>
          </ul>
        </div>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadCryptographyContent(container);
    });
  }
  
  function loadQuantumEncryptionContent(container) {
    container.innerHTML = `
      <div class="cryptography-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Квантовое шифрование</h1>
        <div class="theory-section">
          <h2>Что такое квантовое шифрование?</h2>
          <p>Квантовое шифрование — это передовая технология, использующая принципы квантовой механики для защиты данных. В отличие от классических методов шифрования, которые полагаются на математические алгоритмы, квантовое шифрование использует физические свойства квантовых систем, такие как суперпозиция, запутанность и принцип неопределённости Гейзенберга. Это делает его теоретически невзламываемым даже с использованием квантовых компьютеров.</p>
  
          <h2>Квантовое распределение ключей (QKD)</h2>
          <p>Одним из ключевых направлений квантового шифрования является квантовое распределение ключей (Quantum Key Distribution, QKD). QKD позволяет двум сторонам (например, Алисе и Бобу) безопасно обмениваться криптографическими ключами, используя квантовые состояния, такие как поляризация фотонов. Наиболее известный протокол QKD — это BB84, разработанный Чарльзом Беннеттом и Жилем Брассаром в 1984 году.</p>
          <p>Принцип работы QKD:</p>
          <ul>
            <li>Алиса отправляет Бобу последовательность фотонов, каждый из которых находится в случайном квантовом состоянии (например, поляризация 0°, 45°, 90° или 135°).</li>
            <li>Боб измеряет фотоны, выбирая случайную основу измерения (прямоугольную или диагональную).</li>
            <li>Алиса и Боб сравнивают свои основы через открытый канал и отбрасывают результаты, где основы не совпали.</li>
            <li>Оставшиеся биты формируют общий секретный ключ.</li>
            <li>Если злоумышленник (Ева) пытается перехватить фотоны, её измерения изменят квантовые состояния (согласно принципу неопределённости), что будет обнаружено Алисой и Бобом через проверку ошибок.</li>
          </ul>
          <p>Пример: В 2023 году китайская спутниковая система Micius успешно использовала QKD для передачи ключей между наземными станциями на расстоянии более 1000 км, демонстрируя практическую применимость технологии.</p>
  
          <h2>Постквантовые алгоритмы (PQC)</h2>
          <p>Квантовое шифрование также связано с развитием постквантовых криптографических алгоритмов (Post-Quantum Cryptography, PQC), которые устойчивы к атакам квантовых компьютеров. В отличие от QKD, PQC не требует квантового оборудования и может быть внедрена на существующих устройствах. В 2022 году Национальный институт стандартов и технологий США (NIST) завершил первый этап стандартизации PQC, выбрав следующие алгоритмы:</p>
          <ul>
            <li><strong>CRYSTALS-Kyber:</strong> Алгоритм для шифрования и обмена ключами, основанный на решётках (lattice-based cryptography).</li>
            <li><strong>CRYSTALS-Dilithium:</strong> Алгоритм для цифровой подписи, также основанный на решётках.</li>
            <li><strong>FALCON:</strong> Ещё один алгоритм подписи на основе решёток, оптимизированный для компактности.</li>
            <li><strong>SPHINCS+:</strong> Алгоритм подписи, основанный на хэш-функциях, обеспечивающий высокую надёжность.</li>
          </ul>
          <p>Эти алгоритмы уже начинают внедряться в современные системы. Например, в 2024 году Google анонсировала поддержку Kyber в Chrome для защиты TLS-соединений, а Cloudflare интегрировала PQC в свои серверы для защиты HTTPS-трафика.</p>
  
          <h2>Квантовые сети и будущее</h2>
          <p>Квантовое шифрование активно развивается в направлении квантовых сетей. В 2023 году в Нидерландах была запущена первая коммерческая квантовая сеть, использующая QKD для защиты данных между дата-центрами. В Китае продолжается развитие квантовой сети на основе спутников и оптоволоконных линий, которая охватывает более 2000 км.</p>
          <p>Квантовые сети также открывают перспективы для квантового интернета, где данные передаются с использованием квантовой запутанности. Это может обеспечить мгновенную передачу информации и абсолютную безопасность, так как любое вмешательство в запутанные состояния будет немедленно обнаружено.</p>
  
          <h2>Вызовы и перспективы</h2>
          <p>Несмотря на потенциал, квантовое шифрование сталкивается с рядом вызовов:</p>
          <ul>
            <li><strong>Технические ограничения:</strong> QKD требует специализированного оборудования (например, фотонных детекторов) и чувствителен к потерям сигнала в оптоволокне. Максимальная дистанция передачи пока ограничена (до 500 км без ретрансляторов).</li>
            <li><strong>Стоимость:</strong> Квантовые технологии пока дороги для массового внедрения.</li>
            <li><strong>Интеграция:</strong> Постквантовые алгоритмы требуют обновления существующих систем, что может занять годы. Например, переход на PQC в PKI требует обновления сертификатов, протоколов и программного обеспечения.</li>
            <li><strong>Стандартизация:</strong> Хотя NIST уже выбрал несколько PQC-алгоритмов, процесс их стандартизации и тестирования продолжается. Новые атаки на решётки или хэш-функции могут потребовать пересмотра стандартов.</li>
          </ul>
          <p>Тем не менее, квантовое шифрование — это будущее криптографии. Ожидается, что к 2030 году QKD станет стандартом для защиты критически важных данных (например, в банковской сфере и государственных системах), а PQC будет повсеместно внедрён в интернет-протоколы, такие как TLS и SSH. Компании, такие как IBM, Google и Microsoft, активно инвестируют в квантовые технологии, что ускоряет их развитие.</p>
        </div>
      </div>
    `;
  
    document.querySelector('.back-btn').addEventListener('click', () => {
      loadCryptographyContent(container);
    });
  }