// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

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
          <button class="network-btn" id="steganography-btn">Стеганография</button>
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

    document.getElementById('steganography-btn').addEventListener('click', () => {
      loadSteganographyContent(container);
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

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>RSA</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Генерация ключей
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Два простых числа</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Открытый ключ</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Подпись
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Закрытый ключ</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SSL-сертификаты</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>RSA</h3>
            <p>RSA — это асимметричный алгоритм, основанный на сложности факторизации больших чисел. Он использует пару ключей: открытый для шифрования и закрытый для расшифровки или подписи. Алгоритм был разработан в 1977 году Рональдом Ривестом, Ади Шамиром и Леонардом Адлеманом.</p>
            <p><strong>Особенности:</strong> RSA применяется для шифрования и создания цифровых подписей. Для обеспечения безопасности рекомендуется использовать ключи длиной 2048 бит и выше, так как более короткие ключи (например, 1024 бита) уязвимы к современным вычислительным атакам.</p>
            <p><strong>Пример использования:</strong> RSA широко используется для подписи в SSL-сертификатах, обеспечивая аутентификацию серверов в HTTPS-соединениях.</p>
            <p><strong>Рекомендации:</strong> Используйте ключи длиной 2048+ бит и избегайте устаревших длин ключей (например, 1024 бита), которые уже не считаются безопасными из-за прогресса в вычислительных мощностях и алгоритмах факторизации.</p>
          </div>
        </div>
      </div>

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>ECDSA</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Эллиптическая кривая
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Математическая основа</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Генерация ключей
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Короткие ключи</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Подпись
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Закрытый ключ</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">TLS 1.3</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>ECDSA (Elliptic Curve Digital Signature Algorithm)</h3>
            <p>ECDSA — это асимметричный алгоритм на основе эллиптических кривых, предназначенный для создания и проверки цифровых подписей. Он обеспечивает тот же уровень безопасности, что и RSA, но с меньшей длиной ключа, что делает его более эффективным.</p>
            <p><strong>Что такое эллиптические кривые?</strong> Эллиптические кривые — это математические структуры, описываемые уравнением вида y² = x³ + ax + b, где a и b — константы, а кривая определена над конечным полем. Безопасность ECDSA основана на сложности задачи дискретного логарифма в группе точек эллиптической кривой (ECDLP). В отличие от RSA, где безопасность зависит от факторизации больших чисел, ECDLP сложнее решить даже на квантовых компьютерах при правильном выборе параметров. Точки на кривой образуют группу, в которой операции сложения и умножения на скаляр используются для генерации ключей и подписи.</p>
            <p><strong>Особенности:</strong> Ключ длиной 256 бит в ECDSA эквивалентен по безопасности ключу RSA длиной 3072 бит. Это делает алгоритм более компактным и быстрым.</p>
            <p><strong>Пример использования:</strong> ECDSA применяется для подписи в сертификатах TLS 1.3, обеспечивая безопасность HTTPS-соединений.</p>
            <p><strong>Рекомендации:</strong> Используйте кривые уровня NIST P-256 или выше (например, P-384, P-521) и избегайте устаревших кривых, таких как secp112r1, которые имеют недостаточную длину ключа и уязвимы к атакам.</p>
          </div>
        </div>
      </div>

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>SHA-256</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Входные данные
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст или файл</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Хэширование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">256-битный хэш</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Подпись
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">С RSA/ECDSA</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Цифровая подпись</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>SHA-256</h3>
            <p>SHA-256 — это хэш-функция из семейства SHA-2, используемая для создания хэшей в цифровых подписях. Она преобразует входные данные произвольной длины в фиксированный 256-битный хэш, который устойчив к коллизиям.</p>
            <p><strong>Особенности:</strong> Длина хэша составляет 256 бит, что обеспечивает высокую стойкость к атакам на коллизии (в отличие от устаревшего SHA-1, который уже скомпрометирован).</p>
            <p><strong>Пример использования:</strong> SHA-256 применяется для хэширования документа перед подписью в системах электронной подписи, гарантируя целостность данных.</p>
            <p><strong>Рекомендации:</strong> Используйте SHA-256 или более современный SHA-3, избегая устаревших функций, таких как MD5 и SHA-1, которые уязвимы к атакам на коллизии и не соответствуют современным стандартам безопасности.</p>
          </div>
        </div>
      </div>

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>X.509</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Данные владельца
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">CN, O, C</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Ключ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Открытый ключ</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Сертификат
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Формат</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">HTTPS</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>X.509</h3>
            <p>X.509 — это стандарт для формата цифрового сертификата, используемого в инфраструктуре открытых ключей (PKI). Он определяет структуру сертификатов, которые содержат открытый ключ, данные владельца и подпись удостоверяющего центра (CA).</p>
            <p><strong>Особенности:</strong> Формат включает ключ, данные владельца (например, CN — общее имя, O — организация, C — страна) и информацию о CA, что делает его универсальным для аутентификации.</p>
            <p><strong>Пример использования:</strong> X.509 применяется в HTTPS-соединениях для проверки подлинности серверов и защиты данных в интернете.</p>
            <p><strong>Рекомендации:</strong> Проверяйте сертификаты на соответствие стандарту, используйте OCSP или CRL для проверки актуальности и следите за сроками действия сертификатов, чтобы избежать уязвимостей.</p>
          </div>
        </div>
      </div>

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>S/MIME</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Сообщение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Электронное письмо</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сертификат</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Подпись
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Закрытый ключ</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Email в Outlook</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>S/MIME</h3>
            <p>S/MIME (Secure/Multipurpose Internet Mail Extensions) — это протокол для шифрования и подписи электронных писем. Он использует сертификаты для защиты сообщений и проверки подлинности отправителя.</p>
            <p><strong>Особенности:</strong> Протокол поддерживает шифрование и подпись с использованием сертификатов, что обеспечивает конфиденциальность и целостность переписки.</p>
            <p><strong>Пример использования:</strong> S/MIME применяется для подписи и шифрования email в почтовых клиентах, таких как Outlook.</p>
            <p><strong>Рекомендации:</strong> Используйте S/MIME с надежными сертификатами от проверенных удостоверяющих центров для обеспечения максимальной безопасности.</p>
          </div>
        </div>
      </div>

      <div class="theory-section">
        <p>Алгоритмы и стандарты, представленные выше, являются основой для обеспечения безопасности в системах шифрования. Асимметричные алгоритмы, такие как RSA и ECDSA, используются для создания и проверки цифровых подписей, а также для шифрования данных. RSA, основанный на сложности факторизации больших чисел, был одним из первых широко используемых алгоритмов, но требует больших длин ключей (2048+ бит) для обеспечения безопасности. ECDSA, использующий эллиптические кривые, более эффективен, так как обеспечивает тот же уровень безопасности с меньшими ключами (например, 256 бит эквивалентны 3072 бит RSA).</p>
        <p>Хэш-функции, такие как SHA-256, играют ключевую роль в создании цифровых подписей, обеспечивая целостность данных. Они генерируют уникальный хэш документа, который затем подписывается закрытым ключом. Стандарт X.509 определяет формат цифровых сертификатов, которые являются основой для аутентификации, а S/MIME обеспечивает защиту электронной почты, используя шифрование и подпись.</p>
        <p>Важно учитывать, что устаревшие алгоритмы (например, MD5, SHA-1, RSA с ключами менее 2048 бит) уязвимы к современным атакам, таким как атаки на коллизии или факторизацию. Поэтому рекомендуется использовать современные алгоритмы и следить за обновлениями стандартов, особенно с учётом угрозы квантовых вычислений, которые могут поставить под угрозу традиционные алгоритмы.</p>
      </div>

      <h2>Стандарты PKCS #7 и PKCS #10</h2>

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>PKCS #7</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Сообщение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Данные</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Подпись
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">С сертификатом</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">CMS формат</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">S/MIME</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>PKCS #7</h3>
            <p>PKCS #7 — это стандарт для формата сообщений с цифровой подписью или шифрованием, также известный как Cryptographic Message Syntax (CMS). Он используется для создания защищённых сообщений, которые могут включать подпись, шифрование и сертификаты.</p>
            <p><strong>Пример применения:</strong> PKCS #7 применяется для подписи и шифрования email-сообщений через S/MIME, где сообщение подписывается с указанием сертификатной аутентификации.</p>
            <p><strong>Особенности:</strong> Стандарт поддерживает подпись, шифрование и включение сертификатов. Он используется в S/MIME и SSL/TLS (например, для цепочек сертификатов) и доступен в форматах PEM (Base64) и DER (бинарный).</p>
            <p><strong>Рекомендации:</strong> Используйте PKCS #7 для подписи и шифрования сообщений, проверяйте целостность сертификатов при получении, применяйте SHA-256 и ECDSA для повышения безопасности, а также храните закрытый ключ в HSM для защиты от утечек.</p>
          </div>
        </div>
      </div>

      <div class="algo-method">
        <div class="algo-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="algo-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>PKCS #10</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Данные владельца
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">CN, O, C</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Ключ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Открытый ключ</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Запрос CSR
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Подпись CA</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">SSL-сертификат</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>PKCS #10</h3>
            <p>PKCS #10 — это стандарт для формата запроса на сертификат (Certificate Signing Request, CSR). Он используется для создания запроса, содержащего открытый ключ и данные владельца, который затем отправляется удостоверяющему центру (CA) для получения сертификата.</p>
            <p><strong>Пример применения:</strong> PKCS #10 применяется для создания CSR для получения SSL-сертификатов, например, через сервисы вроде Let’s Encrypt.</p>
            <p><strong>Особенности:</strong> CSR содержит открытый ключ, информацию о владельце (CN — общее имя, O — организация, C — страна), подпись удостоверяющего центра и срок действия. Форматы включают PEM (Base64) и DER (бинарный).</p>
            <p><strong>Рекомендации:</strong> Генерируйте CSR с надежными параметрами (RSA 2048+ или ECDSA), проверяйте данные в CSR перед передачей и используйте HTTPS для безопасной отправки запроса.</p>
          </div>
        </div>
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
        <h2>AES (Advanced Encryption Standard)</h2>
        <p>AES (Advanced Encryption Standard) — это симметричный блочный шифр, принятый в 2001 году Национальным институтом стандартов и технологий США (NIST) после конкурса, в котором победил алгоритм Rijndael, разработанный Винсентом Рэйменом и Йоаном Дайменом. AES заменил устаревший стандарт DES (Data Encryption Standard) благодаря своей высокой скорости, безопасности и универсальности.</p>
        <p>AES работает с блоками данных фиксированной длины 128 бит (16 байт) и поддерживает ключи длиной 128, 192 или 256 бит. Алгоритм использует несколько раундов преобразований (10, 12 или 14 в зависимости от длины ключа), включая подстановку, перестановку, смешивание столбцов и добавление раундового ключа. Эти шаги обеспечивают высокую степень рассеивания и запутывания данных, что делает AES устойчивым к криптоанализу.</p>
        <p>Ниже представлены основные режимы работы AES и их характеристики.</p>
      </div>

      <h2>Режимы работы AES</h2>

      <div class="aes-method">
        <div class="aes-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="aes-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>ECB (Electronic Codebook)</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Исходный текст
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Разделение на блоки</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Каждый блок отдельно</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифротекст
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Объединение блоков</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Простые задачи</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>ECB (Electronic Codebook)</h3>
            <p>ECB (Electronic Codebook) — это самый простой режим работы AES, в котором каждый блок исходного текста шифруется независимо с использованием одного и того же ключа. Процесс напоминает работу кодовой книги, где каждому блоку соответствует зашифрованный эквивалент.</p>
            <p><strong>Описание:</strong> Исходный текст делится на блоки по 128 бит, каждый блок шифруется отдельно, а затем результаты объединяются в шифротекст. Это делает процесс простым и параллелизуемым.</p>
            <p><strong>Пример использования:</strong> ECB может использоваться для шифрования небольших данных, таких как ключи или идентификаторы, где повторяемость не критична.</p>
            <p><strong>Проблемы:</strong> Основной недостаток — отсутствие рассеивания: одинаковые блоки исходного текста дают одинаковый шифротекст, что раскрывает структуру данных (например, узоры в изображениях). Это делает ECB уязвимым к анализу шаблонов.</p>
            <p><strong>Рекомендации:</strong> Не используйте ECB для больших данных или конфиденциальной информации из-за его слабой безопасности. Предпочтительны более сложные режимы, такие как CBC или GCM.</p>
          </div>
        </div>
      </div>

      <div class="aes-method">
        <div class="aes-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="aes-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>CBC (Cipher Block Chaining)</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Исходный текст
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Разделение на блоки</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Вектор IV
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">XOR с первым блоком</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Цепочка блоков</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Файловые системы</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>CBC (Cipher Block Chaining)</h3>
            <p>CBC (Cipher Block Chaining) — это режим, в котором каждый блок исходного текста перед шифрованием комбинируется с предыдущим шифротекстом через операцию XOR. Первый блок комбинируется с инициализирующим вектором (IV).</p>
            <p><strong>Описание:</strong> Исходный текст делится на блоки по 128 бит. Первый блок XOR-ится с IV, затем шифруется. Каждый следующий блок XOR-ится с шифротекстом предыдущего блока перед шифрованием, создавая цепочку зависимостей.</p>
            <p><strong>Пример использования:</strong> CBC часто применяется для шифрования файлов в файловых системах, таких как LUKS, благодаря хорошему рассеиванию данных.</p>
            <p><strong>Проблемы:</strong> Требуется уникальный IV для каждой операции шифрования, иначе одинаковые исходные тексты дадут одинаковый шифротекст. Ошибки в одном блоке могут повлиять на следующий.</p>
            <p><strong>Рекомендации:</strong> Используйте CBC с уникальным, случайным IV для каждой сессии. Передавайте IV вместе с шифротекстом открыто, так как он не является секретом.</p>
          </div>
        </div>
      </div>

      <div class="aes-method">
        <div class="aes-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="aes-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>CTR (Counter)</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Исходный текст
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Разделение на блоки</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Счётчик
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Nonce + счетчик</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Потоковый режим</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Потоковые данные</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>CTR (Counter)</h3>
            <p>CTR (Counter) — это режим, превращающий блочный шифр AES в потоковый. Он генерирует псевдослучайный поток, шифруя счётчик, который затем XOR-ится с исходным текстом.</p>
            <p><strong>Описание:</strong> Счётчик состоит из уникального значения (nonce) и увеличивающегося числа. Каждый блок счётчика шифруется AES, а результат XOR-ится с блоком исходного текста, создавая шифротекст.</p>
            <p><strong>Пример использования:</strong> CTR применяется для шифрования потоковых данных, таких как видео или аудио в реальном времени, благодаря возможности параллельной обработки.</p>
            <p><strong>Проблемы:</strong> Повторное использование nonce с тем же ключом приводит к раскрытию данных через XOR-анализ. Нет встроенной проверки целостности.</p>
            <p><strong>Рекомендации:</strong> Используйте уникальный nonce для каждого сообщения и комбинируйте CTR с MAC (например, HMAC) для проверки целостности.</p>
          </div>
        </div>
      </div>

      <div class="aes-method">
        <div class="aes-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="aes-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>GCM (Galois/Counter Mode)</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Исходный текст
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Разделение на блоки</p>
              </div>
              <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Счётчик + IV
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Поток шифрования</p>
              </div>
              <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Аутентификация
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Galois MAC</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">TLS 1.2+</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>GCM (Galois/Counter Mode)</h3>
            <p>GCM (Galois/Counter Mode) — это режим, сочетающий шифрование в стиле CTR с аутентификацией данных через Galois MAC (аутентифицированное шифрование, AEAD). Он обеспечивает конфиденциальность и целостность.</p>
            <p><strong>Описание:</strong> Как и в CTR, используется счётчик с IV для генерации потока шифрования, который XOR-ится с исходным текстом. Дополнительно вычисляется тег аутентификации (MAC) с использованием поля Галуа.</p>
            <p><strong>Пример использования:</strong> GCM применяется в TLS 1.2 и выше для защиты веб-трафика, обеспечивая одновременно шифрование и проверку целостности.</p>
            <p><strong>Проблемы:</strong> Повторное использование IV с тем же ключом компрометирует безопасность, раскрывая данные и подделывая тег MAC.</p>
            <p><strong>Рекомендации:</strong> Используйте GCM с уникальным IV для каждой сессии (96 бит рекомендуются NIST). Проверяйте тег MAC перед расшифровкой для защиты от атак на подделку.</p>
          </div>
        </div>
      </div>

      <div class="theory-section">
        <h2>Процесс шифрования AES</h2>
        <p>AES работает с фиксированным размером блока 128 бит и использует ключи длиной 128, 192 или 256 бит. Процесс шифрования включает несколько раундов преобразований, зависящих от длины ключа: 10 раундов для 128 бит, 12 для 192 бит и 14 для 256 бит. Каждый раунд состоит из четырёх основных шагов:</p>
        <ul>
          <li><strong>SubBytes:</strong> Замена байтов в блоке с использованием таблицы подстановки (S-box), основанной на нелинейных функциях. Это обеспечивает запутывание данных.</li>
          <li><strong>ShiftRows:</strong> Циклический сдвиг строк в состоянии (state) — 4x4 матрице байтов. Первая строка остаётся без изменений, вторая сдвигается на 1 байт, третья на 2, четвёртая на 3.</li>
          <li><strong>MixColumns:</strong> Линейное преобразование столбцов состояния с использованием умножения в поле Галуа GF(2⁸). Это обеспечивает рассеивание данных между байтами.</li>
          <li><strong>AddRoundKey:</strong> Добавление раундового ключа к состоянию через операцию XOR. Раундовые ключи генерируются из исходного ключа с помощью процедуры расширения ключа (Key Expansion).</li>
        </ul>
        <p>Перед первым раундом выполняется начальный AddRoundKey. Последний раунд отличается отсутствием шага MixColumns, чтобы упростить процесс расшифровки.</p>

        <h2>Расширение ключа</h2>
        <p>Расширение ключа (Key Expansion) — это процесс генерации раундовых ключей из исходного ключа. Например, для ключа 128 бит генерируется 10 дополнительных ключей (по 128 бит каждый), что даёт в общей сложности 11 ключей (включая исходный). Процесс включает:</p>
        <ul>
          <li>Циклический сдвиг байтов последнего слова предыдущего ключа.</li>
          <li>Применение S-box к сдвинутому слову.</li>
          <li>XOR с константой раунда (Rcon), зависящей от номера раунда.</li>
          <li>Последовательное XOR с другими словами ключа для создания нового раундового ключа.</li>
        </ul>
        <p>Для ключей 192 и 256 бит процесс аналогичен, но генерируется больше раундовых ключей (13 и 15 соответственно).</p>

        <h2>Применение и безопасность</h2>
        <p>AES используется повсеместно: в TLS/SSL для защиты веб-трафика, в VPN (например, IPsec), в шифровании дисков (BitLocker, FileVault) и в стандартах вроде WPA2/WPA3 для Wi-Fi. Безопасность AES зависит от выбора режима работы и управления ключами. Например, ECB уязвим к анализу шаблонов, а повторное использование IV в CBC, CTR или GCM может привести к раскрытию данных.</p>
        <p>На март 2025 года AES остаётся устойчивым к классическим атакам при использовании ключей 256 бит и современных режимов (например, GCM). Однако квантовые компьютеры с алгоритмом Гровера могут сократить эффективную длину ключа вдвое (например, 256 бит станут эквивалентны 128 битам), что требует перехода на постквантовые алгоритмы в будущем.</p>

        <h2>Рекомендации</h2>
        <ul>
          <li>Используйте ключи длиной 256 бит для максимальной безопасности.</li>
          <li>Предпочитайте GCM или CTR с MAC для шифрования с аутентификацией.</li>
          <li>Избегайте ECB для конфиденциальных данных.</li>
          <li>Обеспечьте уникальность IV/nonce для каждой операции шифрования.</li>
          <li>Храните ключи в защищённых устройствах (например, HSM) и регулярно обновляйте их.</li>
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
        <p>Квантовое шифрование — это подход к защите информации, основанный на принципах квантовой механики, таких как суперпозиция, запутанность и невозможность измерения квантового состояния без его изменения. В отличие от классической криптографии, которая полагается на вычислительную сложность (например, факторизацию или дискретные логарифмы), квантовое шифрование использует физические свойства квантовых систем, обеспечивая теоретически абсолютную безопасность.</p>
        <p>Квантовое шифрование включает два ключевых направления: квантовое распределение ключей (QKD), позволяющее двум сторонам безопасно обмениваться ключами, и постквантовую криптографию, которая разрабатывает алгоритмы, устойчивые к атакам квантовых компьютеров. На март 2025 года квантовые технологии активно развиваются, но их массовое внедрение пока ограничено высокой стоимостью и сложностью оборудования.</p>
      </div>

      <h2>Методы квантового шифрования</h2>

      <div class="quantum-method">
        <div class="quantum-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="quantum-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>BB84</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Квантовые биты
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фотонная поляризация</p>
              </div>
              <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Передача
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Квантовый канал</p>
              </div>
              <div style="background-color: #64b5f6; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Измерение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Случайные базисы</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Ключ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Общий секрет</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>BB84</h3>
            <p>BB84 — это первый и наиболее известный протокол квантового распределения ключей (QKD), разработанный Чарльзом Беннеттом и Жилем Брассаром в 1984 году. Он использует квантовые свойства фотонов, такие как поляризация, для безопасной передачи ключа между двумя сторонами (Алисой и Бобом).</p>
            <p><strong>Описание:</strong> Алиса отправляет Бобу последовательность фотонов, каждый из которых кодирует бит (0 или 1) в одном из двух базисов (например, прямом или диагональном). Боб измеряет фотоны в случайно выбранных базисах. Затем они сравнивают базисы по классическому каналу, отбрасывая несовпадения, и формируют общий ключ из оставшихся битов. Любая попытка перехвата (Евой) изменяет квантовое состояние фотонов, что выявляется при проверке ошибок.</p>
            <p><strong>Пример использования:</strong> BB84 применяется в квантовых сетях, таких как сеть DARPA Quantum Network (2004) или коммерческие системы от ID Quantique.</p>
            <p><strong>Проблемы:</strong> Уязвим к атакам на оборудование (например, ослеплению детекторов) и ограничен расстоянием передачи (до 100-200 км из-за потерь в оптоволокне).</p>
            <p><strong>Рекомендации:</strong> Используйте BB84 с проверкой подлинности по классическому каналу (например, с MAC) и усиливайте сигнал с помощью квантовых повторителей для больших расстояний.</p>
          </div>
        </div>
      </div>

      <div class="quantum-method">
        <div class="quantum-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="quantum-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>E91</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Запутанные пары
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фотоны</p>
              </div>
              <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Распределение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Алиса и Боб</p>
              </div>
              <div style="background-color: #64b5f6; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Измерение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Корреляция</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Ключ
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Общий секрет</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>E91</h3>
            <p>E91 — это протокол QKD, предложенный Артуром Экертом в 1991 году, основанный на квантовой запутанности. Он использует пары запутанных частиц для генерации общего ключа между Алисой и Бобом.</p>
            <p><strong>Описание:</strong> Источник генерирует пары запутанных фотонов, которые распределяются между Алисой и Бобом. Они измеряют свои частицы в случайных базисах, а затем сравнивают результаты, чтобы проверить нарушение неравенств Белла, подтверждающее отсутствие подслушивания. Коррелированные измерения формируют ключ.</p>
            <p><strong>Пример использования:</strong> E91 тестировался в экспериментальных квантовых сетях, таких как сеть в Вене (2008), демонстрируя устойчивость к перехвату.</p>
            <p><strong>Проблемы:</strong> Требует сложного оборудования для генерации и поддержания запутанности, а также чувствителен к потерям фотонов на больших расстояниях.</p>
            <p><strong>Рекомендации:</strong> Применяйте E91 с высококачественными источниками запутанности и используйте квантовые повторители для увеличения дальности передачи.</p>
          </div>
        </div>
      </div>

      <div class="quantum-method">
        <div class="quantum-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="quantum-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Shor’s Algorithm</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Квантовый компьютер
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Кубиты</p>
              </div>
              <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Факторизация
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Период функции</p>
              </div>
              <div style="background-color: #64b5f6; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Вычисление
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Быстрое решение</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Угроза
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">RSA взлом</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>Shor’s Algorithm</h3>
            <p>Алгоритм Шора — это квантовый алгоритм, разработанный Питером Шором в 1994 году, который эффективно решает задачу факторизации больших чисел и дискретного логарифма, угрожая классическим асимметричным алгоритмам, таким как RSA и ECC.</p>
            <p><strong>Описание:</strong> Алгоритм использует квантовую суперпозицию и преобразование Фурье для нахождения периода функции, связанной с факторизацией. Это позволяет разложить большое число на множители за полиномиальное время, в отличие от экспоненциального времени на классических компьютерах.</p>
            <p><strong>Пример использования:</strong> Пока применяется только в экспериментах (например, факторизация 21 на квантовом компьютере IBM в 2012 году), но представляет угрозу для RSA и ECC при масштабировании квантовых систем.</p>
            <p><strong>Проблемы:</strong> Требует мощного квантового компьютера с тысячами стабильных кубитов, что пока недостижимо (на 2025 год).</p>
            <p><strong>Рекомендации:</strong> Переходите на постквантовые алгоритмы (например, решётчатые схемы) для защиты от будущих атак Шора.</p>
          </div>
        </div>
      </div>

      <div class="quantum-method">
        <div class="quantum-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="quantum-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Grover’s Algorithm</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Квантовый компьютер
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Кубиты</p>
              </div>
              <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Поиск
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Оракул</p>
              </div>
              <div style="background-color: #64b5f6; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Ускорение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Квадратичное</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Угроза
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">AES взлом</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>Grover’s Algorithm</h3>
            <p>Алгоритм Гровера, разработанный Ловом Гровером в 1996 году, обеспечивает квадратичное ускорение поиска в неструктурированных данных, что угрожает симметричным алгоритмам, таким как AES.</p>
            <p><strong>Описание:</strong> Алгоритм использует квантовую суперпозицию и оракул для поиска элемента в базе данных за O(√N) шагов вместо O(N) на классическом компьютере. Это снижает эффективную длину ключа симметричных шифров вдвое (например, AES-256 становится эквивалентным 128 битам).</p>
            <p><strong>Пример использования:</strong> Пока используется в теоретических демонстрациях (например, поиск в малых базах на квантовых симуляторах), но может применяться для атак на ключи AES в будущем.</p>
            <p><strong>Проблемы:</strong> Требует значительного числа кубитов и устойчивости к шуму, что пока ограничивает практическое применение (на 2025 год).</p>
            <p><strong>Рекомендации:</strong> Удвойте длину ключей для симметричных алгоритмов (например, используйте AES-256 вместо AES-128) для защиты от Гровера.</p>
          </div>
        </div>
      </div>

      <div class="quantum-method">
        <div class="quantum-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
          <div class="quantum-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
            <h3>Lattice-Based Crypto</h3>
            <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
              <div style="background-color: #1976d2; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Решётки
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Математическая основа</p>
              </div>
              <div style="background-color: #2196f3; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Генерация ключей
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Короткие векторы</p>
              </div>
              <div style="background-color: #64b5f6; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Шифрование
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Устойчивость</p>
              </div>
              <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                Применение
                <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">NIST стандарты</p>
              </div>
            </div>
          </div>
          <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
          <div style="flex: 1; padding: 15px;">
            <h3>Lattice-Based Crypto (Решётчатая криптография)</h3>
            <p>Решётчатая криптография — это постквантовая криптосистема, основанная на сложности задач в математических решётках (lattices), таких как поиск кратчайшего вектора (SVP) или ближайшего вектора (CVP).</p>
            <p><strong>Описание:</strong> Алгоритмы используют решётки — регулярные структуры в многомерном пространстве. Безопасность основана на том, что даже квантовые компьютеры не могут эффективно решать эти задачи. Примеры включают схемы Learning With Errors (LWE) и Ring-LWE.</p>
            <p><strong>Пример использования:</strong> Решётчатые алгоритмы, такие как Kyber и Dilithium, выбраны NIST в 2022 году для стандартизации постквантовой криптографии.</p>
            <p><strong>Проблемы:</strong> Большие размеры ключей (до нескольких килобайт) и высокая вычислительная сложность по сравнению с классическими алгоритмами.</p>
            <p><strong>Рекомендации:</strong> Внедряйте решётчатые схемы (например, Kyber) для защиты данных в долгосрочной перспективе, особенно для критической инфраструктуры.</p>
          </div>
        </div>
      </div>

      <div class="theory-section">
        <h2>Принципы квантовой безопасности</h2>
        <p>Квантовое шифрование опирается на фундаментальные принципы квантовой механики. Суперпозиция позволяет кубиту находиться в состоянии 0 и 1 одновременно, что используется в алгоритмах Шора и Гровера для ускорения вычислений. Запутанность обеспечивает корреляцию между частицами на расстоянии, как в протоколе E91, где любое вмешательство нарушает эту корреляцию и выявляется. Принцип неопределённости Гейзенберга гарантирует, что измерение квантового состояния (например, в BB84) изменяет его, делая подслушивание заметным.</p>
        <p>Протоколы QKD, такие как BB84 и E91, обеспечивают безопасное распределение ключей, которые затем могут использоваться в классических шифрах (например, AES). Их безопасность не зависит от вычислительной сложности, а от физических законов, что делает их теоретически невзламываемыми.</p>

        <h2>Угрозы классической криптографии</h2>
        <p>Квантовые алгоритмы, такие как Шора и Гровера, представляют угрозу для существующих систем. Алгоритм Шора может сломать RSA и ECC, решая факторизацию и дискретный логарифм за полиномиальное время. Алгоритм Гровера снижает стойкость симметричных шифров (AES, SHA) вдвое, требуя удвоения длины ключей. На март 2025 года квантовые компьютеры ещё не достигли уровня, необходимого для практических атак, но прогресс в этой области (например, разработки IBM и Google) указывает на необходимость подготовки.</p>

        <h2>Перспективы</h2>
        <p>К 2030 году ожидается значительный прогресс в квантовых технологиях. QKD может стать стандартом для защиты каналов связи в банковской и военной сферах, особенно с развитием квантовых повторителей и спутниковых систем (например, китайский спутник Micius, 2016). Постквантовая криптография, такая как решётчатые схемы, будет интегрирована в TLS, VPN и другие протоколы. Однако высокая стоимость и необходимость специализированного оборудования пока ограничивают массовое внедрение.</p>

        <h2>Рекомендации</h2>
        <ul>
          <li>Используйте QKD (BB84, E91) для критически важных каналов связи с проверкой подлинности.</li>
          <li>Переходите на постквантовые алгоритмы (например, Kyber, Dilithium) для защиты данных от будущих атак.</li>
          <li>Удвойте длину ключей симметричных шифров (AES-256) для защиты от Гровера.</li>
          <li>Следите за развитием квантовых компьютеров и стандартов NIST для своевременной адаптации.</li>
        </ul>
      </div>
    </div>
  `;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadCryptographyContent(container);
  });
}

  function loadSteganographyContent(container) {
    container.innerHTML = `
      <div class="cryptography-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Стеганография</h1>
        <div class="theory-section">
          <h2>Что такое стеганография?</h2>
          <p>Стеганография — это наука и искусство скрытия информации внутри других данных (контейнеров), таких как изображения, аудио, видео или текстовые файлы, таким образом, чтобы факт наличия скрытого сообщения оставался незаметным для стороннего наблюдателя. В отличие от криптографии, которая шифрует данные, делая их нечитаемыми без ключа, стеганография скрывает само существование сообщения. Название происходит от греческих слов "steganos" (скрытый) и "graphein" (писать).</p>
          <p>Стеганография часто используется в сочетании с криптографией: сначала данные шифруются, а затем скрываются в контейнере, что повышает уровень безопасности. Исторически стеганография применялась с древних времён: в Древней Греции сообщения писали на деревянных табличках, покрытых воском, а во время Второй мировой войны шпионы использовали микроточки (уменьшенные фотографии) для передачи секретных данных.</p>

          <h2>Принцип работы стеганографии</h2>
          <p>Стеганография работает путем внедрения данных в контейнер с минимальными изменениями, которые не воспринимаются человеческими органами чувств. Основная цель — сохранить естественный вид контейнера, чтобы он не вызывал подозрений. Например, в изображении можно изменять младшие биты пикселей, в аудио — незначительные изменения частот, а в тексте — невидимые символы или форматирование.</p>
          <p>Процесс включает несколько этапов: выбор контейнера, преобразование данных в битовый поток, внедрение данных в контейнер и маскировка изменений. Контейнер должен обладать достаточной "избыточностью" (redundancy), чтобы вместить скрытые данные без заметных искажений. Например, изображения в формате BMP имеют больше избыточности, чем сжатые JPEG, что делает их более подходящими для стеганографии.</p>
          <p>Теоретически стеганография основывается на концепции информационной энтропии: изменения в контейнере должны быть статистически незначимыми, чтобы не выделяться при анализе. Однако эффективность метода зависит от баланса между объемом скрытых данных (емкостью), незаметностью (robustness) и устойчивостью к обработке контейнера (resilience).</p>
          <p>Ниже представлена схема процесса скрытия данных с помощью стеганографии:</p>
          <div class="scheme-frame" style="border: 2px solid #444; border-radius: 8px; padding: 20px; background-color: #05060a; display: flex; justify-content: center; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
            <div class="stego-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Процесс стеганографии</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #8e24aa; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Исходные данные
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст, файл или шифротекст.</p>
                </div>
                <div style="background-color: #ab47bc; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Выбор контейнера
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изображение, аудио, видео.</p>
                </div>
                <div style="border: 2px solid #ce93d8; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #ce93d8; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Внедрение данных
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изменение битов, частот и т.д.</p>
                  </div>
                  <div style="background-color: #ab47bc; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Маскировка изменений
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Сохранение естественного вида.</p>
                  </div>
                </div>
                <div style="background-color: #8e24aa; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Передача контейнера
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Отправка получателю.</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Извлечение</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Получатель извлекает данные.</p>
                </div>
              </div>
            </div>
          </div>

          <h2>Методы стеганографии</h2>
          <div class="stego-method">
            <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
              <div class="stego-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                <h3>LSB (Least Significant Bit)</h3>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                  <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Исходные данные
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст или шифротекст</p>
                  </div>
                  <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Контейнер (BMP/WAV)
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выбор носителя</p>
                  </div>
                  <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Замена LSB
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Младшие биты</p>
                  </div>
                  <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Итоговый файл
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Скрытые данные</p>
                  </div>
                </div>
              </div>
              <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
              <div style="flex: 1; padding: 15px;">
                <h3>LSB (Least Significant Bit)</h3>
                <p>Метод LSB (Least Significant Bit) заключается во внедрении данных в младшие биты пикселей изображения или аудиосэмплов. Например, в изображении каждый пиксель представлен значениями RGB (красный, зелёный, синий), где каждый канал занимает 8 бит. Изменение младшего бита (например, с 0 на 1) практически не влияет на визуальное восприятие цвета.</p>
                <p><strong>Пример использования:</strong> Этот метод часто применяется для скрытия текста в файлах формата BMP или WAV, где избыточность данных позволяет вместить значительный объем информации.</p>
                <p><strong>Преимущества:</strong> Простота реализации и незаметность изменений для человеческого глаза или уха делают LSB популярным выбором.</p>
                <p><strong>Недостатки:</strong> Однако метод уязвим к сжатию (например, преобразование изображения в JPEG уничтожает скрытые данные), а также к обработке, которая изменяет младшие биты.</p>
                <p><strong>Поиск (стегоанализ):</strong> Обнаружение LSB возможно через статистический анализ младших битов (например, построение гистограмм или использование χ²-теста). Также визуальные аномалии могут стать заметными при усилении контраста изображения.</p>
              </div>
            </div>
          </div>

          <div class="stego-method">
            <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
              <div class="stego-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                <h3>Эхо-скрытие</h3>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                  <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Исходные данные
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст или биты</p>
                  </div>
                  <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Аудиофайл
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выбор носителя</p>
                  </div>
                  <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Модуляция эха
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Изменение задержек</p>
                  </div>
                  <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Итоговый аудио
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Скрытые данные</p>
                  </div>
                </div>
              </div>
              <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
              <div style="flex: 1; padding: 15px;">
                <h3>Эхо-скрытие</h3>
                <p>Эхо-скрытие — это метод изменения эха в аудиофайлах для кодирования данных. Данные внедряются путём модуляции параметров эха (например, задержки или амплитуды), которые остаются незаметными для человеческого слуха при правильной настройке.</p>
                <p><strong>Пример использования:</strong> Метод подходит для скрытия сообщений в музыкальных треках или голосовых записях.</p>
                <p><strong>Преимущества:</strong> Эхо-скрытие устойчиво к некоторым видам анализа, так как изменения эха сложнее обнаружить без специализированных инструментов.</p>
                <p><strong>Недостатки:</strong> Ограниченная емкость (мало данных можно спрятать) и сложность реализации являются основными минусами.</p>
                <p><strong>Поиск (стегоанализ):</strong> Обнаружение возможно через анализ спектра эха для выявления аномальных задержек или сравнение с оригинальным звуком, если он доступен.</p>
              </div>
            </div>
          </div>

          <div class="stego-method">
            <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
              <div class="stego-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                <h3>Скрытие в метаданных</h3>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                  <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Исходные данные
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст или файл</p>
                  </div>
                  <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Файл-носитель
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фото, аудио</p>
                  </div>
                  <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Вставка в метаданные
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">EXIF/ID3</p>
                  </div>
                  <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Итоговый файл
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Скрытые данные</p>
                  </div>
                </div>
              </div>
              <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
              <div style="flex: 1; padding: 15px;">
                <h3>Скрытие в метаданных</h3>
                <p>Скрытие в метаданных предполагает использование метаданных файлов (например, EXIF для изображений или ID3 для аудио) для хранения данных. Метаданные — это дополнительная информация о файле, такая как дата создания или автор, которая не влияет на основное содержимое.</p>
                <p><strong>Пример использования:</strong> Метод часто применяется для внедрения текста в EXIF-раздел фотографий, снятых цифровыми камерами.</p>
                <p><strong>Преимущества:</strong> Простота реализации и высокая емкость делают этот метод удобным для хранения больших объемов данных.</p>
                <p><strong>Недостатки:</strong> Однако он легко обнаруживается при анализе метаданных, так как они не защищены от просмотра.</p>
                <p><strong>Поиск (стегоанализ):</strong> Обнаружение осуществляется через извлечение и анализ метаданных с помощью инструментов вроде ExifTool, а также проверку подозрительных или нестандартных полей.</p>
              </div>
            </div>
          </div>

          <div class="stego-method">
            <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
              <div class="stego-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                <h3>Стеганография в тексте</h3>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                  <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Исходные данные
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст или биты</p>
                  </div>
                  <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Текстовый файл
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выбор носителя</p>
                  </div>
                  <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Невидимые символы
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Пробелы, Unicode</p>
                  </div>
                  <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Итоговый текст
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Скрытые данные</p>
                  </div>
                </div>
              </div>
              <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
              <div style="flex: 1; padding: 15px;">
                <h3>Стеганография в тексте</h3>
                <p>Стеганография в тексте использует невидимые символы (например, нулевые пробелы Unicode), вариации пробелов или изменения шрифтов для скрытия данных в текстовых документах. Например, данные могут кодироваться в последовательности пробелов между словами.</p>
                <p><strong>Пример использования:</strong> Метод подходит для скрытия данных в PDF или Word документах, где текст выглядит обычным.</p>
                <p><strong>Преимущества:</strong> Незаметность без специального анализа делает этот метод простым и эффективным в определённых сценариях.</p>
                <p><strong>Недостатки:</strong> Малая емкость (ограниченный объем данных) и уязвимость к копированию или форматированию текста — основные ограничения.</p>
                <p><strong>Поиск (стегоанализ):</strong> Обнаружение возможно через анализ кодировки для поиска невидимых символов или Unicode-аномалий, а также визуализацию пробелов и скрытых элементов.</p>
              </div>
            </div>
          </div>

          <div class="stego-method">
            <div class="stego-method-container" style="display: flex; align-items: stretch; gap: 20px; margin-bottom: 20px;">
              <div class="stego-diagram" style="flex: 0 0 250px; padding: 15px; border-radius: 8px; text-align: center; background-color: #05060a;">
                <h3>DCT (Discrete Cosine Transform)</h3>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 8px;">
                  <div style="background-color: #8e24aa; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Исходные данные
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Текст или биты</p>
                  </div>
                  <div style="background-color: #ab47bc; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    JPEG-изображение
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Выбор носителя</p>
                  </div>
                  <div style="background-color: #ce93d8; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Изменение DCT
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Коэффициенты</p>
                  </div>
                  <div style="background-color: #2a2f3b; padding: 8px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                    Итоговый JPEG
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Скрытые данные</p>
                  </div>
                </div>
              </div>
              <div style="flex: 0 0 1px; background-color: #444; height: auto;"></div>
              <div style="flex: 1; padding: 15px;">
                <h3>DCT (Discrete Cosine Transform)</h3>
                <p>DCT (Discrete Cosine Transform) — это метод внедрения данных в коэффициенты дискретного косинусного преобразования, используемые в сжатых изображениях, таких как JPEG. Данные скрываются в частотных компонентах изображения, что делает их устойчивыми к сжатию.</p>
                <p><strong>Пример использования:</strong> Метод применяется для скрытия данных в JPEG-файлах, широко используемых в интернете.</p>
                <p><strong>Преимущества:</strong> Устойчивость к сжатию делает DCT подходящим для современных форматов изображений.</p>
                <p><strong>Недостатки:</strong> Сложность реализации и возможные визуальные артефакты при неправильной настройке — основные проблемы.</p>
                <p><strong>Поиск (стегоанализ):</strong> Обнаружение возможно через анализ DCT-коэффициентов для выявления статистических отклонений или обнаружение артефактов сжатия при визуальном анализе.</p>
              </div>
            </div>
          </div>

          <h2>Роль стеганографии в информационной безопасности</h2>
          <p>Стеганография играет важную роль в информационной безопасности, дополняя криптографию:</p>
          <ul>
            <li><strong>Скрытность переписки:</strong> В условиях цензуры или слежки стеганография позволяет передавать сообщения незаметно. Например, в 2010-х годах активисты использовали стеганографию для передачи данных через изображения в социальных сетях в странах с ограниченным интернетом.</li>
            <li><strong>Защита от обнаружения:</strong> Даже если криптографическое сообщение перехвачено, противник может не знать о его существовании, если оно скрыто в контейнере.</li>
            <li><strong>Водяные знаки:</strong> Стеганография используется для внедрения цифровых водяных знаков в медиафайлы для защиты авторских прав (например, в фильмах или музыке).</li>
            <li><strong>Кибератаки:</strong> Злоумышленники применяют стеганографию для передачи вредоносного кода или данных через изображения на сайтах, обходя фильтры безопасности.</li>
          </ul>
          <p>Пример из практики: В 2021 году исследователи обнаружили, что хакеры использовали стеганографию в PNG-файлах, загруженных на форумы, для передачи команд управления ботнетами, что затрудняло их обнаружение антивирусами.</p>

          <h2>Вызовы и ограничения</h2>
          <ul>
            <li><strong>Обнаружение (стегоанализ):</strong> Современные методы анализа (например, статистический анализ или машинное обучение) могут выявить скрытые данные.</li>
            <li><strong>Емкость:</strong> Объем данных, который можно спрятать, ограничен размером контейнера.</li>
            <li><strong>Устойчивость:</strong> Сжатие, обрезка или обработка контейнера (например, изображения) могут уничтожить скрытые данные.</li>
          </ul>

          <h2>Перспективы</h2>
          <p>С развитием технологий стеганография становится всё более сложной. Ожидается, что к 2030 году методы на основе искусственного интеллекта позволят создавать более устойчивые и незаметные способы скрытия данных, что найдет применение как в защите информации, так и в киберпреступности.</p>
        </div>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadCryptographyContent(container);
    });
}
