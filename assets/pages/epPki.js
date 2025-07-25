// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0.

function loadEpPkiContent(container) {
  container.innerHTML = `
    <div class="ep-pki-container">
      <h1>ЭП и PKI</h1>
      <p>Электронная подпись (ЭП) и инфраструктура открытых ключей (PKI) — это ключевые технологии для обеспечения безопасности данных, аутентификации и конфиденциальности в цифровой среде. Здесь представлены основные аспекты, связанные с ЭП и PKI.</p>

      <!-- Аккордеон для таблиц -->
      <div class="accordion">
        <!-- Электронная подпись (ЭП) -->
        <div class="accordion-item">
          <button class="accordion-header">Электронная подпись (ЭП)</button>
          <div class="accordion-content">
            <div class="osi-table-container">
              <table class="osi-table">
                <thead>
                  <tr>
                    <th>Компонент</th>
                    <th>Описание</th>
                    <th>Пример работы</th>
                    <th>Методы защиты/Рекомендации</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Электронная подпись</td>
                    <td>Цифровой аналог подписи для подтверждения подлинности документа и целостности.</td>
                    <td>1. Хэширование документа (SHA-256).<br>2. Шифрование хэша закрытым ключом.<br>3. Прикрепление хэша к документу.</td>
                    <td>Хранить закрытый ключ в безопасном месте (HSM), использовать алгоритмы (RSA, ECDSA).</td>
                  </tr>
                  <tr>
                    <td>Электронный сертификат</td>
                    <td>Электронный документ, подтверждающий связь открытого ключа с владельцем.</td>
                    <td>Верификация в HTTPS-соединении (сайта).</td>
                    <td>Проверять срок действия сертификата, использовать надежные CA, CRL/OCSP.</td>
                  </tr>
                  <tr>
                    <td>Хэширование</td>
                    <td>Проверочная целостность (хэш) для проверки целостности файла.</td>
                    <td>256, SHA-3, хэш уникален для проверки целостности.</td>
                    <td>Использовать устойчивые алгоритмы (SHA-256), избегать устаревших (MD5, SHA-1).</td>
                  </tr>
                  <tr>
                    <td>Асимметричное шифрование</td>
                    <td>Использование пары ключей (публичный и закрытый) для шифрования/расшифровки.</td>
                    <td>Открытый ключ шифрует документ, получатель расшифровывает закрытым.</td>
                    <td>Обеспечить безопасность закрытого ключа, использовать алгоритмы шифрования (RSA 2048+).</td>
                  </tr>
                  <tr>
                    <td>Симметричное шифрование</td>
                    <td>Использование одного ключа для шифрования и расшифровки, а не подписи.</td>
                    <td>Шифрование данных с ЭП, частое в AES, часто в связке с ЭП.</td>
                    <td>Использовать алгоритмы (AES-256), обозначить способность обновления ключей (через PKI).</td>
                  </tr>
                  <tr>
                    <td>S/MIME</td>
                    <td>Протокол для шифрования и подписи электронных писем.</td>
                    <td>Шифрованное email-сообщение с S/MIME.</td>
                    <td>Использовать S/MIME с надежными сертификатами.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Принципы работы ЭП и PKI -->
        <div class="accordion-item">
          <button class="accordion-header">Принципы работы ЭП и PKI</button>
          <div class="accordion-content">
            <div class="osi-table-container">
              <table class="osi-table">
                <thead>
                  <tr>
                    <th>Процесс</th>
                    <th>Описание</th>
                    <th>Пример</th>
                    <th>Уязвимости и защита</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Создание ЭП</td>
                    <td>Подписание документа для подтверждения его подлинности и целостности.</td>
                    <td>1. Хэширование документа (SHA-256).<br>2. Шифрование хэша закрытым ключом.<br>3. Прикрепление ЭП к документу в PDF-документе (Adobe Acrobat).</td>
                    <td>Уязвимость: Компрометация закрытого ключа. Защита: Хранить ключ в HSM, использовать MFA.</td>
                  </tr>
                  <tr>
                    <td>Проверка ЭП</td>
                    <td>Проверка подлинности и открытого ключа.</td>
                    <td>1. Извлечение ЭП и открытого ключа.<br>2. Расшифровка ЭП открытым ключом.<br>3. Сравнение хэша с новым хэшем документа.</td>
                    <td>Уязвимость: Подмена сертификата в электронной почте (S/MIME).</td>
                  </tr>
                  <tr>
                    <td>Выпуск сертификата от CA</td>
                    <td>Процесс получения цифрового сертификата.</td>
                    <td>1. Генерация пары ключей.<br>2. Создание CSR (Certificate Signing Request).<br>3. Отправка CSR в CA.<br>4. Получение SSL-сертификата.</td>
                    <td>Уязвимость: Поддельный CSR. Защита: Проверять запросы перед RA, использовать EV-сертификаты.</td>
                  </tr>
                  <tr>
                    <td>Шифрование с PKI</td>
                    <td>Использование PKI для шифрования данных.</td>
                    <td>1. Получение открытого ключа из сертификата.<br>2. Шифрование данных открытым ключом.<br>3. Расшифровка закрытым ключом.</td>
                    <td>Уязвимость: Перехват сертификата. Защита: Использовать HTTPS для передачи сертификатов.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- Кнопки для перехода к другим разделам -->
      <div class="ep-pki-buttons">
        <button class="network-btn" id="pki-components-btn">Компоненты PKI</button>
        <button class="network-btn" id="threats-vulnerabilities-btn">Угрозы и уязвимости</button>
      </div>

      <!-- Раздел "Дополнительная информация" с теорией и историей -->
      <h2>Дополнительная информация</h2>
      <p><strong>Что такое ЭП и PKI?</strong> Электронная подпись (ЭП) — это криптографический механизм, который позволяет подтвердить подлинность и целостность документа или сообщения. Она основывается на использовании асимметричного шифрования, где пара ключей (открытый и закрытый) используется для создания и проверки подписи. Инфраструктура открытых ключей (PKI) — это система, включающая удостоверяющие центры (CA), сертификаты, ключи и протоколы, которые обеспечивают управление цифровыми сертификатами и их использование для шифрования, подписи и аутентификации.</p>
      <p>ЭП и PKI обеспечивают следующие ключевые функции:</p>
      <ul>
        <li><strong>Аутентификация:</strong> Подтверждение личности отправителя (например, через сертификат).</li>
        <li><strong>Целостность:</strong> Гарантия, что данные не были изменены (через хэширование).</li>
        <li><strong>Конфиденциальность:</strong> Шифрование данных для защиты от несанкционированного доступа.</li>
        <li><strong>Неподделываемость:</strong> Подтверждение, что подпись принадлежит отправителю и не была подделана.</li>
      </ul>

      <h3>История появления и развития ЭП и PKI</h3>
      <p>История электронной подписи и PKI тесно связана с развитием криптографии и информационной безопасности:</p>
      <ul>
        <li><strong>1970-е годы:</strong> Зарождение концепции асимметричного шифрования. В 1976 году Уитфилд Диффи и Мартин Хеллман опубликовали статью, описывающую концепцию шифрования с открытым и закрытым ключами. Это стало основой для будущих систем ЭП и PKI.</li>
        <li><strong>1978 год:</strong> Создание алгоритма RSA (Ривест, Шамир, Адлеман), который стал первым практически применимым методом асимметричного шифрования и подписи. RSA позволил создавать цифровые подписи, где закрытый ключ использовался для подписи, а открытый — для проверки.</li>
        <li><strong>1980-е годы:</strong> Появление первых стандартов для цифровых сертификатов. В 1988 году Международный союз электросвязи (ITU) разработал стандарт X.509, который стал основой для формата цифровых сертификатов, используемых в PKI.</li>
        <li><strong>1990-е годы:</strong> Рост популярности интернета и необходимость безопасного обмена данными. В 1995 году Netscape внедрила протокол SSL (Secure Sockets Layer), который использовал PKI для шифрования данных между браузером и сервером. Это стало первым массовым применением PKI. Также в 1990-х появились стандарты PKCS (Public-Key Cryptography Standards), включая PKCS #7 и PKCS #10, которые определили форматы для подписи и запросов на сертификаты.</li>
        <li><strong>2000-е годы:</strong> Расширение применения ЭП и PKI в юридической практике. В 2000 году в США был принят закон ESIGN (Electronic Signatures in Global and National Commerce Act), который придал юридическую силу электронным подписям. В России в 2002 году был принят Федеральный закон № 1-ФЗ "Об электронной цифровой подписи". PKI стала широко использоваться для защиты электронной почты (S/MIME), VPN (IPsec), и в банковских системах.</li>
        <li><strong>2010-е годы:</strong> Рост числа атак на PKI и ЭП. В 2011 году была скомпрометирована голландская CA DigiNotar, что привело к выдаче поддельных сертификатов для доменов, таких как google.com. Это показало уязвимости в системе доверия PKI. В 2013 году в России был принят закон № 63-ФЗ "Об электронной подписи", который заменил предыдущий закон и ввёл понятия квалифицированной и неквалифицированной ЭП.</li>
        <li><strong>2020-е годы:</strong> Современные вызовы. С ростом квантовых вычислений возникла угроза для традиционных алгоритмов, таких как RSA и ECDSA. В 2022 году NIST начал процесс стандартизации постквантовых алгоритмов (PQC), таких как CRYSTALS-Kyber и CRYSTALS-Dilithium, которые должны заменить уязвимые алгоритмы в будущем. PKI также стала ключевой для защиты IoT-устройств, облачных систем и блокчейн-технологий.</li>
      </ul>
      <p>Эволюция ЭП и PKI связана с развитием технологий и угроз. Если в 1970-х годах подписи использовались в основном в научных кругах, то сегодня они стали неотъемлемой частью цифровой экономики, обеспечивая безопасность онлайн-транзакций, юридических документов и коммуникаций.</p>

      <h3>Современные вызовы и тренды</h3>
      <p>ЭП и PKI сталкиваются с новыми вызовами:</p>
      <ul>
        <li><strong>Квантовые вычисления:</strong> Алгоритмы RSA и ECDSA могут быть взломаны квантовыми компьютерами (алгоритм Шора). Решение — переход на постквантовые алгоритмы.</li>
        <li><strong>Атаки на CA:</strong> Компрометация удостоверяющих центров (как в случае DigiNotar) может привести к массовым атакам. Решение — внедрение Certificate Transparency (CT) для мониторинга сертификатов.</li>
        <li><strong>Рост числа устройств:</strong> IoT-устройства часто не имеют достаточной защиты, что делает их уязвимыми для атак. PKI помогает, но требует автоматизации управления сертификатами.</li>
        <li><strong>Юридические аспекты:</strong> Разные страны имеют разные стандарты для юридической силы ЭП, что затрудняет международное использование.</li>
        <li><strong>Автоматизация:</strong> С ростом числа сертификатов (например, для HTTPS) требуется автоматизация их выпуска и обновления (например, через Let’s Encrypt).</li>
      </ul>
      <p>ЭП и PKI продолжают развиваться, адаптируясь к новым угрозам и технологиям, оставаясь основой для обеспечения доверия в цифровом мире.</p>
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

  document.getElementById('pki-components-btn').addEventListener('click', () => {
      loadPkiComponentsContent(container);
  });

  document.getElementById('threats-vulnerabilities-btn').addEventListener('click', () => {
      loadThreatsVulnerabilitiesContent(container);
  });

}

function loadPkiComponentsContent(container) {
  container.innerHTML = `
    <div class="ep-pki-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Компоненты PKI</h1>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Компонент</th>
              <th>Описание</th>
              <th>Роль в PKI</th>
              <th>Пример</th>
              <th>Методы защиты/Рекомендации</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Удостоверяющий центр (CA)</td>
              <td>Организация, выпускающая цифровые сертификаты, подтверждающие подлинность.</td>
              <td>Выдает сертификаты, подтверждает их срок действия через списки отозванных сертификатов (CRL).</td>
              <td>Выпуск SSL-сертификата для сайта (Let’s Encrypt).</td>
              <td>Использовать надежные CA, проверять репутацию, регулярно обновлять корневые сертификаты.</td>
            </tr>
            <tr>
              <td>Регистрационный центр (RA)</td>
              <td>Подтверждает заявки на сертификаты, связывает сертификаты с владельцем.</td>
              <td>Передает данные в CA для выпуска сертификата, подтверждает подлинность клиента CRL, отзывает сертификаты.</td>
              <td>Проверка компании перед выдачей EV-сертификата.</td>
              <td>Обеспечить безопасность RA, аутентификация для доступа, регулярно обновлять CRL.</td>
            </tr>
            <tr>
              <td>Список отозванных сертификатов (CRL)</td>
              <td>Список отозванных сертификатов, которые больше не считаются доверенными.</td>
              <td>Клиенты проверяют статус сертификата по списку CRL, не отозван ли он.</td>
              <td>Проверка сертификата в браузере.</td>
              <td>Использовать OCSP/CRL, настроить OCSP Stapling для повышения производительности.</td>
            </tr>
            <tr>
              <td>OCSP (Online Certificate Status Protocol)</td>
              <td>Протокол для проверки статуса сертификата в реальном времени.</td>
              <td>Клиенты отправляют запрос к OCSP-серверу, чтобы узнать статус сертификата (действителен/отозван).</td>
              <td>Проверка сертификата в браузере (через OCSP).</td>
              <td>Настройка OCSP Stapling для повышения производительности, защитить OCSP-серверы от атак.</td>
            </tr>
            <tr>
              <td>Хранилище сертификатов</td>
              <td>Место хранения сертификатов и ключей на устройстве пользователя.</td>
              <td>Хранит корневые сертификаты CA, промежуточные сертификаты, используемые браузером.</td>
              <td>Хранение сертификатов в Windows (certmgr.msc).</td>
              <td>Ограничить доступ к хранилищу, использовать HSM для хранения ключей.</td>
            </tr>
            <tr>
              <td>HSM (Hardware Security Module)</td>
              <td>Аппаратный модуль для безопасного хранения ключей и выполнения криптографических операций.</td>
              <td>Генерирует, хранит и подписывает ключи в безопасной среде.</td>
              <td>Хранение закрытого ключа CA в HSM.</td>
              <td>Использовать HSM (FIPS 140-2), ограничить физический доступ.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="theory-section">
        <p>Инфраструктура открытых ключей (PKI) представляет собой сложную систему, состоящую из множества компонентов, которые взаимодействуют для обеспечения безопасности цифровых коммуникаций. Каждый компонент выполняет свою уникальную роль, обеспечивая доверие, аутентификацию и защиту данных.</p>
        <p><strong>Удостоверяющий центр (CA)</strong> является основой PKI, так как он отвечает за выпуск цифровых сертификатов, которые связывают открытый ключ с конкретным субъектом (например, человеком, организацией или сервером). CA подтверждает подлинность субъекта, что делает его доверенной третьей стороной. Однако компрометация CA (как в случае с DigiNotar в 2011 году) может подорвать доверие ко всей системе, поэтому выбор надёжного CA и регулярное обновление корневых сертификатов критически важны.</p>
        <p><strong>Регистрационный центр (RA)</strong> выступает посредником между субъектом и CA, проверяя заявки на сертификаты. RA играет важную роль в предотвращении выдачи поддельных сертификатов, особенно для расширенной проверки (EV-сертификатов), где требуется тщательная верификация организации. Безопасность RA должна быть на высоком уровне, так как его компрометация может привести к выдаче поддельных сертификатов.</p>
        <p><strong>Список отозванных сертификатов (CRL)</strong> и <strong>OCSP</strong> обеспечивают механизм проверки статуса сертификатов. CRL — это список, который публикуется CA и содержит информацию об отозванных сертификатах, но его использование может быть неэффективным из-за больших объёмов данных и задержек обновления. OCSP решает эту проблему, предоставляя проверку в реальном времени, но требует надёжной инфраструктуры, чтобы избежать атак типа "отказ в обслуживании" (DDoS) на OCSP-серверы. Современные системы часто используют OCSP Stapling, чтобы снизить нагрузку на серверы и повысить производительность.</p>
        <p><strong>Хранилище сертификатов</strong> на устройствах пользователей (например, в браузерах или операционных системах) содержит доверенные корневые и промежуточные сертификаты. Неправильное управление хранилищем (например, добавление поддельного корневого сертификата) может привести к серьёзным уязвимостям, таким как подмена сертификатов в MITM-атаках.</p>
        <p><strong>HSM (Hardware Security Module)</strong> обеспечивает физическую и логическую защиту закрытых ключей, что особенно важно для CA и организаций, работающих с критически важными данными. HSM соответствует строгим стандартам безопасности (например, FIPS 140-2) и предотвращает утечку ключей даже в случае компрометации системы.</p>
        <p>Все компоненты PKI должны работать в тесной связке, чтобы обеспечить безопасность. Однако их эффективность зависит от правильной настройки, регулярного обновления и защиты от атак. Например, автоматизация управления сертификатами (как в случае с Let’s Encrypt) упрощает процесс, но требует дополнительных мер для предотвращения злоупотреблений.</p>
      </div>
    </div>
  `;

  document.querySelector('.back-btn').addEventListener('click', () => {
      loadEpPkiContent(container);
  });
}

function loadThreatsVulnerabilitiesContent(container) {
  container.innerHTML = `
    <div class="ep-pki-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Угрозы и уязвимости</h1>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Угроза/Уязвимость</th>
              <th>Описание</th>
              <th>Пример</th>
              <th>Связь с ЭП/PKI</th>
              <th>Методы устранения</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Компрометация ключей</td>
              <td>Несанкционированный доступ к закрытому ключу, что позволяет подделать ЭП или расшифровать данные.</td>
              <td>Ключ хранится в незащищённой базе данных.</td>
              <td>Поддельная ЭП, выдача поддельных сертификатов.</td>
              <td>Хранить ключи в HSM, использовать MFA, регулярно обновлять ключи (HSM).</td>
            </tr>
            <tr>
              <td>Подмена сертификата</td>
              <td>Злоумышленник подменяет сертификат, чтобы выдать себя за доверенную сторону.</td>
              <td>MITM-атака.</td>
              <td>Обман пользователей (например, фишинг).</td>
              <td>Использовать сертификаты CA, Certificate Transparency (CT), мониторинг сертификатов.</td>
            </tr>
            <tr>
              <td>Уязвимости в CA</td>
              <td>Использование устаревших алгоритмов (MD5, SHA-1), которые уязвимы к коллизиям.</td>
              <td>В 2011 году DigiNotar был взломан, что позволило выпустить поддельные сертификаты Google.</td>
              <td>Компрометация системы доверия PKI.</td>
              <td>Использовать современные алгоритмы (SHA-256, ECDSA), избегать устаревших (MD5, SHA-1).</td>
            </tr>
            <tr>
              <td>Атака на CA или OCSP</td>
              <td>Злоумышленники атакуют удостоверяющий центр или OCSP-сервер, чтобы выдать поддельные сертификаты или блокировать проверку.</td>
              <td>Компрометация DigiNotar в 2011 году; выдача поддельных сертификатов.</td>
              <td>Поддельные сертификаты.</td>
              <td>Использовать OCSP Stapling, ресурсы OCSP-серверов, мониторинг сертификатов.</td>
            </tr>
            <tr>
              <td>Шифрование с PKI</td>
              <td>Использование устаревших алгоритмов (RSA 1024).</td>
              <td>Использование устаревших алгоритмов (RSA 2048+).</td>
              <td>Перехват сертификатов (через PKI).</td>
              <td>Использовать алгоритмы (AES-256), обеспечить обмен ключами (через PKI).</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="theory-section">
        <p>Системы ЭП и PKI, несмотря на свою надёжность, подвержены различным угрозам и уязвимостям, которые могут подорвать их безопасность. Эти угрозы связаны как с техническими аспектами (например, использование устаревших алгоритмов), так и с организационными (например, компрометация удостоверяющих центров). Понимание этих уязвимостей и методов их устранения критически важно для обеспечения безопасности цифровых коммуникаций.</p>
        <p><strong>Компрометация ключей</strong> — одна из самых серьёзных угроз, так как закрытый ключ является основой безопасности ЭП. Если злоумышленник получает доступ к закрытому ключу, он может подделывать подписи, выдавать поддельные сертификаты или расшифровывать конфиденциальные данные. Часто это происходит из-за небезопасного хранения ключей (например, в обычных файлах или базах данных). Использование HSM и многофакторной аутентификации (MFA) значительно снижает этот риск.</p>
        <p><strong>Подмена сертификата</strong> используется в атаках типа "человек посередине" (MITM), где злоумышленник подменяет легитимный сертификат на поддельный, чтобы выдать себя за доверенную сторону. Это может привести к фишинговым атакам или краже данных. Certificate Transparency (CT) помогает бороться с этой угрозой, позволяя отслеживать все выданные сертификаты и выявлять поддельные.</p>
        <p><strong>Уязвимости в CA</strong> связаны с использованием устаревших алгоритмов, таких как MD5 или SHA-1, которые уязвимы к атакам на коллизии. Исторический пример — взлом DigiNotar в 2011 году, когда злоумышленники смогли выпустить поддельные сертификаты для доменов, таких как google.com. Это подорвало доверие к PKI и показало важность использования современных алгоритмов (например, SHA-256, ECDSA) и строгого контроля над CA.</p>
        <p><strong>Атаки на CA или OCSP</strong> могут привести к выдаче поддельных сертификатов или блокировке проверки их статуса. Например, компрометация OCSP-сервера может позволить злоумышленнику скрыть факт отзыва сертификата, что сделает поддельный сертификат "доверенным". Использование OCSP Stapling (включение ответа OCSP в TLS-соединение) и мониторинг сертификатов помогают минимизировать этот риск.</p>
        <p><strong>Устаревшие алгоритмы шифрования</strong>, такие как RSA с ключами менее 2048 бит, становятся уязвимыми с развитием вычислительных мощностей и квантовых технологий. Например, алгоритм Шора на квантовом компьютере может эффективно факторизовать большие числа, что делает RSA небезопасным. Переход на более надёжные алгоритмы (например, AES-256 для симметричного шифрования и ECDSA для подписи) и внедрение постквантовых алгоритмов (PQC) — ключевые шаги для защиты PKI в будущем.</p>
        <p>Для минимизации угроз в ЭП и PKI важно не только использовать современные технологии, но и внедрять комплексный подход к безопасности: регулярное обновление алгоритмов, мониторинг сертификатов, обучение персонала и автоматизация процессов управления ключами и сертификатами. Только так можно обеспечить надёжность системы в условиях постоянно эволюционирующих киберугроз.</p>
      </div>
    </div>
  `;

  document.querySelector('.back-btn').addEventListener('click', () => {
      loadEpPkiContent(container);
  });
}
