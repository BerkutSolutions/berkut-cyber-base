function loadSocialEngineeringContent(contentArea) {
    const initialContent = `
      <div class="social-engineering-container">
        <h1>Социальная инженерия</h1>
        <div class="social-engineering-description">
          <p><strong>Социальная инженерия</strong> — это методика манипуляции людьми, направленная на получение доступа к конфиденциальной информации, системам или ресурсам путем обмана. Злоумышленники эксплуатируют человеческую психологию, а не технические уязвимости, чтобы добиться своих целей. Такие атаки часто используются для кражи данных, финансовых мошенничеств или подготовки более сложных кибератак.</p>
          <p>Цель этого раздела — помочь понять, как действуют злоумышленники, и предоставить практические рекомендации для защиты, чтобы минимизировать риски.</p>
        </div>

        <div class="social-engineering-description">
          <h2>Как работает социальная инженерия</h2>
          <p>Злоумышленники используют психологические приемы, чтобы манипулировать жертвами. Они могут представляться доверенными лицами (например, сотрудниками ИТ-отдела, руководством или службой поддержки), создавать ситуации стресса или срочности, а также эксплуатировать доверие, страх или желание помочь. Основные методы включают:</p>
          <ul>
            <li><strong>Фишинг:</strong> Отправка поддельных писем, сообщений в мессенджерах или СМС, которые выглядят как официальные (например, от банка или коллеги). Письма могут содержать ссылки на поддельные сайты для ввода учетных данных или вложения с вредоносным ПО.</li>
            <li><strong>Вишинг:</strong> Телефонные звонки, где злоумышленник представляется сотрудником компании, банка или госоргана, чтобы выманить пароли, коды подтверждения или другую информацию.</li>
            <li><strong>Смишинг:</strong> Использование SMS-сообщений для обмана, часто с ссылками на фишинговые сайты или с просьбой перезвонить по поддельному номеру.</li>
            <li><strong>Претестинг:</strong> Создание вымышленного сценария, чтобы убедить жертву раскрыть информацию (например, злоумышленник представляется аудитором и запрашивает доступ к данным).</li>
            <li><strong>Физический доступ:</strong> Проникновение в офис под видом сотрудника, курьера или технического специалиста, чтобы получить доступ к системам или данным.</li>
            <li><strong>Подбрасывание устройств:</strong> Оставление зараженных USB-накопителей или других устройств в общественных местах (например, в офисе), рассчитывая, что кто-то их подключит.</li>
          </ul>

          <h2>Схемы: процесс атаки и последствия</h2>
          <p>Ниже представлены две схемы: первая показывает, как злоумышленник устанавливает контакт и проводит атаку, вторая — возможные последствия успешной атаки. Каждая схема сопровождается рекомендациями по защите.</p>

          <div class="scheme-frame" style="border: 2px solid #444; border-radius: 8px; padding: 20px; background-color: #05060a; display: flex; justify-content: space-around; align-items: stretch; gap: 40px; position: relative; overflow-x: auto; white-space: nowrap;">
            <div class="social-engineering-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Процесс атаки</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Сбор информации
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">OSINT: соцсети, сайты, утечки данных.</p>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: ограничьте публичный доступ к данным.</p>
                </div>
                <div style="border: 2px solid #ef5350; padding: 10px; border-radius: 5px; width: 250px;">
                  <div id="se-contact" style="background-color: #ef5350; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Установление контакта
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Фишинг, вишинг, поддельные аккаунты.</p>
                    <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: проверяйте отправителя, не доверяйте.</p>
                  </div>
                  <div style="background-color: #f44336; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Манипуляция
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Срочность, страх, доверие.</p>
                    <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: игнорируйте давление, уточняйте запрос.</p>
                  </div>
                </div>
                <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Получение данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Пароли, доступ, файлы.</p>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: не раскрывайте данные, используйте MFA.</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Результат</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Доступ к системам, утечка данных.</p>
                </div>
              </div>
            </div>
            <div class="social-engineering-diagram" style="flex: 0 0 auto; min-width: 250px; padding: 20px; border-radius: 8px; text-align: center; background-color: #05060a;">
              <h3>Последствия атаки</h3>
              <div style="display: flex; flex-direction: column; align-items: center; gap: 10px;">
                <div id="se-impact" style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Утечка данных
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Персональные данные, коммерческая тайна.</p>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: шифруйте данные, ограничьте доступ.</p>
                </div>
                <div style="border: 2px solid #ef5350; padding: 10px; border-radius: 5px; width: 250px;">
                  <div style="background-color: #ef5350; padding: 5px; border-radius: 5px; white-space: normal; word-wrap: break-word;">
                    Финансовые потери
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Мошеннические переводы, вымогательство.</p>
                    <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: проверяйте платежи, внедрите DLP.</p>
                  </div>
                  <div style="background-color: #f44336; padding: 5px; border-radius: 5px; margin-top: 5px; white-space: normal; word-wrap: break-word;">
                    Репутационный ущерб
                    <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Утрата доверия клиентов, партнеров.</p>
                    <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: реагируйте быстро, информируйте.</p>
                  </div>
                </div>
                <div style="background-color: #d32f2f; padding: 10px; border-radius: 5px; width: 200px; white-space: normal; word-wrap: break-word;">
                  Юридические риски
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Нарушение ФЗ-152, штрафы.</p>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #ffeb3b;">Защита: соблюдайте законы, ведите аудит.</p>
                </div>
                <div style="background-color: #2a2f3b; padding: 10px; border-radius: 5px; margin-top: 10px; white-space: normal; word-wrap: break-word;">
                  <span style="font-size: 16px;">Итог</span>
                  <p style="font-size: 12px; margin: 5px 0 0; color: #fff;">Срыв работы, утрата активов.</p>
                </div>
              </div>
            </div>
            <svg id="arrows-svg" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none;">
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="0" refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="#666" />
                </marker>
              </defs>
              <path id="arrow1" stroke="#666" stroke-width="2" fill="none" marker-end="url(#arrowhead)" />
            </svg>
          </div>
          <p>Схемы показывают, как злоумышленник проводит атаку и какие могут быть последствия. На каждом этапе указаны меры защиты, чтобы минимизировать риски.</p>

          <h2>Признаки социальной инженерии</h2>
          <p>Чтобы защититься, важно уметь распознавать признаки таких атак:</p>
          <ul>
            <li>Необычная срочность или давление (например, "Подтвердите платеж прямо сейчас, иначе счет заблокируют").</li>
            <li>Подозрительные отправители (email-адреса или номера, которые отличаются от официальных, например, support@bankl.com вместо support@bank.com).</li>
            <li>Просьбы раскрыть конфиденциальную информацию (пароли, коды, данные карт).</li>
            <li>Неожиданные вложения или ссылки в письмах/сообщениях, особенно от "знакомых".</li>
            <li>Любые несоответствия в поведении или оформлении (грамматические ошибки, логотипы низкого качества, странные домены).</li>
            <li>Необоснованные просьбы о предоставлении доступа или подключении устройств.</li>
          </ul>

          <h2>Как противостоять социальной инженерии</h2>
          <p>Противодействие социальной инженерии требует сочетания технических мер, организационных процедур и обучения сотрудников. Вот ключевые рекомендации:</p>

          <h3>1. Организационные меры</h3>
          <ul>
            <li><strong>Обучение сотрудников:</strong> Проводите регулярные тренинги по информационной безопасности (раз в полгода), включая симуляции фишинговых атак, чтобы повысить осведомленность.</li>
            <li><strong>Четкие процедуры:</strong> Установите строгие правила для передачи конфиденциальной информации. Например, никогда не передавать пароли по телефону или email, даже если запрос кажется официальным.</li>
            <li><strong>Политика "нулевого доверия":</strong> Всегда проверяйте личность человека, запрашивающего доступ или информацию, даже если он представляется руководителем. Используйте внутренние каналы связи для подтверждения (например, корпоративный чат).</li>
            <li><strong>Контроль физического доступа:</strong> Внедрите пропускной режим, видеонаблюдение и контроль посетителей (регистрация, сопровождение). Запретите "тейлгейтинг" (проход за другим сотрудником).</li>
            <li><strong>Управление инцидентами:</strong> Создайте канал для быстрого сообщения о подозрительных действиях (например, email или горячая линия для отдела ИБ).</li>
          </ul>

          <h3>2. Технические меры</h3>
          <ul>
            <li><strong>Фильтрация писем:</strong> Настройте почтовые фильтры (SPF, DKIM, DMARC) для блокировки фишинговых писем. Используйте решения, такие как Microsoft Defender for Office 365 или Barracuda, для анализа вложений и ссылок.</li>
            <li><strong>Антивирус и EDR:</strong> Установите антивирусное ПО (например, Kaspersky, ESET) и системы обнаружения/реагирования (EDR), чтобы блокировать вредоносное ПО из фишинговых писем или подброшенных устройств.</li>
            <li><strong>Контроль USB-устройств:</strong> Настройте политики на рабочих станциях для запрета автозапуска USB (например, через GPO в Windows: HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices → Deny_All).</li>
            <li><strong>Многофакторная аутентификация (MFA):</strong> Внедрите MFA для всех систем (VPN, почта, внутренние порталы), чтобы даже при утечке пароля злоумышленник не получил доступ.</li>
            <li><strong>Мониторинг сети:</strong> Используйте SIEM-системы (Splunk, QRadar) для отслеживания аномального поведения, например, массовых попыток входа с одного IP.</li>
            <li><strong>Шифрование данных:</strong> Шифруйте критичные данные на устройствах и в хранилищах (BitLocker, LUKS), чтобы минимизировать ущерб при утечке.</li>
          </ul>

          <h3>3. Поведенческие меры для сотрудников</h3>
          <ul>
            <li><strong>Проверяйте отправителя:</strong> Всегда проверяйте email-адрес или номер телефона. Наведите курсор на ссылку, чтобы увидеть реальный URL, прежде чем кликать.</li>
            <li><strong>Не раскрывайте данные:</strong> Никогда не сообщайте пароли, коды MFA или другую конфиденциальную информацию по телефону, email или мессенджерам.</li>
            <li><strong>Игнорируйте срочность:</strong> Если вас торопят с решением (например, "Подтвердите платеж сейчас"), остановитесь и проверьте запрос через официальные каналы.</li>
            <li><strong>Сообщайте о подозрительном:</strong> Если получили странное письмо, звонок или заметили подозрительное устройство (например, USB в офисе), немедленно сообщите в отдел ИБ.</li>
            <li><strong>Не подключайте неизвестные устройства:</strong> Никогда не вставляйте найденные USB-накопители или другие устройства в рабочие компьютеры.</li>
            <li><strong>Используйте корпоративные каналы:</strong> Для общения с коллегами или ИТ-отделом используйте только официальные системы (например, Slack, Microsoft Teams), а не личные мессенджеры.</li>
          </ul>

          <h2>Что делать, если атака произошла</h2>
          <p>Если вы подозреваете, что стали жертвой социальной инженерии:</p>
          <ul>
            <li><strong>Немедленно сообщите:</strong> Свяжитесь с отделом ИБ через корпоративный email или горячую линию. Укажите детали: кто звонил/писал, что запрашивали, какие данные передали.</li>
            <li><strong>Смените пароли:</strong> Если могли быть скомпрометированы учетные данные, немедленно смените пароли через доверенное устройство.</li>
            <li><strong>Отключите устройство:</strong> Если подключили подозрительное устройство (например, USB), отключите его и изолируйте компьютер от сети.</li>
            <li><strong>Проверьте активность:</strong> Проверьте логи входа в системы (почта, VPN) на предмет несанкционированного доступа.</li>
            <li><strong>Сотрудничайте с ИБ:</strong> Следуйте инструкциям отдела ИБ для анализа инцидента и минимизации ущерба.</li>
          </ul>

          <h2>Примеры реальных сценариев</h2>
          <p>Вот несколько типичных ситуаций, с которыми можно столкнуться, и как на них реагировать:</p>
          <ul>
            <li><strong>Звонок от "ИТ-отдела":</strong> Вам звонит человек, представляется сотрудником ИТ, и просит сообщить пароль для "срочного обновления". <strong>Действие:</strong> Положите трубку, свяжитесь с ИТ-отделом через официальные каналы (например, корпоративный чат) и уточните, был ли запрос реальным.</li>
            <li><strong>Фишинговое письмо:</strong> Вы получили письмо от "руководителя" с просьбой перевести деньги на новый счет, приложена ссылка на форму. <strong>Действие:</strong> Проверьте email-адрес отправителя, не переходите по ссылке, свяжитесь с руководителем напрямую через корпоративный мессенджер.</li>
            <li><strong>Подозрительный посетитель:</strong> В офисе появился человек без бейджа, утверждающий, что он "новый сотрудник". <strong>Действие:</strong> Не пускайте его в помещения, сообщите охране или ответственному за безопасность, попросите предъявить документы.</li>
          </ul>

          <h2>Рекомендации по внедрению защиты</h2>
          <ul>
            <li>Создайте корпоративную культуру осведомленности: регулярно напоминайте сотрудникам о рисках социальной инженерии (рассылки, плакаты, тренинги).</li>
            <li>Проводите тесты: организуйте контролируемые фишинговые кампании, чтобы проверить готовность сотрудников и выявить слабые места.</li>
            <li>Обновляйте политики ИБ: включите разделы о противодействии социальной инженерии в ЛНА и ЛНД (например, правила проверки запросов, запрет передачи данных).</li>
            <li>Используйте автоматизацию: внедрите системы, которые автоматически блокируют подозрительные действия (DLP, антивирусы, фильтры).</li>
            <li>Сотрудничайте с экспертами: привлекайте специалистов по ИБ для разработки стратегий защиты и реагирования.</li>
          </ul>
        </div>
      </div>
    `;
    contentArea.innerHTML = initialContent;

    function drawArrows() {
      const schemeFrame = document.querySelector('.scheme-frame');
      if (!schemeFrame) {
        console.warn('Scheme frame not found.');
        return;
      }

      const seContact = document.getElementById('se-contact');
      const seImpact = document.getElementById('se-impact');

      if (!seContact || !seImpact) {
        console.warn('One or more elements for arrows not found.');
        return;
      }

      const frameRect = schemeFrame.getBoundingClientRect();
      const contactRect = seContact.getBoundingClientRect();
      const impactRect = seImpact.getBoundingClientRect();

      const startX1 = contactRect.right - frameRect.left;
      const startY1 = (contactRect.top + contactRect.bottom) / 2 - frameRect.top;
      const endX1 = impactRect.left - frameRect.left;
      const endY1 = (impactRect.top + impactRect.bottom) / 2 - frameRect.top;

      const arrow1 = document.getElementById('arrow1');
      const controlX1 = startX1 + (endX1 - startX1) / 2;
      const controlY1 = startY1;
      const controlX2 = controlX1;
      const controlY2 = endY1;
      arrow1.setAttribute('d', `M${startX1},${startY1} C${controlX1},${controlY1} ${controlX2},${controlY2} ${endX1},${endY1}`);
    }

    function debounce(func, wait) {
      let timeout;
      return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
      };
    }

    const debouncedDrawArrows = debounce(drawArrows, 100);

    setTimeout(drawArrows, 100);

    window.addEventListener('resize', debouncedDrawArrows);

    document.querySelector('.scheme-frame').addEventListener('scroll', debouncedDrawArrows);
}