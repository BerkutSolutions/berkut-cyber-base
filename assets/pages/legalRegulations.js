function loadLegalRegulationsContent(container) {
    container.innerHTML = `
      <div class="legal-regulations-container">
        <h1>Правовые нормы</h1>
        <p>Правовые нормы в области защиты информации играют ключевую роль в обеспечении безопасности данных, систем и инфраструктуры. Они устанавливают обязательные требования к защите информации, включая персональные данные, государственную тайну, критическую информационную инфраструктуру (КИИ) и другие категории. В этом разделе рассматриваются основные аспекты правового регулирования защиты информации, включая российские и международные стандарты.</p>
  
        <h2>Разделы правового регулирования</h2>
        <p>Выберите раздел для подробного изучения:</p>
        <div class="legal-regulations-buttons">
          <button class="network-btn" id="russian-regulations-btn">Российское регулирование</button>
          <button class="network-btn" id="international-regulations-btn">Международное регулирование</button>
        </div>

        <h2>Теория "Оранжевой книги" (Orange Book)</h2>
        <p>"Оранжевая книга" — это неофициальное название документа <strong>Trusted Computer System Evaluation Criteria (TCSEC)</strong>, опубликованного Министерством обороны США в 1983 году (обновлено в 1985 году). Этот документ стал одним из первых стандартов для оценки безопасности компьютерных систем и заложил основы для современных подходов к информационной безопасности.</p>
  
        <h3>Основные положения "Оранжевой книги"</h3>
        <ul>
          <li><strong>Цель:</strong> "Оранжевая книга" разработана для оценки безопасности компьютерных систем, используемых в государственных и военных учреждениях, с акцентом на защиту конфиденциальной информации.</li>
          <li><strong>Классы безопасности:</strong> Документ делит системы на четыре уровня безопасности (D, C, B, A), где D — минимальный уровень, а A — максимальный. Каждый уровень включает подуровни (например, C1, C2, B1, B2, B3, A1).</li>
          <li><strong>Критерии оценки:</strong>
            <ul>
              <li><strong>Политика безопасности:</strong> Определение правил доступа (например, дискреционная или мандатная политика управления доступом).</li>
              <li><strong>Ответственность:</strong> Учёт действий пользователей (аудит, логирование).</li>
              <li><strong>Гарантия:</strong> Документация, тестирование и верификация системы для подтверждения её безопасности.</li>
              <li><strong>Документация:</strong> Требования к руководствам по эксплуатации и безопасности.</li>
            </ul>
          </li>
          <li><strong>Уровни безопасности:</strong>
            <ul>
              <li><strong>D (Минимальная защита):</strong> Системы, не соответствующие требованиям безопасности (например, MS-DOS).</li>
              <li><strong>C (Дискреционная защита):</strong> Базовая защита с дискреционным управлением доступом (C1 — базовый контроль, C2 — усиленный контроль, например, ранние версии UNIX).</li>
              <li><strong>B (Мандатная защита):</strong> Мандатное управление доступом (B1 — маркировка данных, B2 — структурированная защита, B3 — домены безопасности).</li>
              <li><strong>A (Верифицированная защита):</strong> Высший уровень с формальной верификацией (A1 — формальная модель безопасности).</li>
            </ul>
          </li>
        </ul>
  
        <h3>Применение "Оранжевой книги"</h3>
        <p>"Оранжевая книга" использовалась для сертификации систем в США, особенно в военных и государственных учреждениях. Например, системы уровня B2 применялись для обработки секретной информации, а A1 — для особо секретных данных. Однако стандарт устарел к 2000-м годам и был заменён более современным <strong>Common Criteria (ISO/IEC 15408)</strong>.</p>
  
        <h3>Влияние на современные стандарты</h3>
        <p>Несмотря на устаревание, "Оранжевая книга" оказала значительное влияние на развитие стандартов ИБ:</p>
        <ul>
          <li>Ввела концепцию мандатного управления доступом, которая используется в современных системах (например, SELinux).</li>
          <li>Заложила основы для Common Criteria, которые применяются для сертификации систем по всему миру.</li>
          <li>Подчеркнула важность аудита и верификации, что стало стандартом в ISO/IEC 27001.</li>
        </ul>
  
        <h2>Основные аспекты правового регулирования</h2>
        <p>Правовое регулирование защиты информации направлено на создание единых стандартов и правил, которые обеспечивают безопасность данных и систем. Оно включает:</p>
        <ul>
          <li><strong>Нормативные акты:</strong> Законы, постановления, приказы и стандарты, которые определяют требования к защите информации (например, ФЗ-149, ФЗ-187, ГОСТ).</li>
          <li><strong>Лицензирование:</strong> Требования к организациям, занимающимся защитой информации, включая лицензии ФСТЭК и ФСБ.</li>
          <li><strong>Сертификация:</strong> Обязательная сертификация средств защиты информации (СЗИ) для соответствия государственным стандартам.</li>
          <li><strong>Международное сотрудничество:</strong> Участие в международных соглашениях и стандартах (например, ISO/IEC 27001) для гармонизации подходов к защите информации.</li>
          <li><strong>Ответственность:</strong> Установление ответственности за нарушение требований (например, штрафы, уголовная ответственность за утечку гостайны).</li>
        </ul>

      </div>
    `;

    document.getElementById('russian-regulations-btn').addEventListener('click', () => {
      loadRussianRegulationsContent(container);
    });
  
    document.getElementById('international-regulations-btn').addEventListener('click', () => {
      loadInternationalRegulationsContent(container);
    });
  }
  
  function loadRussianRegulationsContent(container) {
    container.innerHTML = `
      <div class="legal-regulations-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Российское регулирование</h1>
        <p>В России защита информации регулируется обширным набором нормативных актов, включая федеральные законы, постановления правительства, приказы ФСБ и ФСТЭК, а также стандарты ГОСТ. Эти документы охватывают различные аспекты защиты информации: от персональных данных (ПДн) и государственной тайны до критической информационной инфраструктуры (КИИ) и автоматизированных систем управления технологическими процессами (АСУТП).</p>
  
        <h2>Основные нормативные документы</h2>
        <p>Ниже представлен перечень ключевых нормативных документов, регулирующих защиту информации в России:</p>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Документ</th>
                <th>Описание</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Доктрина информационной безопасности Российской Федерации (утверждена Указом Президента РФ от 5 декабря 2016 г. № 646)</td>
                <td>Стратегический документ, определяющий национальные интересы, цели, задачи и основные направления обеспечения информационной безопасности в России.</td>
              </tr>
              <tr>
                <td>ГОСТ Р 50922-2006 Защита информации. Основные термины и определения</td>
                <td>Устанавливает основные термины и определения в области защиты информации, используемые в нормативных актах и стандартах.</td>
              </tr>
              <tr>
                <td>ГОСТ Р 51275-2006 Защита информации. Объект информатизации. Факторы, воздействующие на информацию</td>
                <td>Описывает факторы, которые могут воздействовать на информацию в объектах информатизации, и методы их анализа.</td>
              </tr>
              <tr>
                <td>ГОСТ Р 53114-2008 Защита информации. Обеспечение информационной безопасности в организации</td>
                <td>Определяет общие принципы и методы обеспечения информационной безопасности в организациях.</td>
              </tr>
              <tr>
                <td>ГОСТ Р 56546-2015 Защита информации. Уязвимости информационных систем</td>
                <td>Устанавливает классификацию уязвимостей информационных систем и методы их выявления.</td>
              </tr>
              <tr>
                <td>ГОСТ Р 56939-2016 Защита информации. Разработка безопасного программного обеспечения</td>
                <td>Описывает требования к разработке безопасного ПО, включая этапы анализа уязвимостей и тестирования.</td>
              </tr>
              <tr>
                <td>ПП РФ от 1 ноября 2012 г. N 1119. Требования к защите ПДн при их обработке в ИСПДн</td>
                <td>Устанавливает требования к защите персональных данных в информационных системах персональных данных (ИСПДн).</td>
              </tr>
              <tr>
                <td>ПП РФ от 19 февраля 2019 г. N 162. Правила разработки, утверждения и корректировки программ</td>
                <td>Определяет правила разработки и корректировки программ в области информационной безопасности.</td>
              </tr>
              <tr>
                <td>ПП РФ от 3 февраля 2012 г. N 79. О лицензировании деятельности по технической защите конфиденциальной информации</td>
                <td>Устанавливает порядок лицензирования деятельности по технической защите конфиденциальной информации.</td>
              </tr>
              <tr>
                <td>ПП РФ от 6 июля 2015 г. N 676. О требованиях к порядку создания и вывода из эксплуатации ГИС</td>
                <td>Определяет требования к созданию, эксплуатации и выводу из эксплуатации государственных информационных систем (ГИС).</td>
              </tr>
              <tr>
                <td>ПП РФ от 8 февраля 2018 г. N 127. Правила категорирования объектов КИИ</td>
                <td>Устанавливает правила категорирования объектов критической информационной инфраструктуры (КИИ).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ РФ от 27 декабря 2011 г. N 795. Требования к форме ключа проверки ЭЦП</td>
                <td>Определяет требования к форме ключа проверки электронной цифровой подписи (ЭЦП).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 10 июля 2014 г. N 378. Обеспечение безопасности ПДн средствами КЗИ</td>
                <td>Устанавливает меры по обеспечению безопасности персональных данных с использованием криптографических средств защиты информации (КЗИ).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 19 июня 2019 г. N 281. Эксплуатация средств госСОПКА</td>
                <td>Регулирует эксплуатацию средств государственной системы обнаружения, предупреждения и ликвидации последствий компьютерных атак (госСОПКА).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 19 июня 2019 г. N 282. Порядок информирования ФСБ госСОПКА</td>
                <td>Устанавливает порядок информирования ФСБ в рамках госСОПКА.</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 24 июля 2018 г. N 366. О НКЦКИ</td>
                <td>Создаёт Национальный координационный центр по компьютерным инцидентам (НКЦКИ).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 24 июля 2018 г. N 367. Перечень информации, предоставляемой в госСОПКА</td>
                <td>Определяет перечень информации, которую субъекты КИИ должны предоставлять в госСОПКА.</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 24 июля 2018 г. N 368. Порядок обмена информацией с госСОПКА</td>
                <td>Регулирует порядок обмена информацией между субъектами КИИ и госСОПКА.</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 27 декабря 2011 г. Требования к средствам ЭЦП и УЦ</td>
                <td>Устанавливает требования к средствам ЭЦП и удостоверяющим центрам (УЦ).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 6 мая 2019 г. N 196. Требования к средствам для госСОПКА</td>
                <td>Определяет требования к средствам, используемым в госСОПКА.</td>
              </tr>
              <tr>
                <td>Приказ ФСБ России от 9 февраля 2005 г. N 66. Разработка КриптоСЗИ</td>
                <td>Регулирует разработку криптографических средств защиты информации (КриптоСЗИ).</td>
              </tr>
              <tr>
                <td>Приказ ФСБ от 24.10.2022 N 524. Об утверждении требований о защите информации, содержащейся в ГИС</td>
                <td>Устанавливает требования к защите информации в государственных информационных системах (ГИС).</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 11 февраля 2013 г. N 17. Требования о защите информации, не составляющих гос. тайну в ГИС</td>
                <td>Определяет требования к защите информации, не составляющей государственную тайну, в ГИС.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 12 января 2023 г. N 3. Об утверждении форм документов, используемых ФСТЭК</td>
                <td>Утверждает формы документов, используемых ФСТЭК для регулирования защиты информации.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 12 января 2023 г. N 4. Об утверждении форм документов, используемых ФСТЭК</td>
                <td>Дополнительно утверждает формы документов, используемых ФСТЭК.</td>
              </tr>
              <tr>
                <td>Приказ ФSTЭК России от 14 марта 2014 г. N 31. Требования к обеспечению защиты информации в АСУ ТП</td>
                <td>Устанавливает требования к защите информации в автоматизированных системах управления технологическими процессами (АСУТП).</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 2 июня 2020 г. N 76. Требования к уровням доверия СЗИ</td>
                <td>Определяет уровни доверия к средствам защиты информации (СЗИ).</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 20 апреля 2023 г. N 69. О внесении изменений в 235</td>
                <td>Вносит изменения в Приказ ФСТЭК № 235, касающийся систем безопасности КИИ.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 20 декабря 2022 г. N 226. Об утверждении программы профилактики нарушений обязательных требований</td>
                <td>Утверждает программу профилактики нарушений обязательных требований в области защиты информации.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 21 декабря 2017 г. N 235. Требования к созданию систем безопасности КИИ</td>
                <td>Устанавливает требования к созданию систем безопасности значимых объектов КИИ.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 25 декабря 2017 г. N 239. Требования к обеспечению безопасности КИИ</td>
                <td>Определяет меры защиты для значимых объектов КИИ.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 28 мая 2020 г. N 75. Порядок согласования подключения КИИ к сети общего пользования</td>
                <td>Регулирует порядок согласования подключения объектов КИИ к сети общего пользования.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 29 апреля 2021 г. N 77. Аттестация объектов информатизации на требования о защите информации</td>
                <td>Устанавливает порядок аттестации объектов информатизации на соответствие требованиям защиты информации.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 29 июня 2023 г. N 125. Об утверждении Обзора правоприменительной практики ФСТЭК</td>
                <td>Утверждает обзор правоприменительной практики ФСТЭК в области защиты информации.</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 3 апреля 2018 г. N 55. О системе сертификации СЗИ</td>
                <td>Регулирует систему сертификации средств защиты информации (СЗИ).</td>
              </tr>
              <tr>
                <td>Приказ ФСТЭК России от 5 мая 2023 г. N 78. О выдаче квалификационного аттестата специалиста в области экспортного контроля</td>
                <td>Устанавливает порядок выдачи квалификационного аттестата специалистам в области экспортного контроля.</td>
              </tr>
              <tr>
                <td>Типовой перечень сведений об объекте исследования</td>
                <td>Содержит перечень сведений, необходимых для проведения исследований объектов информатизации.</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Доктрина информационной безопасности Российской Федерации</h2>
        <p>Доктрина информационной безопасности Российской Федерации (утверждена Указом Президента РФ от 5 декабря 2016 г. № 646) является стратегическим документом, который определяет национальные интересы, цели, задачи и основные направления обеспечения информационной безопасности в России. Она заменила предыдущую версию доктрины от 2000 года, учитывая новые вызовы и угрозы в информационной сфере.</p>
  
        <h3>Основные положения Доктрины</h3>
        <ul>
          <li><strong>Национальные интересы:</strong> Доктрина выделяет ключевые интересы России в информационной сфере, включая защиту суверенитета, обеспечение устойчивости информационной инфраструктуры и защиту прав граждан.</li>
          <li><strong>Угрозы:</strong> Среди основных угроз названы кибератаки, информационные войны, использование ИТ для подрыва государственной стабильности, а также зависимость от иностранных технологий.</li>
          <li><strong>Цели и задачи:</strong>
            <ul>
              <li>Обеспечение устойчивого функционирования информационной инфраструктуры.</li>
              <li>Противодействие киберугрозам, включая создание системы госСОПКА.</li>
              <li>Развитие отечественных технологий и снижение зависимости от импорта.</li>
              <li>Защита прав граждан на конфиденциальность и доступ к информации.</li>
            </ul>
          </li>
          <li><strong>Направления реализации:</strong>
            <ul>
              <li><strong>Правовое регулирование:</strong> Совершенствование законодательства в области ИБ (например, ФЗ-187 о КИИ).</li>
              <li><strong>Технологическое развитие:</strong> Поддержка отечественных разработок в области ИТ и ИБ.</li>
              <li><strong>Международное сотрудничество:</strong> Участие в глобальных инициативах по кибербезопасности.</li>
              <li><strong>Образование:</strong> Повышение уровня осведомлённости граждан и специалистов в области ИБ.</li>
            </ul>
          </li>
        </ul>
  
        <h3>Роль Доктрины в российской системе ИБ</h3>
        <p>Доктрина служит основой для разработки других нормативных актов и стратегий в области ИБ. Она задаёт стратегическое видение и координирует действия государственных органов, бизнеса и общества. Например, создание Национального координационного центра по компьютерным инцидентам (НКЦКИ) и системы госСОПКА напрямую связано с положениями Доктрины.</p>
  
        <h3>Примеры реализации</h3>
        <ul>
          <li><strong>ГосСОПКА:</strong> Система обнаружения и реагирования на кибератаки, созданная для защиты КИИ.</li>
          <li><strong>Импортозамещение:</strong> Разработка отечественного ПО и оборудования (например, процессоры "Эльбрус", ОС Astra Linux).</li>
          <li><strong>Образовательные программы:</strong> Введение курсов по кибербезопасности в вузах и проведение мероприятий, таких как форум "Киберполигон".</li>
        </ul>
  
        <h2>Роль нормативных актов</h2>
        <p>Нормативные акты в России выполняют следующие функции:</p>
        <ul>
          <li><strong>Стандартизация:</strong> Устанавливают единые требования к защите информации, что упрощает внедрение мер безопасности.</li>
          <li><strong>Контроль:</strong> Обеспечивают контроль со стороны государства через ФСБ, ФСТЭК и другие органы.</li>
          <li><strong>Ответственность:</strong> Определяют меры ответственности за нарушение требований (например, штрафы, уголовная ответственность).</li>
          <li><strong>Гармонизация:</strong> Согласовывают российские стандарты с международными (например, ГОСТ Р ИСО/МЭК 27001).</li>
        </ul>
  
        <h2>Рекомендации по соблюдению</h2>
        <ol>
          <li><strong>Изучите нормативные акты:</strong> Ознакомьтесь с требованиями, применимыми к вашей организации (например, ФЗ-187 для КИИ).</li>
          <li><strong>Проведите аудит:</strong> Оцените соответствие вашей системы требованиям нормативных актов.</li>
          <li><strong>Получите лицензии:</strong> Убедитесь, что у вас есть необходимые лицензии ФСТЭК и ФСБ для работы с конфиденциальной информацией.</li>
          <li><strong>Используйте сертифицированные средства:</strong> Применяйте только сертифицированные СЗИ и криптографические средства.</li>
          <li><strong>Сотрудничайте с органами:</strong> Взаимодействуйте с ФСБ и ФСТЭК, предоставляя необходимую информацию (например, в рамках госСОПКА).</li>
        </ol>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadLegalRegulationsContent(container);
    });
  }
  
  function loadInternationalRegulationsContent(container) {
    container.innerHTML = `
      <div class="legal-regulations-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Международное регулирование</h1>
        <p>Международное регулирование защиты информации направлено на создание единых стандартов и подходов к обеспечению безопасности данных и систем в глобальном масштабе. Оно включает международные стандарты, соглашения и рекомендации, которые применяются в разных странах для гармонизации требований к информационной безопасности.</p>
  
        <h2>Основные международные стандарты</h2>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Стандарт</th>
                <th>Описание</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>ISO/IEC 27001</td>
                <td>Международный стандарт управления информационной безопасностью, который определяет требования к созданию, внедрению и поддержанию системы управления информационной безопасностью (СУИБ).</td>
              </tr>
              <tr>
                <td>ISO/IEC 27002</td>
                <td>Содержит рекомендации и лучшие практики для реализации мер информационной безопасности в соответствии с ISO/IEC 27001.</td>
              </tr>
              <tr>
                <td>GDPR (General Data Protection Regulation)</td>
                <td>Регламент Европейского Союза по защите персональных данных, который устанавливает строгие требования к обработке и защите данных граждан ЕС.</td>
              </tr>
              <tr>
                <td>NIST SP 800-53</td>
                <td>Стандарт Национального института стандартов и технологий США (NIST), который определяет меры безопасности для федеральных информационных систем.</td>
              </tr>
              <tr>
                <td>ISO/IEC 62443</td>
                <td>Международный стандарт для защиты автоматизированных систем управления технологическими процессами (АСУТП) от киберугроз.</td>
              </tr>
              <tr>
                <td>CCPA (California Consumer Privacy Act)</td>
                <td>Закон штата Калифорния, США, который регулирует защиту персональных данных потребителей и предоставляет им права на доступ и удаление данных.</td>
              </tr>
              <tr>
                <td>HIPAA (Health Insurance Portability and Accountability Act)</td>
                <td>Закон США, регулирующий защиту медицинских данных и устанавливающий требования к их конфиденциальности.</td>
              </tr>
              <tr>
                <td>PCI DSS (Payment Card Industry Data Security Standard)</td>
                <td>Стандарт безопасности данных индустрии платёжных карт, который применяется к организациям, обрабатывающим данные банковских карт.</td>
              </tr>
            </tbody>
          </table>
        </div>
  
        <h2>Международные соглашения</h2>
        <p>Международное сотрудничество в области защиты информации осуществляется через соглашения и организации:</p>
        <ul>
          <li><strong>Конвенция Совета Европы о киберпреступности (Будапештская конвенция):</strong> Первое международное соглашение, направленное на борьбу с киберпреступностью, включая гармонизацию законодательства и сотрудничество между странами.</li>
          <li><strong>ENISA (European Union Agency for Cybersecurity):</strong> Агентство ЕС, которое занимается разработкой рекомендаций и стандартов в области кибербезопасности.</li>
          <li><strong>ITU (International Telecommunication Union):</strong> Международный союз электросвязи, который разрабатывает стандарты и рекомендации в области кибербезопасности.</li>
        </ul>
  
        <h2>Примеры применения</h2>
        <ul>
          <li><strong>GDPR:</strong> Компании, работающие с данными граждан ЕС, обязаны внедрять шифрование, псевдонимизацию и проводить оценку рисков (DPIA).</li>
          <li><strong>ISO/IEC 27001:</strong> Многие международные компании (например, Microsoft, Google) сертифицируют свои системы по этому стандарту для повышения доверия клиентов.</li>
          <li><strong>PCI DSS:</strong> Банки и платёжные системы (например, Visa, MasterCard) требуют от партнёров соблюдения этого стандарта для защиты данных карт.</li>
        </ul>
  
        <h2>Рекомендации по соблюдению</h2>
        <ol>
          <li><strong>Изучите применимые стандарты:</strong> Определите, какие международные стандарты применимы к вашей организации (например, GDPR для работы с данными граждан ЕС).</li>
          <li><strong>Проведите сертификацию:</strong> Сертифицируйте свои системы по ISO/IEC 27001 для повышения доверия партнёров.</li>
          <li><strong>Внедрите лучшие практики:</strong> Используйте рекомендации ISO/IEC 27002 для реализации мер безопасности.</li>
          <li><strong>Сотрудничайте с международными органами:</strong> Участвуйте в инициативах ENISA или ITU для обмена опытом.</li>
          <li><strong>Обучайте персонал:</strong> Проводите тренинги по международным требованиям, таким как GDPR или PCI DSS.</li>
        </ol>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadLegalRegulationsContent(container);
    });
  }