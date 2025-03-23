function loadRussianSziContent(contentArea) {
  const sziContent = `
    <div class="russian-szi-container">
      <h1>Российские СЗИ</h1>
      <div class="szi-description">
        <p><strong>Российские средства защиты информации (СЗИ)</strong> — это программные и аппаратные решения, разработанные отечественными компаниями для обеспечения информационной безопасности. Они включают межсетевые экраны, антивирусы, операционные системы, системы управления доступом, средства криптографии и многое другое. Такие решения часто используются в государственных структурах, критической инфраструктуре и коммерческих организациях для соответствия требованиям законодательства РФ, включая ФЗ-187 "О безопасности КИИ" и приказы ФСБ.</p>
        <p>Ниже представлена таблица с основными российскими вендорами и их продуктами в области ИБ:</p>
      </div>

      <h2>Таблица: Российские вендоры и их продукты</h2>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Имя вендора</th>
              <th>Название продукта</th>
              <th>Описание продукта</th>
              <th>Где применяется</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td rowspan="3">Группа компаний Astra</td>
              <td>Astra Linux</td>
              <td>Операционная система на базе Linux с усиленной защитой, сертифицированная для работы с государственной тайной.</td>
              <td>Государственные учреждения, военные организации, объекты КИИ.</td>
            </tr>
            <tr>
              <td>ALD Pro</td>
              <td>Система управления доменом и доступом для централизованного контроля пользователей и устройств.</td>
              <td>Корпоративные сети, государственные организации.</td>
            </tr>
            <tr>
              <td>Тантор</td>
              <td>СУБД для управления базами данных с акцентом на безопасность и производительность.</td>
              <td>Корпоративные системы, банки, государственные структуры.</td>
            </tr>
            <tr>
              <td rowspan="4">Код Безопасности</td>
              <td>Соболь</td>
              <td>Аппаратно-программный модуль доверенной загрузки для защиты от несанкционированного доступа на этапе загрузки ОС.</td>
              <td>Рабочие станции и серверы в государственных и коммерческих организациях.</td>
            </tr>
            <tr>
              <td>Secret Net Studio</td>
              <td>Комплексное решение для защиты рабочих станций: контроль доступа, шифрование, антивирус.</td>
              <td>Защита рабочих мест в органах власти, банках, предприятиях.</td>
            </tr>
            <tr>
              <td>Континент</td>
              <td>Межсетевой экран и система VPN для защиты сетевого периметра и удалённого доступа.</td>
              <td>Корпоративные сети, объекты КИИ, удалённые рабочие места.</td>
            </tr>
            <tr>
              <td>vGate</td>
              <td>Система защиты виртуальных инфраструктур и контроля доступа к виртуальным машинам.</td>
              <td>Дата-центры, корпоративные сети с виртуализацией.</td>
            </tr>
            <tr>
              <td rowspan="5">ИнфоТеКС</td>
              <td>ViPNet</td>
              <td>Семейство продуктов для построения защищённых VPN-сетей, шифрования данных и контроля доступа.</td>
              <td>Государственные структуры, банки, телеком-операторы.</td>
            </tr>
            <tr>
              <td>JaCarta</td>
              <td>Смарт-карты и USB-токены для аутентификации и электронной подписи.</td>
              <td>Электронный документооборот, доступ к информационным системам.</td>
            </tr>
            <tr>
              <td>ViPNet IDS</td>
              <td>Система обнаружения и предотвращения вторжений (IDS/IPS).</td>
              <td>Корпоративные сети, объекты КИИ.</td>
            </tr>
            <tr>
              <td>ViPNet Coordinator</td>
              <td>Шлюз безопасности для управления защищёнными соединениями в сетях.</td>
              <td>Крупные распределённые сети, государственные структуры.</td>
            </tr>
            <tr>
              <td>ViPNet Client</td>
              <td>Клиентское ПО для защиты удалённого доступа через VPN.</td>
              <td>Удалённая работа, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="4">Лаборатория Касперского</td>
              <td>Kaspersky Endpoint Security</td>
              <td>Антивирусное решение для защиты рабочих станций и серверов от всех типов угроз.</td>
              <td>Корпоративные сети, малый и средний бизнес, государственные организации.</td>
            </tr>
            <tr>
              <td>Kaspersky Industrial CyberSecurity</td>
              <td>Решение для защиты промышленных систем и объектов КИИ от кибератак.</td>
              <td>Промышленные предприятия, энергетика, транспорт.</td>
            </tr>
            <tr>
              <td>Kaspersky Security Center</td>
              <td>Централизованное управление защитой устройств и мониторинг угроз.</td>
              <td>Крупные компании, государственные структуры.</td>
            </tr>
            <tr>
              <td>Kaspersky Anti Targeted Attack</td>
              <td>Платформа для защиты от целевых атак и APT.</td>
              <td>Крупные корпорации, банки, объекты КИИ.</td>
            </tr>
            <tr>
              <td rowspan="3">Доктор Веб</td>
              <td>Dr.Web Enterprise Security Suite</td>
              <td>Комплексная антивирусная защита для рабочих станций, серверов и мобильных устройств.</td>
              <td>Корпоративные сети, образовательные учреждения, малый бизнес.</td>
            </tr>
            <tr>
              <td>Dr.Web KATANA</td>
              <td>Система поведенческого анализа для защиты от угроз нулевого дня.</td>
              <td>Организации с высокими требованиями к защите от новых угроз.</td>
            </tr>
            <tr>
              <td>Dr.Web Security Space</td>
              <td>Антивирус для защиты рабочих станций с функциями родительского контроля.</td>
              <td>Малый бизнес, частные пользователи.</td>
            </tr>
            <tr>
              <td rowspan="2">Ideco</td>
              <td>Ideco UTM</td>
              <td>Многофункциональный шлюз безопасности: межсетевой экран, VPN, контроль доступа, защита от DDoS.</td>
              <td>Малый и средний бизнес, корпоративные сети, провайдеры.</td>
            </tr>
            <tr>
              <td>Ideco Access</td>
              <td>Решение для организации безопасного удалённого доступа сотрудников.</td>
              <td>Удалённая работа, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">Numa Tech</td>
              <td>Numa Inspector</td>
              <td>Сканер уязвимостей и система управления соответствием требованиям безопасности.</td>
              <td>Организации, проводящие аудит ИБ, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Numa IDS</td>
              <td>Система обнаружения и предотвращения вторжений (IDS/IPS).</td>
              <td>Корпоративные сети, объекты КИИ, дата-центры.</td>
            </tr>
            <tr>
              <td rowspan="4">Positive Technologies</td>
              <td>PT Application Firewall</td>
              <td>Межсетевой экран для защиты веб-приложений от атак (SQL-инъекции, XSS и др.).</td>
              <td>Веб-приложения, порталы, интернет-магазины.</td>
            </tr>
            <tr>
              <td>MaxPatrol SIEM</td>
              <td>Система управления событиями и инцидентами ИБ для мониторинга и анализа угроз.</td>
              <td>Крупные корпорации, банки, государственные структуры.</td>
            </tr>
            <tr>
              <td>PT Sandbox</td>
              <td>Песочница для анализа подозрительных файлов и выявления вредоносного ПО.</td>
              <td>Центры мониторинга ИБ, крупные компании.</td>
            </tr>
            <tr>
              <td>MaxPatrol 8</td>
              <td>Система управления уязвимостями и контроля соответствия стандартам.</td>
              <td>Корпоративные сети, объекты КИИ.</td>
            </tr>
            <tr>
              <td rowspan="3">КриптоПро</td>
              <td>КриптоПро CSP</td>
              <td>Криптографический провайдер для шифрования данных и создания электронной подписи.</td>
              <td>Электронный документооборот, госуслуги, банки.</td>
            </tr>
            <tr>
              <td>КриптоПро HSM</td>
              <td>Аппаратный модуль безопасности для хранения ключей и выполнения криптографических операций.</td>
              <td>Высоконагруженные системы, банки, органы власти.</td>
            </tr>
            <tr>
              <td>КриптоПро DSS</td>
              <td>Сервер подписи для централизованного управления электронными подписями.</td>
              <td>Электронный документооборот, госуслуги.</td>
            </tr>
            <tr>
              <td rowspan="3">Рутокен (Актив)</td>
              <td>Рутокен</td>
              <td>USB-токены и смарт-карты для аутентификации, шифрования и электронной подписи.</td>
              <td>Электронный документооборот, доступ к системам, госуслуги.</td>
            </tr>
            <tr>
              <td>Рутокен VPN</td>
              <td>Решение для организации защищённого удалённого доступа с использованием токенов.</td>
              <td>Удалённая работа, корпоративные сети.</td>
            </tr>
            <tr>
              <td>Рутокен ЭЦП</td>
              <td>Токены с поддержкой российской криптографии для электронной подписи.</td>
              <td>Электронный документооборот, госуслуги.</td>
            </tr>
            <tr>
              <td rowspan="3">СёрчИнформ</td>
              <td>СёрчИнформ КИБ</td>
              <td>DLP-система для предотвращения утечек данных и контроля действий сотрудников.</td>
              <td>Корпоративные сети, банки, предприятия.</td>
            </tr>
            <tr>
              <td>СёрчИнформ SIEM</td>
              <td>Система управления событиями ИБ для анализа логов и выявления инцидентов.</td>
              <td>Крупные компании, центры мониторинга ИБ.</td>
            </tr>
            <tr>
              <td>СёрчИнформ FileAuditor</td>
              <td>Система аудита файлов для контроля доступа и изменений в данных.</td>
              <td>Корпоративные сети, объекты КИИ.</td>
            </tr>
            <tr>
              <td rowspan="3">ГК InfoWatch</td>
              <td>InfoWatch Traffic Monitor</td>
              <td>DLP-система для контроля трафика и предотвращения утечек данных.</td>
              <td>Корпоративные сети, банки, телеком.</td>
            </tr>
            <tr>
              <td>InfoWatch Vision</td>
              <td>Система визуализации и анализа инцидентов ИБ на основе данных DLP.</td>
              <td>Крупные компании, центры ИБ.</td>
            </tr>
            <tr>
              <td>InfoWatch ARMA</td>
              <td>Решение для защиты АСУ ТП и промышленных систем от кибератак.</td>
              <td>Промышленные предприятия, энергетика.</td>
            </tr>
            <tr>
              <td rowspan="3">НПО Эшелон</td>
              <td>Сканер-ВС</td>
              <td>Сканер уязвимостей для анализа защищённости сетей и приложений.</td>
              <td>Аудит ИБ, объекты КИИ, корпоративные сети.</td>
            </tr>
            <tr>
              <td>КОМРАД</td>
              <td>Система управления доступом и контроля целостности информации.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Аккорд</td>
              <td>Аппаратно-программный комплекс для защиты от несанкционированного доступа.</td>
              <td>Государственные структуры, военные организации.</td>
            </tr>
            <tr>
              <td rowspan="3">Ред Софт</td>
              <td>Ред ОС</td>
              <td>Операционная система на базе Linux для рабочих станций и серверов.</td>
              <td>Государственные организации, образование, предприятия.</td>
            </tr>
            <tr>
              <td>Ред Виртуализация</td>
              <td>Платформа виртуализации для создания и управления виртуальными машинами.</td>
              <td>Дата-центры, корпоративные сети.</td>
            </tr>
            <tr>
              <td>Ред База Данных</td>
              <td>СУБД для управления базами данных с поддержкой российских стандартов.</td>
              <td>Корпоративные системы, государственные структуры.</td>
            </tr>
            <tr>
              <td rowspan="3">С-Терра СиЭсПи</td>
              <td>С-Терра Шлюз</td>
              <td>Межсетевой экран и VPN-шлюз для защиты сетевого трафика.</td>
              <td>Корпоративные сети, объекты КИИ, удалённый доступ.</td>
            </tr>
            <tr>
              <td>С-Терра Клиент</td>
              <td>Клиентское ПО для защиты удалённого доступа через VPN.</td>
              <td>Удалённая работа, корпоративные сети.</td>
            </tr>
            <tr>
              <td>С-Терра Виртуальный Шлюз</td>
              <td>Виртуальный шлюз для защиты сетей в облачных инфраструктурах.</td>
              <td>Облачные среды, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="3">Aladdin R.D.</td>
              <td>JaCarta (совместно с ИнфоТеКС)</td>
              <td>Смарт-карты и USB-токены для аутентификации и ЭП.</td>
              <td>Электронный документооборот, доступ к системам.</td>
            </tr>
            <tr>
              <td>Secret Disk</td>
              <td>Решение для шифрования данных на дисках и защиты от утечек.</td>
              <td>Рабочие станции, корпоративные сети.</td>
            </tr>
            <tr>
              <td>JC-WebClient</td>
              <td>Клиентское ПО для работы с токенами JaCarta в веб-приложениях.</td>
              <td>Электронный документооборот, госуслуги.</td>
            </tr>
            <tr>
              <td rowspan="2">ГК Цитадель</td>
              <td>Сканер НСД Аргус</td>
              <td>Система защиты от несанкционированного доступа.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Цитадель МЭ</td>
              <td>Межсетевой экран для защиты сетевого периметра.</td>
              <td>Корпоративные сети, дата-центры.</td>
            </tr>
            <tr>
              <td rowspan="2">НТЦ ИТ РОСА</td>
              <td>РОСА Кобальт</td>
              <td>Операционная система для рабочих станций и серверов с акцентом на безопасность.</td>
              <td>Государственные организации, предприятия.</td>
            </tr>
            <tr>
              <td>РОСА Виртуализация</td>
              <td>Платформа для создания и управления виртуальными машинами.</td>
              <td>Дата-центры, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">BaseALT</td>
              <td>Альт Линукс</td>
              <td>Семейство операционных систем на базе Linux для рабочих станций и серверов.</td>
              <td>Образовательные учреждения, государственные организации.</td>
            </tr>
            <tr>
              <td>Альт Сервер Виртуализации</td>
              <td>Решение для виртуализации серверов с поддержкой контейнеров.</td>
              <td>Дата-центры, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">НПО РусБИТех</td>
              <td>РусБИТех-Астра</td>
              <td>Операционная система для рабочих станций и серверов, сертифицированная для гостайны.</td>
              <td>Государственные структуры, военные организации.</td>
            </tr>
            <tr>
              <td>РусБИТех-Коннект</td>
              <td>Решение для защищённого удалённого доступа.</td>
              <td>Удалённая работа, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">ГК Гарда Технологии</td>
              <td>Гарда БД</td>
              <td>Система защиты баз данных от несанкционированного доступа и атак.</td>
              <td>Банки, телеком, государственные структуры.</td>
            </tr>
            <tr>
              <td>Гарда Enterprise</td>
              <td>Платформа для мониторинга и защиты сетевого трафика.</td>
              <td>Крупные корпорации, объекты КИИ.</td>
            </tr>
            <tr>
              <td rowspan="2">Кремний ЭЛ</td>
              <td>Кремний ЭЛ МЭ</td>
              <td>Межсетевой экран на базе отечественного процессора для защиты сетей.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Кремний ЭЛ VPN</td>
              <td>Аппаратное решение для организации защищённых VPN-сетей.</td>
              <td>Корпоративные сети, удалённый доступ.</td>
            </tr>
            <tr>
              <td rowspan="2">НПО КРИСТА</td>
              <td>КРИСТА МЭ</td>
              <td>Межсетевой экран для защиты сетевого периметра.</td>
              <td>Корпоративные сети, объекты КИИ.</td>
            </tr>
            <tr>
              <td>КРИСТА VPN</td>
              <td>Решение для построения защищённых VPN-сетей.</td>
              <td>Удалённый доступ, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "Криптософт"</td>
              <td>Криптософт МЭ</td>
              <td>Межсетевой экран с поддержкой российской криптографии.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Криптософт VPN</td>
              <td>Решение для организации защищённых VPN-сетей.</td>
              <td>Корпоративные сети, удалённый доступ.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "Смарт-Софт"</td>
              <td>Traffic Inspector</td>
              <td>Шлюз безопасности для контроля трафика, фильтрации контента и защиты сети.</td>
              <td>Малый и средний бизнес, образовательные учреждения.</td>
            </tr>
            <tr>
              <td>Traffic Inspector Next Generation</td>
              <td>Многофункциональный межсетевой экран с функциями UTM.</td>
              <td>Корпоративные сети, провайдеры.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "АЛТЭКС-СОФТ"</td>
              <td>RedCheck</td>
              <td>Сканер уязвимостей для анализа защищённости сетей и приложений.</td>
              <td>Аудит ИБ, корпоративные сети.</td>
            </tr>
            <tr>
              <td>RedTrace</td>
              <td>Система трассировки и анализа сетевых атак.</td>
              <td>Центры мониторинга ИБ, крупные компании.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "Киберпротект"</td>
              <td>Кибер Бэкап</td>
              <td>Решение для резервного копирования и восстановления данных с защитой от шифровальщиков.</td>
              <td>Корпоративные сети, малый и средний бизнес.</td>
            </tr>
            <tr>
              <td>Кибер Инфраструктура</td>
              <td>Платформа для управления виртуальными средами и облачными сервисами.</td>
              <td>Дата-центры, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "НПО ВС"</td>
              <td>Соболь-ВС</td>
              <td>Система защиты от несанкционированного доступа для рабочих станций.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Контур-ВС</td>
              <td>Межсетевой экран для защиты сетевого периметра.</td>
              <td>Корпоративные сети, дата-центры.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "СИГНАЛТЕК"</td>
              <td>Сигналтек МЭ</td>
              <td>Межсетевой экран с поддержкой российской криптографии.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Сигналтек VPN</td>
              <td>Решение для построения защищённых VPN-сетей.</td>
              <td>Корпоративные сети, удалённый доступ.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "АйТи Бастион"</td>
              <td>СКДПУ НТ</td>
              <td>Система контроля действий привилегированных пользователей.</td>
              <td>Корпоративные сети, банки, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Бастион</td>
              <td>Решение для управления доступом и защиты серверов.</td>
              <td>Дата-центры, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "Конфидент"</td>
              <td>Dallas Lock</td>
              <td>Система защиты от несанкционированного доступа и контроля целостности.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Центр Защиты Информации</td>
              <td>Комплексное решение для защиты рабочих станций и серверов.</td>
              <td>Корпоративные сети, банки.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "Секьюр Ай Ти"</td>
              <td>SecureTower</td>
              <td>DLP-система для предотвращения утечек данных и контроля сотрудников.</td>
              <td>Корпоративные сети, банки, предприятия.</td>
            </tr>
            <tr>
              <td>SecureTower SIEM</td>
              <td>Система управления событиями ИБ для анализа инцидентов.</td>
              <td>Крупные компании, центры мониторинга ИБ.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "НПО СтарЛайн"</td>
              <td>СтарЛайн МЭ</td>
              <td>Межсетевой экран для защиты сетевого периметра.</td>
              <td>Корпоративные сети, объекты КИИ.</td>
            </tr>
            <tr>
              <td>СтарЛайн VPN</td>
              <td>Решение для построения защищённых VPN-сетей.</td>
              <td>Удалённый доступ, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "Атом Безопасность"</td>
              <td>StaffCop</td>
              <td>Система контроля действий сотрудников и предотвращения утечек данных.</td>
              <td>Корпоративные сети, малый и средний бизнес.</td>
            </tr>
            <tr>
              <td>StaffCop Enterprise</td>
              <td>Расширенная версия для крупных организаций с функциями DLP и SIEM.</td>
              <td>Крупные компании, банки.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "НПО Перспектива"</td>
              <td>Перспектива МЭ</td>
              <td>Межсетевой экран для защиты сетевого периметра.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Перспектива VPN</td>
              <td>Решение для построения защищённых VPN-сетей.</td>
              <td>Корпоративные сети, удалённый доступ.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "ЭЛВИС-ПЛЮС"</td>
              <td>ЗАСТАВА</td>
              <td>Межсетевой экран и VPN-шлюз для защиты сетей.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>ЗАСТАВА-Клиент</td>
              <td>Клиентское ПО для защищённого удалённого доступа.</td>
              <td>Удалённая работа, корпоративные сети.</td>
            </tr>
            <tr>
              <td rowspan="2">ООО "НПО Информационные Технологии"</td>
              <td>Искра</td>
              <td>Система защиты от несанкционированного доступа.</td>
              <td>Государственные структуры, объекты КИИ.</td>
            </tr>
            <tr>
              <td>Искра МЭ</td>
              <td>Межсетевой экран для защиты сетевого периметра.</td>
              <td>Корпоративные сети, дата-центры.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="szi-description">
        <h2>Примечания</h2>
        <ul>
          <li>Многие из перечисленных продуктов сертифицированы ФСБ и ФСТЭК, что делает их пригодными для использования в системах, обрабатывающих конфиденциальную информацию.</li>
          <li>Российские СЗИ часто интегрируются друг с другом для создания комплексных решений (например, связка ОС Astra Linux с Secret Net Studio).</li>
          <li>Выбор продукта зависит от требований организации, уровня защищённости и бюджета.</li>
        </ul>
      </div>
    </div>
  `;
  contentArea.innerHTML = sziContent;
}