function loadNetworkBuildingContent(container) {
  container.innerHTML = `
    <div class="network-building-container">
      <h1>Принципы построения сетей</h1>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th></th>
              <th>Описание</th>
              <th>Пример применения</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Неразрывческая модель</strong></td>
              <td>Сеть делится на уровни доступа (Access), агрегации (Distribution), ядра (Core).</td>
              <td>Уровень доступа — подключение пользователей, ядро — высокоскоростная маршрутизация.</td>
            </tr>
            <tr>
              <td><strong>Масштабируемость</strong></td>
              <td>Сеть должна поддерживать рост (добавление устройств, пользователей) без потери производительности.</td>
              <td>Использование протоколов маршрутизации (OSPF, BGP) для гибкости сети.</td>
            </tr>
            <tr>
              <td><strong>Надёжность</strong></td>
              <td>Обеспечение отказоустойчивости через резервирование (redundancy) и протоколы (например, VRRP).</td>
              <td>Настройка VRRP для резервирования шлюза по умолчанию.</td>
            </tr>
            <tr>
              <td><strong>Безопасность</strong></td>
              <td>Защита сети: ACL, шифрование, сегментация (VLAN), мониторинг (IDS/IPS).</td>
              <td>Использование VLAN для разделения трафика, настройка IDS для информационной безопасности.</td>
            </tr>
            <tr>
              <td><strong>Производительность</strong></td>
              <td>Оптимизация скорости и пропускной способности (например, через агрегацию каналов, QoS).</td>
              <td>Настройка QoS для приоритизации VoIP-трафика.</td>
            </tr>
            <tr>
              <td><strong>Управляемость</strong></td>
              <td>Централизованное управление и мониторинг (SNMP, syslog, NetFlow).</td>
              <td>Использование Cisco DNA Center для управления сетью.</td>
            </tr>
            <tr>
              <td><strong>Модульность</strong></td>
              <td>Модули для управления управлением и устранения неисправностей.</td>
              <td>Разделение сети на VLAN или подсети для раздела отделов.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="network-building-buttons">
        <button class="network-btn" id="protocols-btn">Сетевые протоколы</button>
        <button class="network-btn" id="corporate-network-btn">Построение корпоративной сети</button>
      </div>

      <h2>Дополнительная теория</h2>
      <p>При построении современных сетей важно учитывать не только текущие потребности, но и будущие масштабы. Например, использование протоколов маршрутизации, таких как OSPF или BGP, позволяет легко масштабировать сеть при добавлении новых устройств или сегментов. Эти протоколы обеспечивают автоматическое обновление маршрутов, что минимизирует ручную настройку.</p>
      <p>Для обеспечения отказоустойчивости применяются технологии резервирования, такие как VRRP или HSRP. Они позволяют настроить резервный шлюз, который автоматически активируется в случае сбоя основного маршрутизатора. Это особенно важно в корпоративных сетях, где недоступность сети может привести к значительным финансовым потерям. Например, VRRP позволяет двум маршрутизаторам совместно использовать виртуальный IP-адрес, где один маршрутизатор является активным, а другой — резервным. Если активный маршрутизатор выходит из строя, резервный автоматически берёт на себя его функции.</p>
      <p>Безопасность сети — ещё один ключевой аспект. Сегментация трафика с помощью VLAN позволяет разделить сеть на логические подсети, что снижает риск атак, таких как ARP-спуфинг или широковещательные штормы. Например, в корпоративной сети можно создать отдельные VLAN для отделов (бухгалтерия, IT, маркетинг), чтобы ограничить доступ между ними. Кроме того, использование протоколов шифрования, таких как IPSec, обеспечивает защиту данных при передаче через ненадёжные сети, например, в VPN-соединениях. Для дополнительной защиты можно настроить списки контроля доступа (ACL), которые фильтруют трафик на основе IP-адресов, портов или протоколов.</p>
      <p>Для мониторинга и анализа сетевого трафика применяются протоколы, такие как SNMP и NetFlow. SNMP позволяет собирать данные о состоянии устройств (например, загрузка процессора, использование памяти), а NetFlow помогает анализировать трафик для обнаружения аномалий, таких как DDoS-атаки. Например, с помощью NetFlow можно определить, какой IP-адрес генерирует аномально большое количество трафика, и заблокировать его. Также для централизованного управления сетью часто используются системы, такие как Cisco DNA Center, которые предоставляют графический интерфейс для мониторинга, настройки и устранения неисправностей.</p>
      <p>В современных дата-центрах активно используются технологии виртуализации, такие как VXLAN и MPLS. VXLAN позволяет создавать оверлей-сети, что упрощает управление большими дата-центрами с тысячами виртуальных машин. Например, VXLAN может использоваться для создания изолированных сетей для разных клиентов в облачной инфраструктуре. MPLS, в свою очередь, используется провайдерами для создания MPLS VPN, обеспечивая изолированные сети для клиентов. MPLS работает на основе меток, что позволяет ускорить маршрутизацию и упростить управление трафиком.</p>
      <p>Наконец, при проектировании сети важно учитывать производительность. Протоколы QoS позволяют приоритетовать трафик, например, отдавая предпочтение голосовому трафику (VoIP) над обычным веб-трафиком. Это особенно важно в сетях, где одновременно передаются данные, голос и видео. Например, в корпоративной сети можно настроить QoS так, чтобы видеоконференции (например, через Zoom) имели приоритет над загрузкой файлов, чтобы избежать задержек и потери качества.</p>
      <p>Ещё одним важным аспектом является выбор оборудования. Например, для уровня доступа (Access) часто используются коммутаторы с поддержкой PoE (Power over Ethernet), чтобы питать IP-телефоны или камеры видеонаблюдения. На уровне агрегации (Distribution) применяются более мощные коммутаторы с поддержкой маршрутизации (Layer 3), чтобы обрабатывать трафик между VLAN. На уровне ядра (Core) используются высокопроизводительные маршрутизаторы или коммутаторы с высокой пропускной способностью, чтобы обеспечить быструю передачу данных между всеми сегментами сети.</p>
      <p>Также стоит учитывать топологию сети. В небольших сетях часто используется звездообразная топология, где все устройства подключены к одному коммутатору. В крупных сетях применяется иерархическая топология (Access-Distribution-Core), которая обеспечивает масштабируемость и управляемость. Для повышения отказоустойчивости можно использовать кольцевую топологию или агрегацию каналов (например, с помощью протокола LACP), чтобы создать резервные пути для передачи данных.</p>
      <p>При проектировании сети важно учитывать и физическую инфраструктуру. Например, для подключения удалённых офисов можно использовать VPN (например, с помощью IPSec или L2TP), а для высокоскоростных соединений между дата-центрами — оптоволоконные линии. Также стоит обратить внимание на стандарты кабелей: для современных сетей рекомендуется использовать кабели категории Cat6 или выше, чтобы поддерживать скорости до 10 Гбит/с.</p>
      <p>Наконец, не забывайте про документирование сети. Хорошая документация (схемы, таблицы IP-адресов, настройки оборудования) значительно упрощает управление и устранение неисправностей. Например, можно использовать инструменты, такие как Cisco Packet Tracer или GNS3, для моделирования сети перед её внедрением, чтобы избежать ошибок на этапе проектирования.</p>
    </div>
  `;

  document.getElementById('protocols-btn').addEventListener('click', () => {
    loadProtocolsContent(container);
  });

  document.getElementById('corporate-network-btn').addEventListener('click', () => {
    loadCorporateNetworkContent(container);
  });

}

function loadProtocolsContent(container) {
  container.innerHTML = `
    <div class="network-building-container">
      <button class="back-btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="19" y1="12" x2="5" y2="12"></line>
          <polyline points="12 19 5 12 12 5"></polyline>
        </svg>
        Назад
      </button>
      <h1>Сетевые протоколы</h1>
      <div class="osi-table-container">
        <table class="osi-table">
          <thead>
            <tr>
              <th>Протокол</th>
              <th>Уровень (OSI/TCP/IP)</th>
              <th>Назначение</th>
              <th>Особенности</th>
              <th>Примеры использования</th>
              <th>Ключевые команды (Cisco)</th>
              <th>Ключевые команды (Windows)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>TCP/IP</td>
              <td>Транспортный/Сетевой (OSI: 3-4, TCP/IP: Internet/Transport)</td>
              <td>Основной стек протоколов для интернета: IP (адресация), TCP/UDP (передача).</td>
              <td>TCP — надежный, с подтверждением; UDP — быстрый, без подтверждения. IP — маршрутизация.</td>
              <td>Передача веб-страниц (HTTP/TCP), стриминг (UDP).</td>
              <td><span style="color: red;">show ip route, show tcp sessions</span></td>
              <td>netstat -an, ipconfig /all</td>
            </tr>
            <tr>
              <td>DHCP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Автоматическое назначение IP-адресов, маски, шлюза и DNS клиентам.</td>
              <td>Работает по модели клиент-сервер (DORA: Discover, Offer, Request, Acknowledge).</td>
              <td>Назначение IP-адресов устройствам в локальной сети.</td>
              <td><span style="color: red;">ip dhcp pool NAME, show ip dhcp binding</span></td>
              <td>ipconfig /release, ipconfig /renew</td>
            </tr>
            <tr>
              <td>VRRP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Обеспечение резервирования шлюза по умолчанию (виртуальный IP).</td>
              <td>Аналог HSRP, но открытый стандарт. Мастер и резервные маршрутизаторы, приоритет (0-255).</td>
              <td>Резервирование шлюза в сетях для отказоустойчивости.</td>
              <td><span style="color: red;">vrrp GROUP ip VIRTUAL_IP, show vrrp</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>VPC</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Virtual Port Channel — объединение портов на разных коммутаторах в один канал.</td>
              <td>Позволяет агрегировать каналы между двумя коммутаторами (например, Nexus), избегая STP-блокировок.</td>
              <td>Агрегация каналов между двумя коммутаторами Cisco Nexus для повышения пропускной способности.</td>
              <td><span style="color: red;">vpc domain ID, show vpc</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>OSPF</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Протокол маршрутизации (Link-State), использует алгоритм Dijkstra.</td>
              <td>Делит сеть на зоны (areas), использует метрику (cost), поддерживает быструю сходимость.</td>
              <td>Динамическая маршрутизация в корпоративных сетях.</td>
              <td><span style="color: red;">router ospf PROCESS_ID, show ip ospf neighbor</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>BGP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Протокол маршрутизации между автономными системами (AS), использует TCP.</td>
              <td>EGP (External Gateway Protocol), использует атрибуты (AS Path, MED) для выбора маршрута.</td>
              <td>Маршрутизация в интернете между провайдерами.</td>
              <td><span style="color: red;">router bgp AS_NUMBER, show ip bgp</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>FC (Fibre Channel)</td>
              <td>Канальный/Физический (OSI: 1-2, TCP/IP: Link)</td>
              <td>Протокол для высокоскоростной передачи данных в SAN (Storage Area Network).</td>
              <td>Использует оптоволокно, поддерживает низкую задержку, высокую надежность, до 128 Гбит/с.</td>
              <td>Подключение серверов к хранилищам данных (SAN).</td>
              <td><span style="color: red;">show fc, zone name ZONE_NAME vsan VSAN_ID</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>EIGRP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Протокол маршрутизации (Hybrid), разработан Cisco, использует DUAL-алгоритм.</td>
              <td>Быстрая сходимость, поддерживает VLSM, использует метрику (пропускная способность, задержка).</td>
              <td>Динамическая маршрутизация в сетях Cisco.</td>
              <td><span style="color: red;">router eigrp AS_NUMBER, show ip eigrp neighbors</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>RIP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Простой протокол маршрутизации (Distance Vector), использует метрику (hops).</td>
              <td>Максимум 15 прыжков, медленная сходимость, версии RIPv1 и RIPv2 (RIPv2 поддерживает VLSM).</td>
              <td>Небольшие сети с простой топологией.</td>
              <td><span style="color: red;">router rip, show ip rip database</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>STP</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Предотвращение петель в сетях на канальном уровне.</td>
              <td>Выбирает корневой мост, блокирует избыточные пути, версии: RSTP (быстрее), MSTP (для VLAN).</td>
              <td>Между коммутаторами в локальной сети.</td>
              <td><span style="color: red;">spanning-tree vlan VLAN_ID, show spanning-tree</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>HSRP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Резервирование шлюза по умолчанию (проприетарный протокол Cisco).</td>
              <td>Аналог VRRP, поддерживает группы, приоритет (0-255), активный и резервный маршрутизатор.</td>
              <td>Резервирование шлюза в сетях Cisco.</td>
              <td><span style="color: red;">standby GROUP ip VIRTUAL_IP, show standby</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>IPsec</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Шифрование и аутентификация данных на сетевом уровне.</td>
              <td>Использует AH (аутентификация) и ESP (шифрование), часто применяется в VPN.</td>
              <td>Защищенные VPN-соединения (например, site-to-site).</td>
              <td><span style="color: red;">crypto ipsec transform-set NAME, show crypto ipsec sa</span></td>
              <td>netsh advfirewall consec show rule name="all"</td>
            </tr>
            <tr>
              <td>SNMP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Мониторинг и управление сетевыми устройствами.</td>
              <td>Версии: SNMPv1, v2c, v3 (v3 с шифрованием), использует агенты и менеджеры.</td>
              <td>Сбор данных о состоянии сети (например, с помощью PRTG).</td>
              <td><span style="color: red;">snmp-server community STRING, show snmp</span></td>
              <td>net start snmp, snmpwalk (с установкой утилит)</td>
            </tr>
            <tr>
              <td>NetFlow</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Анализ сетевого трафика для мониторинга и безопасности.</td>
              <td>Собирает данные о потоках (IP, порты, объем трафика), версии: v5, v9, IPFIX.</td>
              <td>Обнаружение аномалий, анализ трафика.</td>
              <td><span style="color: red;">ip flow-export destination IP PORT, show ip flow export</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>FCoE</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Инкапсуляция Fibre Channel в Ethernet для упрощения инфраструктуры SAN.</td>
              <td>Использует Ethernet для передачи FC, требует поддержки DCB (Data Center Bridging).</td>
              <td>Упрощение SAN в дата-центрах.</td>
              <td><span style="color: red;">feature fcoe, show fcoe</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>MPLS</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Маршрутизация на основе меток (Label Switching).</td>
              <td>Использует метки для быстрой маршрутизации, поддерживает VPN (MPLS VPN), часто в сетях провайдеров.</td>
              <td>Сети провайдеров, создание VPN.</td>
              <td><span style="color: red;">mpls ip, show mpls ldp neighbor</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>VXLAN</td>
              <td>Сетевой/Канальный (OSI: 2-3, TCP/IP: Internet/Link)</td>
              <td>Создание оверлей-сетей для виртуализации в дата-центрах.</td>
              <td>Инкапсулирует кадры в UDP, использует VNI (идентификатор сети), масштабируемость до 16 млн сетей.</td>
              <td>Виртуализация сетей в дата-центрах.</td>
              <td><span style="color: red;">feature vxlan, show vxlan</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>802.1X</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Аутентификация устройств на канальном уровне.</td>
              <td>Использует EAP для аутентификации, взаимодействует с RADIUS-сервером.</td>
              <td>Контроль доступа к сети (например, в офисах).</td>
              <td><span style="color: red;">dot1x system-auth-control, show dot1x</span></td>
              <td>netsh lan show profiles</td>
            </tr>
            <tr>
              <td>ARP</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Сопоставление IP-адресов с MAC-адресами в локальной сети.</td>
              <td>Использует широковещательные запросы для поиска MAC-адреса по IP.</td>
              <td>Обеспечение связи в локальной сети.</td>
              <td><span style="color: red;">show arp</span></td>
              <td>arp -a</td>
            </tr>
            <tr>
              <td>ICMP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Передача сообщений об ошибках и диагностических данных.</td>
              <td>Используется для ping и traceroute, не имеет портов.</td>
              <td>Диагностика сети (например, проверка доступности хоста).</td>
              <td><span style="color: red;">ping IP_ADDRESS</span></td>
              <td>ping IP_ADDRESS</td>
            </tr>
            <tr>
              <td>DNS</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Преобразование доменных имён в IP-адреса.</td>
              <td>Работает на портах 53 (UDP для запросов, TCP для больших ответов).</td>
              <td>Доступ к веб-сайтам по доменному имени.</td>
              <td><span style="color: red;">ip name-server IP, show ip dns</span></td>
              <td>nslookup DOMAIN_NAME</td>
            </tr>
            <tr>
              <td>HTTP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Передача гипертекстовых данных (веб-страниц).</td>
              <td>Работает на порту 80, использует TCP, stateless-протокол.</td>
              <td>Доступ к веб-сайтам.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>curl http://example.com</td>
            </tr>
            <tr>
              <td>HTTPS</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Защищённая передача гипертекстовых данных с шифрованием.</td>
              <td>Работает на порту 443, использует SSL/TLS для шифрования.</td>
              <td>Безопасный доступ к веб-сайтам (например, онлайн-банкинг).</td>
              <td><span style="color: red;">N/A</span></td>
              <td>curl https://example.com</td>
            </tr>
            <tr>
              <td>FTP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Передача файлов между хостами.</td>
              <td>Использует порты 20 (данные) и 21 (управление), работает на TCP.</td>
              <td>Передача файлов на сервер (например, загрузка сайта).</td>
              <td><span style="color: red;">N/A</span></td>
              <td>ftp HOST</td>
            </tr>
            <tr>
              <td>SFTP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Безопасная передача файлов с шифрованием.</td>
              <td>Работает через SSH на порту 22, использует шифрование.</td>
              <td>Безопасная загрузка файлов на сервер.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>sftp USER@HOST</td>
            </tr>
            <tr>
              <td>SSH</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Безопасный удалённый доступ к устройству.</td>
              <td>Работает на порту 22, использует шифрование для защиты данных.</td>
              <td>Удалённое управление серверами или маршрутизаторами.</td>
              <td><span style="color: red;">ip ssh, show ip ssh</span></td>
              <td>ssh USER@HOST</td>
            </tr>
            <tr>
              <td>Telnet</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Удалённый доступ к устройству (незащищённый).</td>
              <td>Работает на порту 23, передача данных в открытом виде.</td>
              <td>Удалённое управление (устаревший, заменён SSH).</td>
              <td><span style="color: red;">line vty 0 4, transport input telnet</span></td>
              <td>telnet HOST</td>
            </tr>
            <tr>
              <td>SMTP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Передача электронной почты между серверами.</td>
              <td>Работает на порту 25, использует TCP.</td>
              <td>Отправка email-сообщений.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>POP3</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Получение электронной почты с сервера.</td>
              <td>Работает на порту 110, использует TCP, удаляет письма с сервера после загрузки.</td>
              <td>Получение email в почтовом клиенте.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>IMAP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Получение электронной почты с сервера с синхронизацией.</td>
              <td>Работает на порту 143, использует TCP, оставляет письма на сервере.</td>
              <td>Синхронизация email между устройствами.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>NTP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Синхронизация времени между устройствами.</td>
              <td>Работает на порту 123, использует UDP.</td>
              <td>Синхронизация времени на серверах и маршрутизаторах.</td>
              <td><span style="color: red;">ntp server IP, show ntp status</span></td>
              <td>w32tm /query /status</td>
            </tr>
            <tr>
              <td>LACP</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Агрегация каналов для повышения пропускной способности.</td>
              <td>Часть стандарта 802.3ad, автоматически настраивает агрегацию каналов.</td>
              <td>Объединение нескольких физических каналов в один логический.</td>
              <td><span style="color: red;">channel-group NUMBER mode active, show etherchannel</span></td>
              <td>netsh interface show interface</td>
            </tr>
            <tr>
              <td>LLDP</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Обнаружение соседних устройств в сети (аналог CDP).</td>
              <td>Открытый стандарт (802.1AB), предоставляет информацию о соседях.</td>
              <td>Обнаружение топологии сети.</td>
              <td><span style="color: red;">lldp run, show lldp neighbors</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>CDP</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Обнаружение соседних устройств Cisco.</td>
              <td>Проприетарный протокол Cisco, предоставляет информацию о соседних устройствах.</td>
              <td>Обнаружение топологии сети в средах Cisco.</td>
              <td><span style="color: red;">cdp run, show cdp neighbors</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>GRE</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Инкапсуляция пакетов для создания туннелей.</td>
              <td>Позволяет передавать любой протокол через IP, часто используется с IPsec.</td>
              <td>Создание VPN-туннелей.</td>
              <td><span style="color: red;">interface tunnel NUMBER, show ip gre</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>PPPoE</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Инкапсуляция PPP через Ethernet для аутентификации.</td>
              <td>Используется провайдерами для подключения клиентов.</td>
              <td>Подключение к интернету через DSL.</td>
              <td><span style="color: red;">pppoe enable, show pppoe session</span></td>
              <td>rasdial</td>
            </tr>
            <tr>
              <td>L2TP</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Создание туннелей для VPN-соединений.</td>
              <td>Часто используется с IPsec для шифрования.</td>
              <td>Удалённый доступ через VPN.</td>
              <td><span style="color: red;">interface virtual-template NUMBER, show l2tp</span></td>
              <td>netsh ras show link</td>
            </tr>
            <tr>
              <td>IS-IS</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Протокол маршрутизации (Link-State).</td>
              <td>Используется в крупных сетях, поддерживает IPv4 и IPv6.</td>
              <td>Маршрутизация в сетях провайдеров.</td>
              <td><span style="color: red;">router isis, show isis neighbors</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>IGMP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Управление многоадресной рассылкой (multicast).</td>
              <td>Позволяет устройствам присоединяться к многоадресным группам.</td>
              <td>IPTV, видеоконференции.</td>
              <td><span style="color: red;">ip igmp join-group, show ip igmp groups</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>PIM</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Маршрутизация многоадресного трафика.</td>
              <td>Поддерживает режимы Sparse Mode (SM) и Dense Mode (DM).</td>
              <td>Передача многоадресного трафика (например, IPTV).</td>
              <td><span style="color: red;">ip pim sparse-mode, show ip pim neighbor</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>QUIC</td>
              <td>Транспортный (OSI: 4, TCP/IP: Transport)</td>
              <td>Протокол для быстрой и безопасной передачи данных.</td>
              <td>Разработан Google, использует UDP, заменяет TCP для HTTP/3.</td>
              <td>Ускорение загрузки веб-страниц (HTTP/3).</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>RSVP</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Резервирование ресурсов для обеспечения QoS.</td>
              <td>Используется для управления пропускной способностью.</td>
              <td>Обеспечение качества обслуживания для VoIP.</td>
              <td><span style="color: red;">ip rsvp bandwidth, show ip rsvp</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>VRF</td>
              <td>Сетевой (OSI: 3, TCP/IP: Internet)</td>
              <td>Виртуализация маршрутизации и пересылки.</td>
              <td>Позволяет создавать изолированные таблицы маршрутизации.</td>
              <td>Разделение трафика в сетях провайдеров.</td>
              <td><span style="color: red;">ip vrf NAME, show ip vrf</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>802.1Q</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Тегирование VLAN для сегментации сети.</td>
              <td>Добавляет тег VLAN в кадр Ethernet.</td>
              <td>Разделение трафика в сетях с VLAN.</td>
              <td><span style="color: red;">switchport mode trunk, show vlan</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>Frame Relay</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Передача данных через виртуальные каналы (устаревший).</td>
              <td>Использует DLCI для идентификации каналов.</td>
              <td>Соединение офисов через WAN (устаревший).</td>
              <td><span style="color: red;">frame-relay map ip, show frame-relay map</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>ATM</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Передача данных с фиксированными ячейками (устаревший).</td>
              <td>Использует ячейки по 53 байта, подходит для голоса и видео.</td>
              <td>Телекоммуникационные сети (устаревший).</td>
              <td><span style="color: red;">interface atm NUMBER, show atm pvc</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>ISDN</td>
              <td>Канальный (OSI: 2, TCP/IP: Link)</td>
              <td>Цифровая телефония и передача данных (устаревший).</td>
              <td>Поддерживает голос, видео и данные через B- и D-каналы.</td>
              <td>Резервное соединение (устаревший).</td>
              <td><span style="color: red;">interface bri NUMBER, show isdn status</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>NetBIOS</td>
              <td>Сеансовый (OSI: 5, TCP/IP: Application)</td>
              <td>Обеспечение связи между приложениями в локальной сети.</td>
              <td>Часто используется с SMB для обмена файлами.</td>
              <td>Обмен файлами в старых сетях Windows.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>nbtstat -a HOST</td>
            </tr>
            <tr>
              <td>SMB</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Обмен файлами и принтерами в локальной сети.</td>
              <td>Работает на портах 445 и 139, используется в Windows.</td>
              <td>Общий доступ к файлам в Windows-сетях.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>net use \\HOST\SHARE</td>
            </tr>
            <tr>
              <td>RTP</td>
              <td>Транспортный (OSI: 4, TCP/IP: Transport)</td>
              <td>Передача мультимедийных данных в реальном времени.</td>
              <td>Работает поверх UDP, используется с RTCP для контроля.</td>
              <td>VoIP, видеоконференции.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>RTCP</td>
              <td>Транспортный (OSI: 4, TCP/IP: Transport)</td>
              <td>Контроль качества передачи мультимедийных данных.</td>
              <td>Работает с RTP, предоставляет статистику (задержка, потери).</td>
              <td>Мониторинг качества VoIP-соединений.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>SIP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Инициирование и управление мультимедийными сессиями.</td>
              <td>Работает на порту 5060 (TCP/UDP), используется для VoIP.</td>
              <td>Установка VoIP-звонков.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>LDAP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Доступ и управление каталогами (например, Active Directory).</td>
              <td>Работает на порту 389 (TCP), LDAPS — на 636.</td>
              <td>Аутентификация пользователей в Active Directory.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>ldifde -f export.ldf</td>
            </tr>
            <tr>
              <td>RADIUS</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Аутентификация, авторизация и учёт (AAA).</td>
              <td>Работает на портах 1812 (аутентификация) и 1813 (учёт), использует UDP.</td>
              <td>Аутентификация пользователей в Wi-Fi-сетях.</td>
              <td><span style="color: red;">aaa new-model, show aaa sessions</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>TACACS+</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Аутентификация, авторизация и учёт (AAA) для устройств.</td>
              <td>Проприетарный протокол Cisco, работает на TCP (порт 49).</td>
              <td>Управление доступом к сетевым устройствам.</td>
              <td><span style="color: red;">tacacs-server host IP, show tacacs</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>IPX/SPX</td>
              <td>Сетевой/Транспортный (OSI: 3-4)</td>
              <td>Сетевой протокол для устаревших сетей Novell NetWare.</td>
              <td>Аналог TCP/IP, но устаревший, не совместим с современными сетями.</td>
              <td>Сети Novell NetWare (устаревший).</td>
              <td><span style="color: red;">ipx routing, show ipx route</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>AppleTalk</td>
              <td>Сетевой/Транспортный (OSI: 3-4)</td>
              <td>Сетевой протокол для устаревших сетей Apple.</td>
              <td>Устаревший, использовался для обмена данными между устройствами Apple.</td>
              <td>Сети Apple (устаревший).</td>
              <td><span style="color: red;">appletalk routing, show appletalk route</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>DECnet</td>
              <td>Сетевой/Транспортный (OSI: 3-4)</td>
              <td>Сетевой протокол для устаревших систем Digital Equipment Corporation.</td>
              <td>Устаревший, использовался в системах DEC.</td>
              <td>Сети DEC (устаревший).</td>
              <td><span style="color: red;">decnet routing, show decnet route</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>WebSocket</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Полнодуплексное соединение для веб-приложений.</td>
              <td>Работает поверх TCP, используется для чатов и уведомлений.</td>
              <td>Чаты, уведомления в реальном времени.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>CoAP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Протокол для устройств IoT с ограниченными ресурсами.</td>
              <td>Работает на UDP, лёгкий аналог HTTP.</td>
              <td>Управление устройствами IoT.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>MQTT</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Протокол обмена сообщениями для IoT.</td>
              <td>Лёгкий, работает на TCP, использует модель publisher/subscriber.</td>
              <td>Управление умными домами.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
            <tr>
              <td>AMQP</td>
              <td>Прикладной (OSI: 7, TCP/IP: Application)</td>
              <td>Протокол обмена сообщениями для корпоративных систем.</td>
              <td>Надёжный, работает на TCP, поддерживает очереди сообщений.</td>
              <td>Обмен сообщениями в корпоративных приложениях.</td>
              <td><span style="color: red;">N/A</span></td>
              <td>N/A</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  document.querySelector('.back-btn').addEventListener('click', () => {
    loadNetworkBuildingContent(container);
  });
}

function loadCorporateNetworkContent(container) {
    container.innerHTML = `
      <div class="network-building-container">
        <button class="back-btn">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="19" y1="12" x2="5" y2="12"></line>
            <polyline points="12 19 5 12 12 5"></polyline>
          </svg>
          Назад
        </button>
        <h1>Построение корпоративной сети</h1>
        <p>Корпоративная сеть — это сетевая инфраструктура, которая объединяет устройства, пользователей и приложения внутри организации. Она должна быть масштабируемой, надёжной, безопасной и управляемой, чтобы обеспечивать бесперебойную работу бизнеса. Построение корпоративной сети требует тщательного планирования, включая выбор топологии, сегментацию, настройку оборудования и внедрение мер безопасности.</p>

        <h2>Основные принципы построения корпоративной сети</h2>
        <div class="osi-table-container">
          <table class="osi-table">
            <thead>
              <tr>
                <th>Аспект</th>
                <th>Описание</th>
                <th>Пример применения</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Иерархическая модель</strong></td>
                <td>Сеть делится на уровни: доступ (Access), агрегация (Distribution), ядро (Core).</td>
                <td>Уровень доступа — подключение рабочих станций, ядро — маршрутизация между филиалами.</td>
              </tr>
              <tr>
                <td><strong>Сегментация</strong></td>
                <td>Разделение сети на VLAN для изоляции трафика отделов (например, бухгалтерия, IT).</td>
                <td>Создание VLAN 10 для бухгалтерии и VLAN 20 для IT с разными политиками доступа.</td>
              </tr>
              <tr>
                <td><strong>Безопасность</strong></td>
                <td>Использование межсетевых экранов, ACL, шифрования (IPsec), мониторинга (IDS/IPS).</td>
                <td>Настройка ACL для ограничения доступа между VLAN, использование IPsec для VPN.</td>
              </tr>
              <tr>
                <td><strong>Отказоустойчивость</strong></td>
                <td>Резервирование каналов (LACP), шлюзов (VRRP/HSRP), источников питания (UPS).</td>
                <td>Настройка VRRP для резервирования шлюза, LACP для агрегации каналов.</td>
              </tr>
              <tr>
                <td><strong>Производительность</strong></td>
                <td>Оптимизация с помощью QoS, балансировки нагрузки, выбора оборудования.</td>
                <td>Настройка QoS для приоритизации VoIP-трафика над веб-трафиком.</td>
              </tr>
              <tr>
                <td><strong>Мониторинг</strong></td>
                <td>Использование SNMP, NetFlow, syslog для анализа состояния сети.</td>
                <td>Настройка NetFlow для анализа трафика и выявления аномалий.</td>
              </tr>
              <tr>
                <td><strong>Масштабируемость</strong></td>
                <td>Проектирование с учётом роста: динамическая маршрутизация (OSPF, BGP), модульность.</td>
                <td>Использование OSPF для автоматической маршрутизации при добавлении новых подсетей.</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h2>Сегментация корпоративной сети</h2>
        <p>Сегментация — это разделение корпоративной сети на логические сегменты для повышения безопасности, производительности и управляемости. Основной метод сегментации — использование VLAN (Virtual Local Area Network), которые изолируют трафик между различными группами пользователей или устройств. Вот как правильно сегментировать корпоративную сеть:</p>
        <ul>
          <li><strong>Разделение по отделам:</strong> Создайте отдельные VLAN для каждого отдела (например, VLAN 10 для IT, VLAN 20 для бухгалтерии, VLAN 30 для маркетинга). Это позволяет изолировать трафик и минимизировать риски, такие как ARP-спуфинг или широковещательные штормы. Например, сотрудники бухгалтерии не смогут напрямую получить доступ к серверам IT-отдела.</li>
          <li><strong>Гостевая сеть:</strong> Настройте отдельную VLAN для гостевого доступа (например, VLAN 100). Гостевая сеть должна быть полностью изолирована от корпоративных ресурсов и иметь ограниченный доступ только к интернету. Для повышения безопасности можно настроить captive portal с аутентификацией для гостей.</li>
          <li><strong>Сеть для устройств IoT:</strong> Устройства Интернета вещей (IoT), такие как IP-камеры или умные датчики, должны быть в отдельной VLAN (например, VLAN 200). Это снижает риск компрометации корпоративной сети, если устройство IoT будет взломано. Например, IP-камеры не должны иметь прямого доступа к серверам с данными.</li>
          <li><strong>Управленческая сеть:</strong> Создайте VLAN для управления сетевыми устройствами (например, VLAN 999). Эта сеть должна быть доступна только для администраторов и защищена строгими правилами доступа (например, через ACL или VPN).</li>
          <li><strong>Межсетевые экраны между VLAN:</strong> Настройте маршрутизацию между VLAN через межсетевой экран или маршрутизатор с поддержкой ACL (Access Control Lists). Например, можно разрешить доступ из VLAN бухгалтерии к серверу ERP, но запретить доступ к другим ресурсам.</li>
        </ul>
        <p>Сегментация также помогает оптимизировать производительность: например, широковещательный трафик (broadcast) ограничивается пределами одной VLAN, что снижает нагрузку на сеть. Для управления VLAN используйте протоколы маршрутизации (например, OSPF) и настройте DHCP для автоматического назначения IP-адресов в каждой VLAN.</p>

        <h2>Иерархическая модель корпоративной сети</h2>
        <p>Корпоративные сети часто строятся по иерархической модели, которая делит сеть на три уровня: Access (доступ), Distribution (агрегация) и Core (ядро). Каждый уровень выполняет свою роль:</p>
        <ul>
          <li><strong>Уровень Access (доступ):</strong> Это нижний уровень, где подключаются конечные устройства (рабочие станции, принтеры, IP-телефоны). Коммутаторы уровня доступа поддерживают PoE (Power over Ethernet) для питания устройств, таких как IP-телефоны, и обеспечивают базовую безопасность (например, Port Security для ограничения подключений).</li>
          <li><strong>Уровень Distribution (агрегация):</strong> Этот уровень агрегирует трафик от уровня доступа и передаёт его на уровень ядра. Коммутаторы уровня агрегации поддерживают маршрутизацию (Layer 3), фильтрацию трафика (ACL) и резервирование (например, через HSRP или VRRP). Здесь также настраиваются политики безопасности, такие как ограничение доступа между VLAN.</li>
          <li><strong>Уровень Core (ядро):</strong> Уровень ядра отвечает за высокоскоростную маршрутизацию между различными сегментами сети (например, между филиалами или дата-центрами). Устройства уровня ядра (обычно маршрутизаторы или мощные коммутаторы) обеспечивают максимальную производительность и минимальные задержки. На этом уровне не должно быть сложной фильтрации, чтобы не снижать скорость.</li>
        </ul>
        <p>Иерархическая модель упрощает масштабирование: например, для добавления нового отдела достаточно подключить новый коммутатор уровня доступа к уровню агрегации. Она также повышает надёжность: если один коммутатор уровня доступа выйдет из строя, остальные сегменты сети продолжат работать.</p>

        <h3>Пример иерархической модели сети (график)</h3>
        <div style="margin: 20px 0;">
          <svg width="600" height="200" xmlns="http://www.w3.org/2000/svg">
            <!-- Уровень Core -->
            <rect x="50" y="20" width="500" height="50" fill="#a9dfbf" stroke="#2a3b4c" stroke-width="2"/>
            <text x="300" y="50" text-anchor="middle" fill="#2a3b4c">Уровень Core (Ядро)</text>

            <!-- Уровень Distribution -->
            <rect x="50" y="90" width="500" height="50" fill="#f9e79f" stroke="#2a3b4c" stroke-width="2"/>
            <text x="300" y="120" text-anchor="middle" fill="#2a3b4c">Уровень Distribution (Агрегация)</text>

            <!-- Уровень Access -->
            <rect x="50" y="160" width="500" height="30" fill="#d4e6f1" stroke="#2a3b4c" stroke-width="2"/>
            <text x="300" y="180" text-anchor="middle" fill="#2a3b4c">Уровень Access (Доступ)</text>
          </svg>
        </div>

        <h2>Защита корпоративной сети</h2>
        <p>Безопасность корпоративной сети — это критически важный аспект, который защищает данные, приложения и пользователей от угроз. Вот основные меры защиты:</p>
        <ul>
          <li><strong>Контроль доступа:</strong> Используйте протоколы 802.1X для аутентификации устройств перед подключением к сети. Настройте ролевые политики доступа (RBAC) для ограничения прав пользователей. Например, сотрудники маркетинга не должны иметь доступ к серверам бухгалтерии.</li>
          <li><strong>Шифрование:</strong> Применяйте шифрование для защиты данных при передаче (например, через IPsec или TLS). Для удалённого доступа настройте VPN (например, с помощью OpenVPN или Cisco AnyConnect) с многофакторной аутентификацией (MFA).</li>
          <li><strong>Межсетевые экраны и ACL:</strong> Установите межсетевые экраны (например, Cisco ASA, Fortinet FortiGate) на границе сети и между VLAN. Настройте списки контроля доступа (ACL) для фильтрации трафика. Например, запретите прямой доступ из гостевой сети к корпоративным серверам.</li>
          <li><strong>IDS/IPS:</strong> Внедрите системы обнаружения и предотвращения вторжений (например, Snort, Cisco Secure IPS) для мониторинга и защиты от атак, таких как SQL-инъекции или эксплойты.</li>
          <li><strong>Антивирусы и EDR:</strong> Установите антивирусное ПО (например, Kaspersky Endpoint Security) и решения EDR (Endpoint Detection and Response, например, CrowdStrike) на все рабочие станции и серверы для защиты от вредоносного ПО.</li>
          <li><strong>Мониторинг и SIEM:</strong> Используйте системы мониторинга (например, Zabbix) и SIEM (например, Splunk, QRadar) для анализа логов и выявления аномалий. Например, SIEM может обнаружить множественные неудачные попытки входа, что может указывать на атаку методом перебора паролей (brute force).</li>
          <li><strong>Защита от DDoS:</strong> Настройте защиту от DDoS-атак на уровне провайдера или с помощью решений, таких как Cloudflare. Также можно использовать ограничение скорости запросов (rate limiting) на межсетевых экранах.</li>
          <li><strong>Физическая безопасность:</strong> Ограничьте физический доступ к сетевому оборудованию (например, коммутаторам, маршрутизаторам) с помощью замков на шкафах и систем видеонаблюдения.</li>
        </ul>

        <h2>Рекомендации по построению и управлению корпоративной сетью</h2>
        <ol>
          <li><strong>Планирование и документирование:</strong> Перед внедрением сети составьте схему (например, в Cisco Packet Tracer или GNS3), определите IP-адресацию и VLAN. Ведите документацию (схемы, таблицы IP-адресов, настройки оборудования) для упрощения управления.</li>
          <li><strong>Выбор оборудования:</strong> Используйте надёжное оборудование: для уровня доступа — коммутаторы с поддержкой PoE (например, Cisco Catalyst 9200), для уровня агрегации — коммутаторы Layer 3 (например, Cisco Catalyst 9300), для ядра — маршрутизаторы или мощные коммутаторы (например, Cisco Nexus).</li>
          <li><strong>Резервирование:</strong> Настройте резервирование на всех уровнях: агрегацию каналов (LACP) для повышения пропускной способности, VRRP/HSRP для резервирования шлюзов, резервные каналы связи (например, через MPLS или SD-WAN).</li>
          <li><strong>Мониторинг и управление:</strong> Используйте протоколы SNMP и NetFlow для мониторинга состояния сети. Внедрите централизованное управление с помощью систем, таких как Cisco DNA Center или SolarWinds, для упрощения настройки и устранения неисправностей.</li>
          <li><strong>Обновление ПО:</strong> Регулярно обновляйте прошивки сетевых устройств, чтобы устранять уязвимости. Планируйте обновления в периоды минимальной нагрузки, чтобы избежать простоев.</li>
          <li><strong>Обучение персонала:</strong> Проводите обучение сотрудников по безопасному использованию сети (например, не подключать личные устройства к корпоративной сети) и распознаванию фишинговых атак.</li>
          <li><strong>Тестирование:</strong> Проводите регулярные тесты на проникновение (penetration testing) и стресс-тесты сети, чтобы выявить слабые места и проверить производительность.</li>
        </ol>

        <h2>Пример атаки на корпоративную сеть</h2>
        <p>Одним из известных примеров атаки на корпоративную сеть является инцидент с Target в 2013 году. Злоумышленники получили доступ к сети через подрядчика, украв учётные данные для системы управления HVAC (отопление, вентиляция, кондиционирование). Затем они переместились по сети, обойдя сегментацию, и украли данные 40 миллионов кредитных карт. Этот случай подчёркивает важность сегментации, контроля доступа и мониторинга в корпоративных сетях.</p>
      </div>
    `;

    document.querySelector('.back-btn').addEventListener('click', () => {
      loadNetworkBuildingContent(container);
    });
}
