#!/bin/bash
# Чек-лист проверок. Каждый вызов: check "Раздел" "Проверка" "Команда"
#
# Комментарий перед каждой проверкой объясняет, ЧТО она проверяет.
# Разделы группируются автоматически по порядку следования.

# =====================================================================
# УЧЁТНЫЕ ЗАПИСИ
# =====================================================================

# Полный список локальных учётных записей — базовая инвентаризация.
# Нужен, чтобы найти общие УЗ, лишних пользователей, УЗ без пароля.
check "Учётные записи" "Список всех УЗ" \
  "cat /etc/passwd"

# Поиск общих УЗ (admin/user/test). По политике ИБ они запрещены,
# т.к. невозможно отследить, кто именно выполнял действия.
check "Учётные записи" "Общие УЗ (admin/user/test)" \
  "grep -E '^(admin|user|test):' /etc/passwd || echo 'общих УЗ нет'"

# Дубликаты UID — признак некорректного управления УЗ.
# Каждый пользователь должен иметь уникальный UID.
check "Учётные записи" "Дубликаты UID" \
  "awk -F: '{print \$3}' /etc/passwd | sort | uniq -d"

# Сервисные УЗ с интерактивным shell — потенциальная дыра.
# Сервисные учётки должны иметь /usr/sbin/nologin или /bin/false.
check "Учётные записи" "Сервисные УЗ с shell" \
  "awk -F: '(\$3 < 1000 && \$7 !~ /(nologin|false)/) {print \$1 \" — \" \$7}' /etc/passwd"

# Последние входы под root. Прямой вход root запрещён —
# все админ-действия должны идти через sudo с персональной УЗ.
check "Учётные записи" "Входы под root" \
  "last root 2>/dev/null | head -10"

# Запрет прямого входа root по SSH — обязательное требование ИБ.
check "Учётные записи" "PermitRootLogin" \
  "grep -E '^PermitRootLogin' /etc/ssh/sshd_config || echo 'не найдено'"

# Проверка действующей конфигурации sshd (не только файла).
# sshd -T показывает реальные параметры после всех include.
check "Учётные записи" "PermitRootLogin (действующая конфигурация - sshd -T)" \
  "sshd -T 2>/dev/null | grep permitrootlogin || echo 'не найдено'"

# =====================================================================
# ПАРОЛЬНАЯ ПОЛИТИКА
# =====================================================================

# Параметры сложности паролей: minlen, minclass, reject_username, dictcheck.
# Без них пользователи смогут ставить простые пароли.
check "Парольная политика" "Параметры pwquality" \
  "cat /etc/security/pwquality.conf 2>/dev/null || echo 'ФАЙЛ ОТСУТСТВУЕТ'"

# Подключён ли модуль pam_pwquality в PAM — без него pwquality.conf бесполезен.
check "Парольная политика" "PAM pam_pwquality" \
  "grep pam_pwquality /etc/pam.d/common-password 2>/dev/null || grep pam_pwquality /etc/pam.d/system-auth 2>/dev/null || echo 'не найден'"

# Пустые пароли в /etc/shadow — критическая уязвимость.
# Такие УЗ можно использовать без аутентификации.
check "Парольная политика" "Пустые пароли" \
  "awk -F: '(\$2 == \"\") {print \$1}' /etc/shadow 2>/dev/null"

# Алгоритм хеширования паролей. Должен быть SHA-512 ($6$).
# MD5, DES, SHA-256 — устаревшие и небезопасные.
check "Парольная политика" "Алгоритм хеша (SHA-512)" \
  "awk -F: '(\$2 ~ /^\\\$6\\\$/) {print \$1 \" — SHA-512\"}' /etc/shadow 2>/dev/null; awk -F: '(\$2 !~ /^\\\$6\\\$/ && \$2 !~ /^!/ && \$2 !~ /^\\*/) {print \$1 \" — НЕ SHA-512\"}' /etc/shadow 2>/dev/null"

# Срок действия пароля в login.defs. По политике — 90 дней (60 для админов).
check "Парольная политика" "Срок действия (login.defs)" \
  "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs 2>/dev/null"

# Реальный срок действия для каждого пользователя (может отличаться
# от login.defs, если УЗ создана до изменения политики).
check "Парольная политика" "Срок действия для пользователей" \
  "for u in \$(awk -F: '\$3>=1000 && \$3<65534 {print \$1}' /etc/passwd); do echo \"=== \$u ===\"; chage -l \"\$u\" 2>/dev/null; done"

# Запрет повторного использования паролей. По политике — 5 (10 для админов).
# Без этого пользователи смогут менять пароль на тот же самый.
check "Парольная политика" "Remember (история паролей)" \
  "grep -r remember /etc/pam.d/ 2>/dev/null || echo 'remember не найден'"

# Список администраторов. Минимальный набор в группах sudo/admins/wheel.
check "Парольная политика" "Админы (группы)" \
  "getent group sudo admins wheel 2>/dev/null || echo 'группа не найдена'"

# Срок действия пароля для админов (должен быть ≤60 дней).
check "Парольная политика" "Срок действия для админов" \
  "for u in \$(getent group sudo admins wheel 2>/dev/null | cut -d: -f4 | tr ',' ' '); do echo \"=== \$u ===\"; chage -l \"\$u\" 2>/dev/null; done"

# Алгоритм шифрования паролей в системе. Должен быть SHA512.
check "Парольная политика" "ENCRYPT_METHOD" \
  "grep ENCRYPT_METHOD /etc/login.defs 2>/dev/null || echo 'не найдено'"

# Поиск паролей в открытом виде в конфигах и скриптах — критическая утечка.
check "Парольная политика" "Пароли в открытом виде" \
  "grep -rInE '(password|passwd|secret|token)\s*=' /etc /opt /srv 2>/dev/null | head -10"

# Наличие секрет-менеджера (Vault, Ansible Vault) — для безопасного
# хранения секретов вместо открытых файлов.
check "Парольная политика" "Секрет-менеджер" \
  "which vault ansible-vault 2>/dev/null || echo 'не найден'"

# Ограничение команды su: только группа admins может повышать привилегии.
check "Парольная политика" "Ограничение su (pam_wheel)" \
  "grep -E 'pam_wheel' /etc/pam.d/su 2>/dev/null; getent group admins 2>/dev/null"

# Полный набор параметров парольной политики в login.defs.
# Проверяет, что заданы все обязательные параметры.
check "Парольная политика" "Параметры login.defs (полные)" \
  "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|LOG_UNKFAIL_ENAB|FAILLOG_ENAB|LOG_OK_LOGINS|ENCRYPT_METHOD' /etc/login.defs 2>/dev/null"

# Sudo-правила — проверка на избыточные привилегии.
check "Парольная политика" "Sudo-правила" \
  "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^#|^$'"

# NOPASSWD в sudo — опасная практика, должна быть обоснована.
check "Парольная политика" "NOPASSWD в sudo" \
  "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'не найден'"

# Часовой пояс (должен быть Europe/Moscow) и пароль root (должен быть установлен).
check "Парольная политика" "Часовой пояс и пароль root" \
  "timedatectl 2>/dev/null; cat /etc/timezone 2>/dev/null; passwd -S root 2>/dev/null"

# =====================================================================
# ЛОГИРОВАНИЕ
# =====================================================================

# Статус rsyslog — основного демона логирования в Linux.
# Если не работает — события безопасности нигде не сохраняются.
check "Логирование" "Статус rsyslog" \
  "systemctl status rsyslog 2>/dev/null | head -3"

# Статус systemd-journald — альтернативного механизма логирования.
check "Логирование" "Статус systemd-journald" \
  "systemctl status systemd-journald 2>/dev/null | head -3"

# Ключевые лог-файлы: auth.log (аутентификация), syslog (общие события).
# Если их нет — система не логирует.
check "Логирование" "Ключевые логи" \
  "ls -la /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null || echo 'логи не найдены'"

# Права на auth.log. Должны быть 640 root:adm —
# иначе любой пользователь сможет прочитать или изменить лог.
check "Логирование" "Права на auth.log" \
  "ls -la /var/log/auth.log /var/log/secure 2>/dev/null"

# События sshd в auth.log — подтверждение, что логи наполняются.
check "Логирование" "События sshd в auth.log" \
  "grep -i sshd /var/log/auth.log 2>/dev/null | tail -5"

# События sudo в auth.log — подтверждение, что действия админов логируются.
check "Логирование" "События sudo в auth.log" \
  "grep -i sudo /var/log/auth.log 2>/dev/null | tail -5"

# Настройка логирования sudo: logfile, log_input, log_output.
check "Логирование" "Логирование sudo (Defaults)" \
  "grep -E 'Defaults.*log' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'не найдено'"

# Содержимое /var/log/sudo.log — проверка, что лог наполняется.
check "Логирование" "Содержимое /var/log/sudo.log" \
  "cat /var/log/sudo.log 2>/dev/null | tail -10 || echo 'лог не найден'"

# Ротация логов — чтобы диск не переполнился и старые логи не терялись.
check "Логирование" "Ротация логов" \
  "cat /etc/logrotate.d/rsyslog 2>/dev/null || echo 'не найдено'"

# Централизованный сбор (rsyslog forwarding на SIEM).
# Без него при компрометации хоста логи можно уничтожить.
check "Логирование" "Централизованный сбор" \
  "grep -rE '^\\*\\.\\*.*@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo 'не настроен'"



# =====================================================================
# ОТКРЫТЫЕ ПОРТЫ
# =====================================================================

# Список всех слушающих портов — базовая инвентаризация.
# Помогает найти лишние сервисы и неизвестные процессы.
check "Открытые порты" "Слушающие порты" \
  "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || echo 'недоступно'"

# Открытые порты с точки зрения файрвола — какие сервисы разрешены.
check "Открытые порты" "Открытые порты и сервисы" \
  "firewall-cmd --list-all 2>/dev/null || iptables -L -n 2>/dev/null || echo 'не найдено'"

# =====================================================================
# ФАЙРВОЛ
# =====================================================================

# Наличие и состояние ufw (Ubuntu/Debian).
check "Файрвол" "Состояние ufw" \
  "ufw status verbose 2>/dev/null || echo 'ufw не настроен'"

# Наличие и состояние firewalld (RHEL/CentOS).
check "Файрвол" "Состояние firewalld" \
  "firewall-cmd --list-all 2>/dev/null || echo 'firewalld не настроен'"

# Наличие и состояние iptables (универсально).
check "Файрвол" "Состояние iptables" \
  "iptables -L -n 2>/dev/null || echo 'iptables не настроен'"

# Правила iptables в кратком формате — удобно для анализа.
check "Файрвол" "Правила iptables (кратко)" \
  "iptables -S 2>/dev/null"

# NAT-правила — важны для маршрутизации и маскарадинга.
check "Файрвол" "NAT-правила" \
  "iptables -t nat -L -n 2>/dev/null"

# Политики цепочек INPUT/FORWARD/OUTPUT.
# Должны быть DROP для deny by default.
check "Файрвол" "Политики цепочек (deny by default)" \
  "iptables -S 2>/dev/null | grep -E '^-P'"

# =====================================================================
# СЕРВИСЫ (версии ПО, актуальность)
# =====================================================================

# Версия операционной системы — для проверки на EOL.
check "Сервисы" "Версия ОС" \
  "cat /etc/os-release 2>/dev/null | head -3"

# Версия ядра — для проверки актуальности и известных уязвимостей.
check "Сервисы" "Версия ядра" \
  "uname -a"

# Доступные обновления пакетов (Debian/Ubuntu).
check "Сервисы" "Доступные обновления (apt)" \
  "apt list --upgradable 2>/dev/null | head -20"

# Доступные обновления пакетов (RHEL/CentOS).
check "Сервисы" "Доступные обновления (dnf)" \
  "dnf check-update 2>/dev/null | head -20"

# Security-обновления — критичные исправления уязвимостей.
# Должны устанавливаться в приоритетном порядке.
check "Сервисы" "Security-обновления" \
  "apt list --upgradable 2>/dev/null | grep -i security || dnf updateinfo list security 2>/dev/null || echo 'не удалось проверить'"

# Автоматические обновления безопасности — снижают окно уязвимости.
check "Сервисы" "Автообновления" \
  "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo 'не настроено'"

# Включённые сервисы — проверка на лишние (принцип минимальной функциональности).
check "Сервисы" "Включённые сервисы" \
  "systemctl list-unit-files --state=enabled 2>/dev/null | head -30"

# Запущенные сервисы — то же, но для текущего состояния.
check "Сервисы" "Запущенные сервисы" \
  "systemctl list-units --type=service --state=running 2>/dev/null | head -30"

# Антивирус установлен — обязательное требование.
check "Сервисы" "Антивирус установлен" \
  "which clamscan 2>/dev/null; dpkg -l 2>/dev/null | grep -iE 'clamav|kaspersky|drweb' || rpm -qa 2>/dev/null | grep -iE 'clamav|kaspersky|drweb' || echo 'не найден'"

# Служба антивируса активна — иначе он бесполезен.
check "Сервисы" "Статус антивируса" \
  "systemctl status clamav-daemon 2>/dev/null | head -3 || echo 'служба не найдена'"

# Базы антивируса — должны быть свежими (не старше 1 дня).
check "Сервисы" "Базы антивируса" \
  "ls -la /var/lib/clamav/ 2>/dev/null || echo 'базы не найдены'"

# Сканирование по расписанию — антивирус должен работать не только вручную.
check "Сервисы" "Сканирование по расписанию" \
  "crontab -l 2>/dev/null | grep -i clam; ls /etc/cron.d/ /etc/cron.daily/ 2>/dev/null | grep -i clam; systemctl list-timers 2>/dev/null | grep -i clam || echo 'не найдено'"

# World-writable файлы — потенциальная возможность подмены.
check "Сервисы" "World-writable файлы" \
  "find / -xdev -type f -perm -0002 2>/dev/null | head -10"

# Защита сетевого стека от атак (redirects, source routing, syncookies).
check "Сервисы" "Защита сетевого стека (sysctl)" \
  "sysctl net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv4.tcp_syncookies 2>/dev/null"

# =====================================================================
# ОТДЕЛЬНЫЕ УЗ ДЛЯ СЕРВИСОВ
# =====================================================================

# Все процессы с владельцами — базовая инвентаризация.
# Показывает, под какими УЗ работают все процессы в системе.
# Если много сервисов под root — нарушение принципа отдельных УЗ.
check "Отдельные УЗ для сервисов" "Все процессы и их владельцы" \
  "ps -eo user,comm --no-headers 2>/dev/null | sort -u"

# Сервисные процессы без системных ядерных (kthreadd, kworker и т.п.).
# Показывает, какие пользовательские сервисы работают и под кем.
check "Отдельные УЗ для сервисов" "Сервисные процессы (без ядерных)" \
  "ps -eo user,pid,comm --no-headers 2>/dev/null | grep -vE '^\s*(root)\s+[0-9]+\s+\[' | sort -u"

# Сервисы systemd и их УЗ из unit-файлов.
# Показывает, какая УЗ назначена каждому сервису в конфигурации.
check "Отдельные УЗ для сервисов" "Сервисы systemd и их УЗ" \
  "systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print \$1}' | while read svc; do user=\$(systemctl show -p User --value \"\$svc\" 2>/dev/null); [ -z \"\$user\" ] && user='root (по умолчанию)'; echo \"\$svc → \$user\"; done"

# Сервисные УЗ с интерактивным shell — аномалия.
# Сервисные УЗ (UID < 1000) должны иметь /usr/sbin/nologin или /bin/false.
check "Отдельные УЗ для сервисов" "Сервисные УЗ с shell (аномалия)" \
  "awk -F: '(\$3 < 1000 && \$7 !~ /(nologin|false)/) {print \$1 \" — UID:\" \$3 \" — shell:\" \$7}' /etc/passwd"

# Процессы от root, кроме системных.
# Если видны nginx, samba, named, coredns — нарушение.
check "Отдельные УЗ для сервисов" "Процессы от root (кроме системных)" \
  "ps -eo user,pid,comm --no-headers 2>/dev/null | awk '\$1==\"root\"' | grep -vE '\\[|systemd|kthread|init|kworker|migration|rcu|watchdog|cpuhp'"

# --- Проверка конкретных сервисов ---

# Nginx: в конфиге должен быть user www-data или nginx, не root.
# Мастер-процесс от root, воркеры — от непривилегированной УЗ.
check "Отдельные УЗ для сервисов" "Nginx — пользователь" \
  "{ grep -E '^user' /etc/nginx/nginx.conf 2>/dev/null; ps aux 2>/dev/null | grep nginx | awk '{print \$1, \$11}' | sort -u; } || echo 'Nginx не установлен'"

# Samba: smbd/nmbd работают от root (норма), но доступ к файлам
# должен идти через force user или valid users.
check "Отдельные УЗ для сервисов" "Samba — пользователь" \
  "{ ps aux 2>/dev/null | grep -E 'smbd|nmbd' | awk '{print \$1, \$11}' | sort -u; grep -E 'force user|guest account' /etc/samba/smb.conf 2>/dev/null; } || echo 'Samba не установлена'"

# DNS (CoreDNS или named): процесс должен работать от своей УЗ.
check "Отдельные УЗ для сервисов" "DNS — пользователь" \
  "ps aux 2>/dev/null | grep -iE 'named|coredns' | grep -v grep | awk '{print \$1, \$11}' | sort -u || echo 'DNS-сервер не найден'"

# rsyslog: должен работать от syslog, а не от root.
check "Отдельные УЗ для сервисов" "rsyslog — пользователь" \
  "ps aux 2>/dev/null | grep rsyslog | grep -v grep | awk '{print \$1, \$11}' | sort -u || echo 'rsyslog не запущен'"

# FTP (vsftpd): должен работать от своей УЗ или через анонимного пользователя.
check "Отдельные УЗ для сервисов" "FTP — пользователь" \
  "ps aux 2>/dev/null | grep -iE 'vsftpd|proftpd|pure-ftpd' | grep -v grep | awk '{print \$1, \$11}' | sort -u || echo 'FTP-сервер не найден'"


# =====================================================================
# ВЕБ-СЕРВИСЫ (сокрытие информации)
# =====================================================================

# Версия Nginx — для проверки на EOL и известные уязвимости.
check "Веб-сервисы" "Версия Nginx" \
  "nginx -v 2>&1 || echo 'Nginx не установлен'"

# Пакет Nginx в системе — для проверки источника установки.
check "Веб-сервисы" "Пакет Nginx" \
  "dpkg -l 2>/dev/null | grep nginx || rpm -qa 2>/dev/null | grep nginx || echo 'пакет не найден'"

# Пользователь в nginx.conf — не должен быть root.
check "Веб-сервисы" "Пользователь в nginx.conf" \
  "grep -E '^user' /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# Мастер-процесс Nginx — не должен работать от root.
check "Веб-сервисы" "Мастер-процесс Nginx" \
  "ps aux 2>/dev/null | grep nginx | head -3"

# Логирование Nginx — access.log и error.log должны быть заданы.
check "Веб-сервисы" "Логирование Nginx" \
  "grep -E 'access_log|error_log' /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# Файлы логов Nginx — должны существовать и наполняться.
check "Веб-сервисы" "Файлы логов Nginx" \
  "ls -la /var/log/nginx/ 2>/dev/null || echo 'не найдено'"

# server_tokens off — скрытие версии Nginx от внешних пользователей.
check "Веб-сервисы" "server_tokens" \
  "grep server_tokens /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# Заголовки ответа веб-сервера — проверка, что версия не раскрывается.
check "Веб-сервисы" "Заголовки ответа" \
  "curl -I http://localhost 2>/dev/null | head -15"

# Лимиты размера запроса — защита от DoS.
check "Веб-сервисы" "Лимиты запроса" \
  "grep -E 'client_max_body_size|client_body_buffer_size|client_body_timeout|client_header_timeout' /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# Безопасные таймауты — защита от медленных атак.
check "Веб-сервисы" "Таймауты" \
  "grep -E 'keepalive_timeout|send_timeout|reset_timedout_connection' /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# SSL/TLS параметры — только TLSv1.2/1.3, стойкие шифры.
check "Веб-сервисы" "SSL/TLS" \
  "grep -E 'ssl_protocols|ssl_ciphers|ssl_session_tickets|ssl_session_timeout' /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# Security headers — защита от Clickjacking, XSS, MIME-sniffing.
check "Веб-сервисы" "Security headers" \
  "grep -E 'add_header' /etc/nginx/nginx.conf 2>/dev/null || echo 'не найдено'"

# Полная конфигурация Nginx — комплексная проверка ключевых параметров.
check "Веб-сервисы" "Полная конфигурация Nginx" \
  "nginx -T 2>/dev/null | grep -E 'server_tokens|client_max_body_size|add_header' || echo 'Nginx не установлен'"

# =====================================================================
# DNS-СЕРВИС
# =====================================================================

# Статус DNS-сервера. Проверяем оба варианта: named (BIND) и coredns.
# Если ни один не запущен — на хосте нет DNS-сервиса.
check "DNS-сервис" "Статус DNS-сервера (named/coredns)" \
  "{ systemctl status named 2>/dev/null | head -3; systemctl status coredns 2>/dev/null | head -3; } || ps aux 2>/dev/null | grep -iE 'named|coredns' | grep -v grep | head -3 || echo 'DNS-сервер не найден'"

# Конфигурация DNS-сервера. Для named — /etc/named.conf,
# для coredns — Corefile.
check "DNS-сервис" "Конфигурация DNS (named.conf / Corefile)" \
  "{ cat /etc/named.conf 2>/dev/null | head -20; cat /etc/coredns/Corefile 2>/dev/null | head -20; cat /Corefile 2>/dev/null | head -20; } || echo 'конфигурация не найдена'"

# Зоны DNS. Для named — /var/named/, для coredns — /etc/coredns/ или /zones/.
check "DNS-сервис" "Зоны DNS (каталоги)" \
  "{ ls -la /var/named/ 2>/dev/null; ls -la /etc/coredns/ 2>/dev/null; ls -la /zones/ 2>/dev/null; } || echo 'каталог зон не найден'"

# Слушает ли порт 53 — базовый признак работающего DNS.
check "DNS-сервис" "Порт 53 слушается" \
  "ss -tulnp 2>/dev/null | grep ':53' || echo 'порт 53 не слушается'"

# Проверка разрешения имени. Пробуем dig и nslookup,
# обращаемся к localhost.
check "DNS-сервис" "Разрешение имени (corp.local)" \
  "dig @127.0.0.1 corp.local +short 2>/dev/null || nslookup corp.local 127.0.0.1 2>/dev/null || echo 'разрешение не работает или утилиты недоступны'"

# Рекурсия. Для named — recursion no в named.conf.
# Для coredns — плагин forward или отсутствие рекурсии.
# Если в файле /etc/named.conf настроено recursion yes; 
# (или этот параметр вообще забыли указать), DNS-сервер становится публичным рекурсивным резолвером (Open Resolver). 
# Он начнет искать по всему интернету ответы на любые запросы от чужих компьютеров. 
# Хакеры используют это, чтобы отправлять на ваш сервер маленькие запросы с поддельным IP-адресом жертвы, 
# а ваш сервер будет заваливать жертву огромными ответами.
check "DNS-сервис" "Рекурсия (recursion)" \
  "{ grep -i 'recursion' /etc/named.conf 2>/dev/null; grep -iE 'forward|forwarders' /etc/coredns/Corefile 2>/dev/null; } || echo 'не найдено'"

# Allow-query — ограничение круга клиентов, которым DNS отвечает.
check "DNS-сервис" "Ограничение клиентов (allow-query)" \
  "grep -iE 'allow-query|allow-transfer' /etc/named.conf 2>/dev/null || echo 'не найдено'"


# =====================================================================
# ФАЙЛОВЫЙ СЕРВЕР
# =====================================================================

# Права на /srv/files — разграничение доступа к общим файлам.
check "Файловый сервер" "Права на /srv/files" \
  "ls -la /srv/files 2>/dev/null || echo 'каталог не найден'"

# Владелец и права /srv/files — должны быть root:fs_admins 750.
check "Файловый сервер" "Владелец и права /srv/files" \
  "stat -c '%U:%G %a' /srv/files 2>/dev/null || echo 'каталог не найден'"

# Группа fs_admins — должна существовать и управлять доступом.
check "Файловый сервер" "Группа fs_admins" \
  "getent group fs_admins 2>/dev/null || echo 'группа не найдена'"

# =====================================================================
# ИМЕНОВАНИЕ
# =====================================================================

# Имя хоста — проверка соответствия стандарту именования.
check "Именование" "Имя хоста" \
  "hostname; cat /etc/hostname 2>/dev/null"

# Длина имени — не должна превышать 15 символов (ограничение NetBIOS).
check "Именование" "Длина имени (≤15)" \
  "hostname | awk '{ if (length(\$0) > 15) print \$0 \" — СЛИШКОМ ДЛИННОЕ\" }'; hostname"

# hostnamectl — расширенная информация о хосте.
check "Именование" "hostnamectl" \
  "hostnamectl 2>/dev/null || echo 'недоступен'"