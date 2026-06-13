[English](README.md) | **Русский**

# BitrixProbe

![logo](img/bp_logo.jpg)


BitrixProbe — инструмент для оценки уязвимостей инсталляций CMS «1С-Битрикс»/Bitrix24, написанный на Python.

Он поддерживает два отдельных режима оценки:
- `pentest`: внешнее HTTP/HTTPS-сканирование целевого URL.
- `audit`: аутентифицированное локальное сканирование сервера по SSH.


### Правовая оговорка и ответственное использование

BitrixProbe предназначен только для санкционированного тестирования безопасности, внутренних аудитов, исследований и защитной оценки.

Полная правовая оговорка приведена в файле [DISCLAIMER](./DISCLAIMER.md).


## Почему я создал BitrixProbe

Я начал создавать BitrixProbe, столкнувшись с повторяющейся проблемой при сканировании уязвимостей и согласовании их устранения.

Системы на базе Битрикс часто значительно изменяются веб-разработчиками и интеграторами. Такие изменения могут сделать устранение уязвимостей медленным, рискованным или сложным для согласования, особенно в корпоративных средах, где бизнес-логика зависит от устаревшего кода и пользовательских модулей.

В результате уязвимый код может долго оставаться в продуктивной среде. Во многих случаях у команд безопасности недостаточно информации о том, какие компоненты Битрикс доступны извне, какие модули установлены и какие проблемы требуют срочного внимания.

Первая идея BitrixProbe была простой: создать небольшой Python-инструмент, который разделяет внешние веб-проверки и аутентифицированные серверные проверки, собирает полезные данные и формирует практичные отчёты для реальных оценок безопасности.

BitrixProbe продолжает развиваться. Одни проверки предназначены для определения версий и выявления доступных компонентов, другие для проверки конкретных уязвимостей или локального аудита.


## Возможности

- Поддержка CVE, BDU, EPSS, CVSS и трендовых уязвимостей от Positive Technologies.
- Модули энумерации для тестирования на проникновение и аудита.
- Внешнее сканирование Битрикс по HTTP и HTTPS.
- Аутентифицированный локальный аудит сервера по SSH.
- Стандартный формат результата для каждого модуля.
- Формирование текстовых отчётов.
- Локальная база уязвимостей, обновляемая ежедневно.


## Протестированное окружение

BitrixProbe разрабатывался и тестировался в контролируемых лабораторных окружениях.

| ОС | Версия PHP | Веб-сервер | Версия / редакция Битрикс |
| --- | --- | --- | --- |
| Ubuntu 24.04.4 LTS / 6.8.0-117-generic aarch64 Linux | PHP 8.3.6 | Apache/2.4.58 | 1C-Bitrix/Bitrix24 26.150.0 |
| VMBitrix 9.0.9 CentOS Stream 9 / 5.14.0-710.el9.x86_64 Linux | PHP 8.2.31 | Apache/2.4.62<br/>nginx/1.30.2 | Bitrix24 26.150.0 |
| VMBitrix 9.0.9 AlmaLinux 9.7 / 5.14.0-611.26.1.el9_7.x86_64 Linux | PHP 8.2.30 | Apache/2.4.62<br/>nginx/1.28.1 | Bitrix24 26.150.0 |
| VMBitrix 9.0.9 Rocky Linux 9.7 / 5.14.0-611.24.1.el9_7.x86_64 Linux | PHP 8.2.30 | Apache/2.4.62<br/>nginx/1.28.1 | Bitrix24 26.150.0 |
| RED OS 8.0.2 / 6.12.92-1.red80.x86_64 Linux | PHP 8.4.19 | nginx/1.30.2 | Bitrix24 26.150.0 |


## Режимы

| Режим | Протокол | Описание | Аутентификация | Типичное применение |
| --- | --- | --- | --- | --- |
| `pentest` | TCP HTTP/HTTPS | Внешнее HTTP/HTTPS-сканирование целевого URL. | Не требуется | Проверка публичной доступности, определение версий, неаутентифицированные проверки. |
| `audit` | TCP SSH, SFTP | Локальное сканирование сервера по SSH. | Требуется | Проверка установленных модулей, локальной конфигурации и сравнение версий. |


## Примеры сканирования

BitrixProbe выводит результат каждого модуля во время сканирования и сохраняет те же понятные человеку доказательства в отчёте. Следующие примеры поясняют информацию, получаемую при сканировании в режимах pentest и audit.


### Pentest-сканирование

Pentest-модули выполняют внешние HTTP/HTTPS-проверки без доступа к целевому серверу. Например, проверка доступности `restore.php` может обнаружить публично доступный скрипт восстановления резервной копии Битрикс.

![restore.php](img/restore_exmpl.gif)

Модуль сообщает проверенный URL, метаданные HTTP-ответа и маркеры Битрикс, подтвердившие находку. Положительный результат `Detected: yes` означает, что модуль нашёл соответствующие доказательства.

Разведка и энумерация играют ключевую роль в любой атаке. Поэтому для обеспечения безопасности важно понимать, какие конфигурации и компоненты развёрнуты и доступны злоумышленнику.
В Битрикс существует множество модулей, в которых периодически обнаруживаются уязвимости.
Полезно попытаться определить, какие модули установлены в Битрикс.
Для этого создана проверка перечисления, которая сравнивает доступные на веб-сервере статические файлы со словарём. Результаты могут подсказать, какие стандартные модули присутствуют в файловой системе и установлены.
Определение плагинов также помогает понять, используется ли CMS «1С-Битрикс» или Bitrix24.
Ниже видно, что модуль landing, вероятно, установлен, а CMS, по всей видимости, является «1С-Битрикс».

![modules](img/pmodules_exmpl.gif)


### Audit-сканирование

Audit-модули выполняют аутентифицированные серверные проверки через SSH. Например, проверка аудита может сравнить версии установленных модулей Битрикс с локальной базой уязвимостей. Ниже показаны результаты для присутствующих и установленных модулей, а также устаревших версий.
Некоторая информация о модулях может отсутствовать в базе данных, поскольку поставщик публикует на своём сайте не все данные.

![amodules](img/amodules_exmpl.gif)

Следующий результат показывает версию установленного модуля, идентификаторы уязвимостей, критичность и версию с исправлением. Например, отображается красный флаг PT-Trending, сигнализирующий об активной эксплуатации уязвимости в СНГ. Он по сути аналог американского каталога CISA KEV.
Также присутствует метрика EPSS, но она доступна только при наличии CVE.
У многих уязвимостей сейчас нет CVE, но есть идентификатор BDU.

![avulns](img/audit_vuln_exmpl.gif)


### Статусы результатов

| Вывод | Значение |
| --- | --- |
| `Detected: yes` | Модуль завершил работу и нашёл соответствующие доказательства. |
| `Detected: no` | Модуль успешно завершил работу, но не обнаружил проверяемое условие. |
| `Check skipped` | Необходимая зависимость была недоступна или не обнаружена. |
| `Failed` | Техническая ошибка помешала модулю завершить работу штатно. |


## Установка

Клонируйте репозиторий и установите зависимости Python из корня проекта:

```bash
git clone https://github.com/ErSilh0x/bitrixprobe.git
cd bitrixprobe
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Запустите BitrixProbe из корня репозитория:

```bash
python -m bitrixprobe --help
```


## Использование

Запуск внешнего pentest-сканирования:

```bash
python -m bitrixprobe pentest --url https://example.com
```

Запуск аутентифицированного серверного audit-сканирования по SSH:

```bash
python -m bitrixprobe audit \
  --host 192.168.56.10 \
  --port 22 \
  --user ubuntu \
  --webroot /var/www/bitrix
```

По умолчанию отчёты сохраняются в каталоге `reports/`.


### Файл окружения

BitrixProbe может читать параметры SSH-подключения для аудита из файла `.env`. Это полезно для режима audit, поскольку пароль SSH нельзя передать аргументом командной строки.

Создайте файл `.env` в корне проекта:

```env
BP_SSH_HOST=192.168.56.10
BP_SSH_PORT=22
BP_SSH_USER=ubuntu
BP_SSH_PASSWORD=change-me
```

Перед запуском режима audit установите строгие права доступа:

```bash
chmod 640 .env
```

BitrixProbe проверяет права файла `.env` перед загрузкой. Файл не должен быть символической ссылкой, а ожидаемый режим прав — `640`. Если установлены другие права, BitrixProbe останавливается и выводит необходимую команду `chmod`.

Использование стандартного файла `.env`:

```bash
python -m bitrixprobe audit --webroot /var/www/bitrix
```

Использование другого файла окружения:

```bash
python -m bitrixprobe audit \
  --env-file ./lab.env \
  --webroot /var/www/bitrix
```

Значения CLI переопределяют значения `.env` для SSH-хоста, порта и имени пользователя:

```bash
python -m bitrixprobe audit \
  --host 192.168.56.20 \
  --port 2222 \
  --user bitrix \
  --env-file .env \
  --webroot /var/www/bitrix
```

Если после чтения параметров CLI и файла `.env` по-прежнему отсутствуют хост, порт, имя пользователя или пароль, BitrixProbe запросит их интерактивно.


### Параметры

Показать основную справку:

```bash
python -m bitrixprobe --help
```

Показать справку режима pentest:

```bash
python -m bitrixprobe pentest --help
```

| Параметр | Обязательный | Описание |
| --- | --- | --- |
| `--url` | Да | URL цели, например `https://example.com` или `https://192.168.56.10:8080`. Если схема не указана, BitrixProbe использует `https://`. |

Показать справку режима audit:

```bash
python -m bitrixprobe audit --help
```

| Параметр | Обязательный | Описание |
| --- | --- | --- |
| `-H`, `--host` | Нет | Адрес SSH-сервера. Переопределяет `BP_SSH_HOST` из файла `.env`. |
| `-p`, `--port` | Нет | Порт SSH-сервера. Переопределяет `BP_SSH_PORT`; значение по умолчанию — `22`. |
| `-u`, `--user` | Нет | Имя пользователя SSH. Переопределяет `BP_SSH_USER` из файла `.env`. |
| `--env-file` | Нет | Путь к файлу окружения. По умолчанию `.env`. |
| `--webroot` | Нет | Удалённый корневой веб-каталог Битрикс. По умолчанию `/var/www/html`. |
| `--output-dir` | Нет | Локальный каталог для файлов отчётов. По умолчанию `reports`. |


## Использование BitrixProbe с Docker

Соберите Docker-образ из корня проекта BitrixProbe. Контекст сборки должен содержать `Dockerfile` и `requirements.txt`:

```bash
docker build --no-cache -t bitrixprobe:local .
```

Запустите BitrixProbe в Docker, примонтировав текущий каталог хоста как `/app`.
При этом локальный файл `.env` останется вне образа, а отчёты будут сохраняться в `$(pwd)/reports` на хосте:

```bash
docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local --help
```

Запуск внешнего веб-сканирования по URL:

```bash
docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local pentest --url http://bitrix.local
```

Если цель использует локальное имя хоста, сопоставьте его с IP-адресом цели внутри контейнера:

```bash
docker run --rm -it \
  --add-host bitrix.local:10.111.111.137 \
  -v "$(pwd):/app" \
  bitrixprobe:local pentest --url http://bitrix.local
```

Запуск режима SSH-аудита с хостом/IP-адресом и портом. Не передавайте HTTP URL в `audit --host`:

```bash
docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local audit \
  --host 10.111.111.137 \
  --port 22 \
  --user ubuntu \
  --webroot /var/www/bitrix
```

Для режима audit с локальным файлом `.env` оставьте `.env` в текущем каталоге и примонтируйте каталог в контейнер:

```bash
chmod 640 .env

docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local audit --webroot /var/www/bitrix
```

### Docker и цели сканирования в виртуальных машинах на одном хосте

Если целевая установка Битрикс находится внутри виртуальной машины, контейнер может не иметь возможности разрешить её имя или построить маршрут к ней, даже если хостовая машина имеет доступ. Ошибка DNS вида `Name does not resolve` означает, что контейнер не может разрешить имя хоста. Используйте `--add-host` или укажите IP-адрес цели напрямую.

Если подключиться к IP-адресу из контейнера также не удаётся, проблема связана с сетевой доступностью. В Docker Engine для Linux попробуйте сеть хоста:

```bash
docker run --rm -it \
  --net=host \
  -v "$(pwd):/app" \
  bitrixprobe:local audit \
  --host 10.111.111.137 \
  --port 22 \
  --user ubuntu \
  --webroot /var/www/bitrix
```

В Docker Desktop для macOS или Windows параметр `--net=host` обычно не предоставляет прямой доступ к host-only-сетям виртуальных машин. Вместо этого используйте один из следующих вариантов:

- Переключите сетевой адаптер виртуальной машины в режим моста.
- Настройте перенаправление портов NAT виртуальной машины для SSH и HTTP/HTTPS.
- Создайте SSH-туннель на хосте и подключайтесь из контейнера к `host.docker.internal`.

Пример SSH-туннеля с хоста для audit-сканирования:

```bash
ssh -N -L 127.0.0.1:2222:10.111.111.137:22 ubuntu@10.111.111.137
```

Затем запустите контейнер, указав перенаправленный SSH-порт:

```bash
docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local audit \
  --host host.docker.internal \
  --port 2222 \
  --user ubuntu \
  --webroot /var/www/bitrix
```

Для `pentest --url` перенаправьте веб-порт виртуальной машины через SSH с хоста. Это полезно, когда хост имеет доступ к виртуальной машине, но Docker-контейнер не может напрямую построить маршрут к её сети.

Перенаправьте HTTP из виртуальной машины на локальный порт `8080`:

```bash
ssh -N -L 127.0.0.1:8080:127.0.0.1:80 ubuntu@10.111.111.137
```

Затем просканируйте перенаправленный URL из Docker:

```bash
docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local pentest --url http://host.docker.internal:8080
```

Для HTTPS перенаправьте порт `443` виртуальной машины на локальный порт `8443`:

```bash
ssh -N -L 127.0.0.1:8443:127.0.0.1:443 ubuntu@10.111.111.137
```

Затем выполните сканирование:

```bash
docker run --rm -it \
  -v "$(pwd):/app" \
  bitrixprobe:local pentest --url https://host.docker.internal:8443
```

Веб-сервер и сайт Битрикс часто требуют определённое доменное имя из-за конфигурации виртуальных доменов. Оставьте туннель активным и добавьте сопоставление хоста для контейнера. В macOS/Linux Docker Engine:

```bash
docker run --rm -it \
  --add-host bitrix.local:host-gateway \
  -v "$(pwd):/app" \
  bitrixprobe:local pentest --url http://bitrix.local:8080
```

Команды для проверки сетевого доступа из контейнера:

```bash
python -c "import socket; print(socket.gethostbyname('bitrix.local'))"
python -c "import socket; socket.create_connection(('10.111.111.137', 22), 5); print('ok')"
```

>*`https://bitrix.local` — URL цели


## Список уязвимостей

### Обозначения статуса обнаружения

- ![YES](https://img.shields.io/badge/status-YES-brightgreen?style=flat-square) — обнаружение поддерживается.
- ![YES Unauthenticated](https://img.shields.io/badge/status-YES_Unauthenticated-orange?style=flat-square) — HTTP pentest-сканирование работает только в том случае, если уязвимость может быть использована без аутентификации в установках CMS с нестандартной конфигурацией. По умолчанию **требуется** аутентифицированный доступ.
- ![NO Authenticated](https://img.shields.io/badge/status-NO_Auth-red?style=flat-square) — для эксплуатации уязвимости в установках CMS со стандартной конфигурацией **требуется** аутентифицированный доступ.
- ![NO DOS](https://img.shields.io/badge/status-NO_DOS-red?style=flat-square) — уязвимость приводит к отказу в обслуживании.
- ![NO](https://img.shields.io/badge/status-NO-red?style=flat-square) — обнаружение ещё не реализовано.


### Статус обнаружения

| Обнаружено | Название | Модуль | Критичность | ID уязвимости | SSH-аудит | Pentest-сканирование <br/>HTTP/S |
|:----------:|---|:---:|:---:|:---:|:---:|:---:|
| X | Обнаружение доступного скрипта восстановления резервных копий Битрикс restore.php | X | 10 | | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) |
| X | Обнаружение доступного установочного скрипта Битрикс bitrixsetup.php | X | Доступность | | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) |
| 08.01.2026 | Включение локального файла при редактировании лендинга | landing | 9.8 | BDU:2026-05965 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 07.04.2026 | Несанкционированный доступ к информации о настройках почты | main | 8.5 | BDU:2026-04276 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![YES Unauthenticated](https://img.shields.io/badge/YES_Unauth-orange?style=flat-square) |
| 30.08.2025 | Добавление постороннего содержимого в текст связанных почтовых рассылок через заполнение CRM-формы | crm | 3.1 | BDU:2025-15620 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 21.04.2025 | Включение локального файла при изменении свойств инфоблока | iblock | 8 | BDU:2025-08666 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 21.04.2025 | Чтение произвольных файлов при импорте XML-инфоблока | iblock | 6.9 | BDU:2025-08665 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 21.04.2025 | Чтение произвольных файлов при импорте инфоблока | iblock | 6.9 | BDU:2025-08664 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 17.04.2025 | Повышение привилегий при редактировании почтовых шаблонов | main | 7.1 | BDU:2025-08663 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 17.04.2025 | Выход за установленные ограничения при копировании файлов | fileman | 7.1 | BDU:2025-08662 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 05.08.2024 | Повышение привилегий bitrix до root в виртуальной машине | vmbitrix | 8 | BDU:2025-04604 | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 16.12.2024 | Повышение привилегий bitrix до root в виртуальной машине | vmbitrix | 8 | BDU:2025-04539 | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 03.12.2024 | Хранимая XSS с обходом проактивной защиты в функциональности форума | ui | 8 | BDU:2025-00765 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 24.04.2024 | (С аутентификацией) Системный администратор может получить ранее заданный пароль прокси-сервера | dav | 6,8 | BDU:2024-08613<br/>CVE-2024-34883 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 24.04.2024 | (С аутентификацией) Системный администратор может получить ранее заданный пароль SMTP | main | 6,8 | BDU:2024-08612<br/>CVE-2024-34882 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 24.04.2024 | (С аутентификацией) Системный администратор может получить ранее заданный пароль Exchange | dav | 6,8 | BDU:2024-08611<br/>CVE-2024-34891 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 24.04.2024 | (С аутентификацией) Системный администратор может получить ранее заданный пароль SMTP | main | 6,8 | BDU:2024-08610<br/>CVE-2024-34885 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 24.04.2024 | (С аутентификацией) Системный администратор может получить ранее заданный пароль Active Directory | ldap | 6,8 | BDU:2024-08600<br/>CVE-2024-34887 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 02.07.2024 | (CVE отклонён) Если злоумышленник использует установщик виртуальной машины раньше администратора, он может получить контроль над сервером | vmbitrix Ver. 7.5.5 | | BDU:2024-05252<br/>CVE-2022-29268 | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 07.12.2023 | Установочный скрипт bitrixsetup.php не экранирует сообщение об ошибке с пользовательским вводом; отсутствие проверки параметров позволяет читать файлы ОС | bitrixsetup.php | 3 | BDU:2024-01501 | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) |
| 30.03.2023 | (С аутентификацией) [RCE] Ошибки механизма импорта данных Bitrix24 позволяют внутреннему злоумышленнику повысить привилегии | crm | 8.8 | BDU:2023-07464<br/>CVE-2023-1713 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 30.03.2023 | (С аутентификацией) Хранимая XSS в Bitrix24 из-за некорректной нейтрализации ввода на странице редактирования счёта; используется в цепочке с CVE-2023-1716 | crm | 9 | BDU:2023-07463<br/>CVE-2023-1715 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 30.03.2023 | XSS: проактивная защита «1С-Битрикс»/Bitrix24 не учитывала определённую последовательность байтов, которая могла быть частью XSS-атаки; используется в цепочке с CVE-2023-1715 | security | 9 | BDU:2023-07462<br/>CVE-2023-1716 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 30.03.2023 | XSS через загрязнение прототипа на стороне клиента в `bitrix/templates/bitrix24/components/bitrix/menu/left_vertical/script.js` | main | 9.6 | BDU:2023-07461<br/>CVE-2023-1717 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 30.03.2023 | (Без аутентификации) [DOS] Отказ в обслуживании системы управления веб-проектами «1С-Битрикс» | main | 7.5 | BDU:2023-07460<br/>CVE-2023-1718 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO DOS](https://img.shields.io/badge/NO_DOS-red?style=flat-square) |
| 30.03.2023 | (Без аутентификации) IDOR: небезопасное извлечение глобальных переменных Bitrix24 в bitrix/modules/main/tools.php | intranet | 7.5 | BDU:2023-07459<br/>CVE-2023-1719 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 10.04.2023 | (Без аутентификации) Хранимая XSS через загрузку специально созданного HTML-файла посредством `/desktop_app/file.ajax.php?action=uploadfile` (Bitrix24 22.0.300) | main | 9.3 | BDU:2023-07458<br/>CVE-2023-1720 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 30.03.2023 | (С аутентификацией) [RCE] Ошибки механизма импорта данных Bitrix24 позволяют внутреннему злоумышленнику повысить привилегии | main | 8.8 | BDU:2023-07457<br/>CVE-2023-1714 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 30.03.2023 | (С аутентификацией) [RCE] Ошибка обработки входных данных Bitrix24 позволяет внутреннему злоумышленнику выполнять произвольный код в системах с определёнными конфигурациями и версиями PHP | crm | 8.8 | BDU:2023-07457<br/>CVE-2023-1714 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 13.09.2023 | [RCE] Уязвимость модуля landing системы управления содержимым сайта | landing | 10 | BDU:2023-05857 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 28.10.2022 | Уязвимость системы управления содержимым сайта | sale | 9.8 | BDU:2023-05566 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 24.10.2022 | Уязвимость системы управления содержимым сайта | fileman | 9.6 | BDU:2023-05565 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 05.12.2019 | [RCE] Уязвимость встроенного редактора кода системы управления содержимым сайта | main | 9.8 | BDU:2023-02793 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| 28.10.2022 | (С аутентификацией) Уязвимость сервера AD/LDAP Bitrix24, позволяющая получить несанкционированный доступ к защищённой информации | ldap | 4.4 | BDU:2023-01604<br/>CVE-2022-43959 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO Authenticated](https://img.shields.io/badge/NO_Auth-red?style=flat-square) |
| 04.03.2022 | (Без аутентификации) [RCE] Уязвимость модуля «Опросы, голосования» системы управления содержимым сайта | vote | 9.8 | BDU:2022-01141<br/>CVE-2022-27228 | | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) |
| 12.10.2020 | Отражённая XSS в параметре arParams`[API_KEY]` компонента map.google Bitrix24, позволяющая выполнить произвольный JavaScript-код | fileman | 9.8 | BDU:2021-03055 | ![YES](https://img.shields.io/badge/YES-brightgreen?style=flat-square) | ![NO](https://img.shields.io/badge/NO-red?style=flat-square) |
| | Уязвимость системы управления веб-проектами «1С-Битрикс» | main | 4.6 | BDU:2014-00404 | - | - |
| | Уязвимость системы управления веб-проектами «1С-Битрикс» | main | 10 | BDU:2014-00403 | - | - |


## Архитектура проекта

Ручное поддержание данных об уязвимостях в актуальном состоянии может занимать много времени и приводить к ошибкам.
Для решения этой задачи создан простой конвейер обработки данных об уязвимостях с проверкой: он собирает данные из источников, нормализует новые записи и отправляет их на ручную проверку перед утверждением и публикацией в GitHub.

![bitrixprobe-pipeline](img/bitrixprobe-pipeline.gif)

## Структура проекта

Каждый модуль оценки безопасности регистрируется в соответствующем файле `__init__.py`, чтобы средство запуска могло его выполнить.

```text
BitrixProbe/
  bitrixprobe/                    Основной пакет Python и код сканера
    cli.py                        Основная точка входа CLI
    config.py                     Конфигурация CLI и среды выполнения
    db/                           Локальная база уязвимостей SQLite
    modes/                        Средства запуска pentest- и audit-сканирования
        pentest.py                Средство запуска внешнего HTTP/HTTPS-сканирования
        audit.py                  Средство запуска SSH-аудита
    modules/                      Общие клиенты, средства отчётности и проверки
      pentest_checks/             Внешние HTTP/HTTPS-проверки Битрикс
      audit_checks/               Аутентифицированные серверные проверки по SSH
        www_client.py             Общие вспомогательные функции HTTP
        ssh_client.py             Общие вспомогательные функции SSH
        out_report.py             Вспомогательные функции формирования отчётов
        db_connect.py             Функции подключения к базе уязвимостей SQLite
    wordlists/                    Словари конечных точек, модулей и конфиденциальных файлов
  reports/                        Сформированные отчёты сканирования
```
