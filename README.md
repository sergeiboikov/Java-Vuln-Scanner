# java-vuln-scanner

CLI-утилита: отчёт по уязвимостям GitLab-репозиториев при помощи [Trivy](https://artifactory.nsd.ru:18079/dmzart1/repository/docker/v2/aquasec/trivy/manifests/0.71.2).

Утилита читает список репозиториев из `repositories.json`, клонирует каждый из них (shallow-клон указанной ветки), запускает сканирование файловой системы контейнером Trivy и сохраняет сводку в CSV-отчёт в папке `OUTPUT_FOLDER` (по умолчанию `reports`).

## Требования

- Python 3.11+
- Docker (проверено на red-docker в WSL2, Windows)
- `git` в `PATH`
- Образ Trivy и базы уязвимостей (устанавливаются автоматически через `trivy_setup.py`, см. ниже), доступ к GitLab
- Python-зависимость: `python-dotenv`

## Установка

```bash
cd C:\_NSD\Tools\java_vuln_scanner
python -m venv .venv
. .venv/scripts/activate
pip install python-dotenv
```

## Подготовка образа и баз Trivy

Загрузка образа Trivy и установка/обновление баз автоматизированы скриптом `trivy_setup.py`. Он читает те же `.env`, что и сканер, и выполняет всё внутри одноразового контейнера Trivy.

```bash
python trivy_setup.py --env-file .env all
```

Команды:

| Команда | Действие |
|---|---|
| `all` | `docker pull` образа Trivy + установка обеих баз (основной и Java) |
| `image` | только `docker pull` образа Trivy |
| `db-install` | (пере)установка обеих баз в volume |
| `db-update` | обновление только основной базы |
| `verify` | проверка наличия файлов баз в volume |

Проверка раскладки баз:

```bash
python trivy_setup.py verify
```

Ожидаемый результат — четыре файла: `db/trivy.db`, `db/metadata.json`, `java-db/trivy-java.db`, `java-db/metadata.json`.

Откуда берутся базы и как они называются, можно переопределить в `.env` (`TRIVY_DB_URL`, `TRIVY_JAVA_DB_URL`, `TRIVY_CACHE_VOLUME`, `DB_INSTALL_TIMEOUT_SEC`).


## Настройка

Скопируйте `.env.example` в `.env` рядом с файлом `repositories.json` и заполните значения.

### Переменные `.env`

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `GIT_TOKEN` | да | — | Токен GitLab. Используется только для доступа git; в URL клонирования не попадает |
| `GIT_BASE_URL` | нет | `https://gitlabsvr.nsd.ru/gitlab` | Базовый URL GitLab (из него строится URL клонирования для `group/project`) |
| `WORKERS` | нет | `4` | Количество параллельных воркеров (клонирование + сканирование) |
| `REGISTRY_URL` | нет | `artifactory.nsd.ru:18079` | Docker-registry с образом Trivy |
| `REPOSITORIES_FILE` | нет | `repositories.json` | Файл со списком репозиториев (относительный путь — рядом с `.env`) |
| `OUTPUT_FOLDER` | нет | `reports` | Папка для итоговых CSV-отчётов (относительный путь — рядом с `.env`) |
| `TRIVY_VERSION` | нет | `0.71.2` | Версия Trivy |
| `CLONE_TIMEOUT_SEC` | нет | `600` | Таймаут `git clone`, секунды |
| `DOCKER_TIMEOUT_SEC` | нет | `600` | Таймаут `docker image inspect`, секунды |
| `SCAN_TIMEOUT_SEC` | нет | `1800` | Таймаут сканирования Trivy, секунды |
| `DB_INSTALL_TIMEOUT_SEC` | нет | `1800` | Таймаут установки/обновления баз (`trivy_setup.py`), секунды |
| `TRIVY_CACHE_VOLUME` | нет | `trivy-cache` | Имя docker-volume для кэша Trivy (образ и базы) |
| `TRIVY_DB_URL` | нет | URL основной базы | Источник для скачивания основной базы (`trivy_setup.py`) |
| `TRIVY_JAVA_DB_URL` | нет | URL Java-базы | Источник для скачивания Java-базы (`trivy_setup.py`) |

### Файл `repositories.json`

Массив объектов. Ключ `group/project` обязателен; `branch` можно оставить пустым — тогда будет отсканирована ветка по умолчанию, а в отчёт попадёт фактически отсканированная ветка.

```json
[
  {
    "group/project": "nsd/java/app-one",
    "URL": "https://gitlabsvr.nsd.ru/gitlab/nsd/java/app-one",
    "Team": "Команда А",
    "branch": "main"
  },
  {
    "group/project": "nsd/java/app-two",
    "URL": "https://gitlabsvr.nsd.ru/gitlab/nsd/java/app-two",
    "Team": "Команда Б",
    "branch": ""
  }
]
```

Поведение при ошибках в файле: дубликаты и пустые `group/project` пропускаются с предупреждением в stderr; пустой `URL` заменяется на `<GIT_BASE_URL>/<group/project>`; пустой `branch` — предупреждение и ветка по умолчанию.

## Запуск

```bash
python main.py --env-file .env
```

Единственный аргумент командной строки — `--env-file` (по умолчанию `.env` в текущем каталоге). Все остальные параметры берутся из файла окружения.

Прогресс и подробности ошибок выводятся в stderr. Коды выхода:

| Код | Значение |
|---|---|
| `0` | Успешно |
| `1` | Ошибка конфигурации, файла репозиториев, docker/trivy или нет репозиториев |
| `130` | Прервано пользователем (`Ctrl+C`) |

## Результат

CSV-файл в папке `OUTPUT_FOLDER` с именем `vuln_report_YYYYMMDD_N.csv` (`YYYYMMDD` — локальная дата старта запуска; `N` — порядковый номер запуска за этот день: максимальный номер среди существующих файлов за дату + 1, начиная с `1`). Разделитель `;`, строки отсортированы по названию репозитория.

| Колонка | Источник |
|---|---|
| Название репозитория | `group/project` из `repositories.json` |
| URL | `URL` из `repositories.json` |
| Team | `Team` из `repositories.json` |
| Ветка | Фактически отсканированная ветка |
| Версия Trivy | `TRIVY_VERSION` из `.env` |
| Статус проверки | `Success` или `Failed` |
| Кол-во уязвимостей (CRITICAL/HIGH/MEDIUM/LOW) | Число найденных уязвимостей соответствующей критичности |
| Комментарий | Пусто при `Success`; при `Failed` — сообщение об ошибке |

## Как это работает

1. Читает `.env` и `repositories.json`.
2. Проверяет наличие образа Trivy локально; при отсутствии — ошибка с подсказкой (`trivy_setup.py image` или `docker pull <TRIVY_IMAGE>`).
3. Для каждого репозитория (параллельно, `WORKERS` воркеров):
   - создаёт временный каталог и выполняет `git clone --depth 1 --single-branch` нужной ветки;
   - запускает контейнер (пути к каталогам переводятся в стиль хоста docker, `/mnt/<диск>/...`):
     ```
     docker run --rm --name <tmp> --cap-drop=ALL --security-opt=no-new-privileges \
       -v <checkout>:/scan:ro -v <out>:/out:rw -v <cache-volume>:/root/.cache/trivy \
       -e TRIVY_NO_PROGRESS=true <TRIVY_IMAGE> \
       fs --scanners vuln --format json --quiet --output /out/report.json /scan
     ```
   - читает JSON-отчёт из `<out>/report.json` и считает уязвимости по критичности;
   - удаляет временный каталог.
4. Формирует имя отчёта `vuln_report_YYYYMMDD_N.csv`, создаёт папку `OUTPUT_FOLDER` при необходимости, записывает CSV и выводит сводку.

## Диагностика

- **`trivy fs: ... no such file or directory ... /scan` / пустой отчёт** — каталог не смонтировался. Docker-демон здесь работает в WSL2 (red-docker), поэтому пути должны быть в стиле `/mnt/<диск>/...`; сканер переводит их автоматически. Убедитесь, что каталог с клоном доступен демону.
- **`--skip-db-update cannot be specified on the first run`** — база не найдена в volume. Установите/проверьте базы: `python trivy_setup.py db-install` (должны быть `db/trivy.db` + `db/metadata.json` и, для Java, `java-db/trivy-java.db` + `java-db/metadata.json`); наличии проверяется командой `python trivy_setup.py verify`.
- **`Trivy image not found locally`** — загрузите образ: `python trivy_setup.py image` (или `docker pull <TRIVY_IMAGE>`).
- **`invalid volume specification` / `invalid mode`** — путь не переведён в стиль хоста docker (ожидается `/mnt/<диск>/...`); проверьте, что запуск идёт из Windows-каталога на диске с буквой.
- **Ошибки аутентификации git** — проверьте `GIT_TOKEN` и права доступа к репозиторию; в CSV такой репозиторий будет со строкой `ERROR: ...`.
