# evtxview

Быстрый просмотр и триаж журналов Windows `.evtx` из командной строки — с **проверкой полноты чтения**.

[![CI](https://github.com/kotru21/evtx-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/kotru21/evtx-viewer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Tests](https://img.shields.io/badge/tests-72%20passing-brightgreen)
[![Linting: Ruff](https://img.shields.io/badge/lint-ruff-261230)](https://github.com/astral-sh/ruff)
![Checked with mypy](https://img.shields.io/badge/mypy-checked-2a6db2)
![License](https://img.shields.io/badge/license-MIT-green)

`evtxview` построен на rust-based парсере [`evtx`](https://pypi.org/project/evtx/) и предназначен для быстрого DFIR-триажа: сводка по EventID, фильтры по времени/ID/подстроке, экспорт в CSV/JSON. Отличается от «просто просмотрщика» встроенной командой `--verify`, которая доказывает, что прочитаны все записи, а не молчаливая часть файла.

---

## Зачем ещё один просмотрщик evtx

Инструмент вырос из разбора ransomware-инцидента, где популярный `python-evtx` **молча прочитал только первый chunk из 30** — 94 записи из 2309 — и едва не увёл расследование в неверную сторону. Урок зашит в дизайн:

> **Число записей из парсера без ошибки ≠ полнота данных.** Парсер может тихо отдать часть файла.

Поэтому `--verify` — не вспомогательная опция, а центральная функция. Прогоняйте её перед любым серьёзным анализом: она сверяет прочитанные записи с заголовками chunk'ов **и** ищет пропуски в `EventRecordID`, ловя потерю данных даже когда счётчик случайно совпал.

## Возможности

- **Проверка полноты** (`--verify`) — сверка с заголовками chunk'ов и поиск пропущенных `EventRecordID`; печатает `OK` или `!!! ОБРЕЗКА` со списком потерянных ID.
- **Сводка** (`--summary`) — распределение EventID и диапазон времени; security-relevant EID подсвечены.
- **Единый таймлайн** (`--timeline`) — события из нескольких `.evtx` сливаются в одну ленту, отсортированную по времени, с колонкой источника. Коррелирует Sysmon/Security/PowerShell в один поток.
- **Пресеты** (`--preset`) — готовые представления под задачу. `process-tree` строит дерево процессов из Sysmon EID 1 (по `ProcessGuid`→`ParentProcessGuid`); `logon-analysis` разбирает входы Security (сессии 4624→4634, привилегированные логоны 4672, признаки brute-force по 4625); `network` группирует соединения Sysmon EID 3 по назначению, выводя необычные порты и исходящий с хоста трафик первыми.
- **Фильтры** — по EventID (`--eid`), по подстроке в сыром XML (`--grep`), по времени (`--after`/`--before`).
- **Экспорт** — CSV и JSON с метаполями (`_EventID`, `_UTC`, `_Local`, `_Provider`, `_Computer`, `_SourceFile`) и всеми полями события.
- **Устойчивый разбор** — `ElementTree` с namespace/атрибутами/многострочными значениями и декодированием XML-сущностей; fallback на регулярки для битого XML. Работает с форматом `UserData` (PrintService и др.), не только `EventData`.
- **Несколько файлов сразу** — маски (`*.evtx`) раскрываются, каждый файл в своей секции.
- **Кросс-платформенность** — Windows и Linux, корректный UTF-8 вывод. Цвет — только в терминале.

## Установка

Требуется Python 3.9+. Единственная runtime-зависимость — пакет `evtx` (rust-биндинг), ставится автоматически.

### Вариант 1 — команда `evtxview` в PATH (рекомендуется)

[`pipx`](https://pipx.pypa.io/) ставит инструмент в изолированное окружение и сам добавляет шорткат в PATH:

```bash
git clone https://github.com/kotru21/evtx-viewer
cd evtx-viewer
pipx install .
```

После этого команда доступна из любого каталога:

```console
$ evtxview --help
$ evtxview Security.evtx --summary
```

### Вариант 2 — обычный pip

```bash
git clone https://github.com/kotru21/evtx-viewer
cd evtx-viewer
pip install .
```

`pip` создаёт исполняемый файл `evtxview` в каталоге скриптов интерпретатора. Если после установки команда `evtxview` не находится (`command not found`), этот каталог не в `PATH`:

- **Windows:** обычно `%LOCALAPPDATA%\Programs\Python\PythonXX\Scripts` (или `...\Scripts` рядом с `python.exe`). Добавьте его в переменную среды `PATH` — путь пишется в предупреждении pip при установке.
- **Linux/macOS:** обычно `~/.local/bin`. Добавьте в `~/.bashrc`/`~/.zshrc`: `export PATH="$HOME/.local/bin:$PATH"`.

Универсальный запуск, не зависящий от PATH, доступен всегда:

```bash
python -m evtxview Security.evtx --summary
```

### Для разработки

```bash
pip install -e ".[dev]"     # editable + pytest, ruff, mypy
```

## Быстрый старт

**1. Сначала — проверить, что файл прочитан целиком:**

```console
$ evtxview Sysmon.evtx --verify
Sysmon.evtx: chunks=30 заявлено=2309 прочитано=2309 OK
```

При потере записей:

```console
$ evtxview suspect.evtx --verify
suspect.evtx: chunks=30 заявлено=2309 прочитано=2201 !!! ОБРЕЗКА
  пропущено EventRecordID: 108  [11290, 11291, 11292, …(+105)]  (диапазон 11193..13501)
```

**2. Обзор — что вообще в журнале:**

```console
$ evtxview Sysmon.evtx --summary
  Всего: 2309 записей
  Диапазон (UTC): 2026-05-11T12:15:49  ..  2026-05-11T13:00:56
  EventID:
        11: 689 <-- security-relevant
         5: 636
         3: 518 <-- security-relevant
         1: 187 <-- security-relevant
         2: 145
        13: 121 <-- security-relevant
```

**3. Углубиться — процессы, сеть, учётки:**

```console
$ evtxview Sysmon.evtx --eid 1 --limit 1
2026-05-11 15:20:42  EID     1  Image=C:\Windows\System32\sc.exe CommandLine=C:\Windows\system32\sc.exe start w32time User=NT AUTHORITY\LOCAL SERVICE ParentImage=C:\Windows\System32\services.exe
```

```bash
evtxview Sysmon.evtx --eid 3 --grep spoolsv          # сетевые соединения из спулера
evtxview Sysmon.evtx --eid 1 --grep "net user"       # создание учёток
evtxview Security.evtx --eid 1102 --full             # очистка журнала, все поля
evtxview Sysmon.evtx --eid 1 --csv processes.csv     # экспорт для таймлайна
evtxview *.evtx --verify                              # проверить все файлы на обрезку
```

**4. Свести несколько журналов в единую ленту** — коррелировать процессы, вход и сеть по времени:

```console
$ evtxview Sysmon.evtx Security.evtx --timeline --after "2026-05-11 12:57:40" --before "2026-05-11 12:57:42"
2026-05-11 15:57:40  [Sysmon.evtx]    EID     1  Image=C:\Windows\System32\LogonUI.exe ParentImage=C:\Windows\System32\winlogon.exe
2026-05-11 15:57:40  [Security.evtx]  EID  4648  SubjectUserName=VM1-PC$ TargetUserName=vm1 IpAddress=10.8.0.2
2026-05-11 15:57:40  [Security.evtx]  EID  4624  SubjectUserName=VM1-PC$ TargetUserName=vm1 IpAddress=10.8.0.2 LogonType=10
2026-05-11 15:57:41  [Sysmon.evtx]    EID     3  Image=C:\Windows\System32\svchost.exe DestinationIp=10.10.10.20 DestinationPort=3389
2026-05-11 15:57:41  [Sysmon.evtx]    EID     5  Image=C:\Windows\System32\rdpclip.exe
```

**5. Построить дерево процессов** — цепочка «родитель → потомок» из Sysmon EID 1 сразу вскрывает активность атакующего:

```console
$ evtxview Sysmon.evtx --preset process-tree
Дерево процессов (Sysmon EID 1): 187 процессов, 25 корней

15:25:10  cmd.exe (3188)  C:\Windows\system32\cmd.exe
├─ 15:25:28  net.exe (568)  net user /domain
├─ 15:26:03  net.exe (3740)  net user john 123123qwe /add
│  └─ 15:26:03  net1.exe (2852)  C:\Windows\system32\net1 user john 123123qwe /add
├─ 15:27:43  net.exe (992)  net localgroup Administrators john /add
└─ 15:27:58  net.exe (888)  net localgroup "Remote Desktop Users" john /add
```

**6. Разобрать входы** — сессии, привилегированные логоны и признаки brute-force из Security 4624/4625/4634/4672:

```console
$ evtxview Security.evtx --preset logon-analysis
Анализ входов (Security): 2 успешных, 0 неуспешных

vm1-PC\vm1  (2 вход(ов))
    2026-05-11 15:57:40 -> 15:58:22  (0:42)  LogonType=RemoteInteractive(RDP)  IP=10.8.0.2  [privileged: 4672]
    2026-05-11 15:57:40 -> 15:57:41  (0:00)  LogonType=RemoteInteractive(RDP)  IP=10.8.0.2
```

Сессии строятся парой 4624→4634 по `TargetLogonId` (длительность считается из совпавшей пары); вход помечается `[privileged: 4672]`, если по тому же `LogonId` было выдано специальное право. При наличии неудачных входов (4625) выводится их список и, если по одной учётке или IP набирается 5+ неудач за 5 минут, — предупреждение о вероятном brute-force.

**7. Разобрать сетевую активность** — соединения Sysmon EID 3, сгруппированные по назначению; необычные порты и исходящие с хоста соединения — первыми:

```console
$ evtxview Sysmon.evtx --preset network
Сетевые соединения (Sysmon EID 3): 518 событий, 36 назначений

10.10.10.20:7070  (47 соедин., 15:17:07..15:18:57)  [необычный порт]
    процессы: AnyDesk.exe
10.10.10.1:22  (6 соедин., 16:00:48..16:00:52)  [необычный порт, исходящее с этого хоста (6)]
    процессы: nmap.exe
10.8.0.2:4444  (1 соедин., 15:24:56..15:24:56)  [необычный порт, исходящее с этого хоста (1)]
    процессы: spoolsv.exe
10.10.10.1:161  (1 соедин., 15:31:42..15:31:42)  [исходящее с этого хоста (1)]
    процессы: advanced_ip_scanner.exe
```

Группировка — по `DestinationIp:Port`. «Необычный порт» — не входит в общеизвестные (DNS/RPC/SMB/RDP/…) и не из динамического RPC-диапазона (`49152+`, обычные callback-порты после негоциации через порт 135 — не помечаются, чтобы не заваливать вывод шумом). «Исходящее с этого хоста» — `Initiated=true`, то есть соединение инициировал сам хост, а не принял: как раз так выглядит recon и удалённый доступ атакующего на фоне обычного фонового трафика ОС.

## Опции

| Флаг | Назначение |
|---|---|
| `files...` | Один или несколько `.evtx`; поддерживаются маски (`*.evtx`) |
| `--verify` | Проверка полноты чтения (chunk-заголовки + пропуски `EventRecordID`) |
| `--summary` | Сводка: распределение EventID и диапазон времени |
| `--full` | Полный дамп всех полей каждого события |
| `--timeline` | Единая лента из всех файлов, отсортированная по времени (колонка источника) |
| `--preset process-tree` | Дерево процессов из Sysmon EID 1 (`ProcessGuid`→`ParentProcessGuid`) |
| `--preset logon-analysis` | Сессии, привилегированные входы и brute-force из Security 4624/4625/4634/4672 |
| `--preset network` | Соединения Sysmon EID 3, сгруппированные по назначению; необычные порты и исходящие с хоста — первыми |
| `--eid 1,3,1102` | Фильтр по EventID (через запятую) |
| `--grep СТРОКА` | Фильтр: подстрока в сыром XML (регистронезависимо) |
| `--after "YYYY-MM-DD HH:MM"` | События не раньше указанного времени (UTC) |
| `--before "YYYY-MM-DD HH:MM"` | События не позже указанного времени (UTC) |
| `--tz N` | Сдвиг локального времени в часах для вывода (по умолчанию `+3`) |
| `--csv FILE` | Экспорт отобранных событий в CSV. Несовместим с `--summary`/`--preset` (они не строят построчную выборку) |
| `--json FILE` | Экспорт отобранных событий в JSON. Те же ограничения, что у `--csv` |
| `--limit N` | Показать в терминале не более N событий. На `--csv`/`--json` не влияет — экспорт всегда содержит все отобранные события |

## Проверка полноты

`--verify` разбирает заголовки chunk'ов напрямую (`ElfChnk\x00`, шаг `0x10000`) и опирается на два независимых источника истины:

- **счётчик** — номера записей (`0x08`/`0x10`) дают ожидаемое число записей;
- **диапазон** — идентификаторы `EventRecordID` (`0x18`/`0x20`) дают ожидаемый непрерывный диапазон.

Прочитанные записи сверяются с обоими: несовпадение счётчика **или** дыра в диапазоне `EventRecordID` → `ОБРЕЗКА` с перечислением пропущенных ID. Пустые предвыделенные chunk'и (sentinel-заголовок `0xFFFF…FF`) не считаются потерей. Битые chunk'и не роняют разбор — они подсчитываются и выводятся как `chunk-errors: N`.

Если сам заголовок chunk'а повреждён и объявляет неправдоподобно широкий диапазон ID (на порядки больше, чем бывает в реальных файлах), `--verify` не пытается перечислить пропуски в таком диапазоне — это дало бы либо ложный `OK`, либо попытку выделить память под нереальное число элементов. Вместо этого выводится явное предупреждение о повреждённом заголовке.

## Разбор полей

Каждая запись парсится один раз (`parse_record`) в модель `EventRecord`. Основной путь — `ElementTree`: корректно обрабатывает namespace, атрибуты, многострочные значения и декодирует XML-сущности (`&lt;` → `<`). На нестандартно оформленном или битом XML происходит откат на разбор регулярными выражениями, чтобы не потерять запись целиком.

## Кросс-валидация

На критичных артефактах полезно сверять результат с независимым инструментом — [`EvtxECmd`](https://ericzimmerman.github.io/) (Eric Zimmerman) или нативным `wevtutil`. Расхождение в числе записей сразу видно и указывает на проблему в одном из парсеров.

## Ограничения и планы

- Фильтры `--after`/`--before` принимают время только в UTC (флаг локального времени — в планах).
- Пресет `rdp` — в планах (готовы `process-tree`, `logon-analysis`, `network`).
- Весь файл загружается в память списком; потоковый режим для многогигабайтных логов — в планах.
- Набор security-relevant EventID и выбор полей для однострочной сводки заданы под Sysmon/Security; вынос в конфиг — в планах.

## Разработка

```bash
pip install -e ".[dev]"
pytest            # тесты (юниты разбора + интеграция на реальных .evtx фикстурах)
ruff check .      # линт
mypy src/evtxview # типы
```

CI (GitHub Actions) прогоняет ruff, mypy и pytest на Windows и Linux (Python 3.9 и 3.12).

### Структура

| Модуль | Ответственность |
|---|---|
| `reader.py` | Чтение `.evtx` и проверка полноты по заголовкам chunk'ов |
| `record.py` | Модель `EventRecord` и разбор полей (ElementTree + regex-fallback) |
| `render.py` | Форматирование вывода: цвета, сводка, однострочный/полный дамп |
| `presets.py` | Пресеты анализа (`process-tree`, …) |
| `export.py` | Экспорт в CSV/JSON |
| `constants.py` | Наборы EID и приоритеты полей (кандидат на вынос в конфиг) |
| `util.py` | Кодировка вывода, работа со временем |
| `cli.py` | Разбор аргументов и оркестрация |

## Лицензия

MIT — см. [LICENSE](LICENSE).
