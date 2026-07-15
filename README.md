# evtxview

Быстрый просмотр и триаж журналов Windows `.evtx` из командной строки — с **проверкой полноты чтения**.

[![CI](https://github.com/kotru21/evtx-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/kotru21/evtx-viewer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Tests](https://img.shields.io/badge/tests-49%20passing-brightgreen)
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
- **Пресеты** (`--preset`) — готовые представления под задачу. `process-tree` строит дерево процессов из Sysmon EID 1 (по `ProcessGuid`→`ParentProcessGuid`).
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

## Опции

| Флаг | Назначение |
|---|---|
| `files...` | Один или несколько `.evtx`; поддерживаются маски (`*.evtx`) |
| `--verify` | Проверка полноты чтения (chunk-заголовки + пропуски `EventRecordID`) |
| `--summary` | Сводка: распределение EventID и диапазон времени |
| `--full` | Полный дамп всех полей каждого события |
| `--timeline` | Единая лента из всех файлов, отсортированная по времени (колонка источника) |
| `--preset process-tree` | Дерево процессов из Sysmon EID 1 (`ProcessGuid`→`ParentProcessGuid`) |
| `--eid 1,3,1102` | Фильтр по EventID (через запятую) |
| `--grep СТРОКА` | Фильтр: подстрока в сыром XML (регистронезависимо) |
| `--after "YYYY-MM-DD HH:MM"` | События не раньше указанного времени (UTC) |
| `--before "YYYY-MM-DD HH:MM"` | События не позже указанного времени (UTC) |
| `--tz N` | Сдвиг локального времени в часах для вывода (по умолчанию `+3`) |
| `--csv FILE` | Экспорт отобранных событий в CSV |
| `--json FILE` | Экспорт отобранных событий в JSON |
| `--limit N` | Показать не более N событий |

## Проверка полноты

`--verify` разбирает заголовки chunk'ов напрямую (`ElfChnk\x00`, шаг `0x10000`) и опирается на два независимых источника истины:

- **счётчик** — номера записей (`0x08`/`0x10`) дают ожидаемое число записей;
- **диапазон** — идентификаторы `EventRecordID` (`0x18`/`0x20`) дают ожидаемый непрерывный диапазон.

Прочитанные записи сверяются с обоими: несовпадение счётчика **или** дыра в диапазоне `EventRecordID` → `ОБРЕЗКА` с перечислением пропущенных ID. Пустые предвыделенные chunk'и (sentinel-заголовок `0xFFFF…FF`) не считаются потерей. Битые chunk'и не роняют разбор — они подсчитываются и выводятся как `chunk-errors: N`.

## Разбор полей

Каждая запись парсится один раз (`parse_record`) в модель `EventRecord`. Основной путь — `ElementTree`: корректно обрабатывает namespace, атрибуты, многострочные значения и декодирует XML-сущности (`&lt;` → `<`). На нестандартно оформленном или битом XML происходит откат на разбор регулярными выражениями, чтобы не потерять запись целиком.

## Кросс-валидация

На критичных артефактах полезно сверять результат с независимым инструментом — [`EvtxECmd`](https://ericzimmerman.github.io/) (Eric Zimmerman) или нативным `wevtutil`. Расхождение в числе записей сразу видно и указывает на проблему в одном из парсеров.

## Ограничения и планы

- Фильтры `--after`/`--before` принимают время только в UTC (флаг локального времени — в планах).
- Пресеты `logon-analysis`, `network`, `rdp` — в планах (готов `process-tree`).
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
