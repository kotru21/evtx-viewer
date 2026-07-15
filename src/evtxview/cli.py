#!/usr/bin/env python3
"""
evtxview — удобный просмотр Windows .evtx на Linux.

Использует rust-based парсер `evtx` (pip install evtx), который корректно
читает ВСЕ chunk'и файла — в отличие от python-evtx, который может молча
останавливаться на первом chunk и терять 95% записей.

Примеры:
  evtxview Security.evtx --summary
  evtxview Sysmon.evtx --eid 1,3 --grep spoolsv
  evtxview Sysmon.evtx --eid 3 --after "2026-05-11 12:24" --before "2026-05-11 12:26"
  evtxview Security.evtx --eid 1102 --full
  evtxview Sysmon.evtx --eid 1 --csv out.csv
  evtxview Sysmon.evtx --verify        # сверка полноты (chunk-заголовки vs прочитано)
  evtxview *.evtx --summary            # сводка по нескольким файлам
"""

import argparse, sys, json, re, struct, csv, glob
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

# ---------- вывод в UTF-8 (иначе кириллица бьётся на Windows-консоли) ----------
def force_utf8_output():
    """Windows по умолчанию пишет stdout в кодировке локали (cp1251) — кириллица
    превращается в мусор. Принудительно переключаем потоки на UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure:
            try:
                reconfigure(encoding='utf-8')
            except (ValueError, OSError):
                pass

force_utf8_output()

# ---------- зависимость ----------
try:
    from evtx import PyEvtxParser
except ImportError:
    sys.exit("Нужен rust-based парсер. Установи:  pip install evtx --break-system-packages")

NS = 'http://schemas.microsoft.com/win/2004/08/events/event'

# ---------- цвета (только если tty) ----------
class C:
    on = sys.stdout.isatty()
    R = '\033[31m' if on else ''; G = '\033[32m' if on else ''
    Y = '\033[33m' if on else ''; B = '\033[34m' if on else ''
    CY= '\033[36m' if on else ''; DIM='\033[2m' if on else ''
    BOLD='\033[1m' if on else ''; X = '\033[0m' if on else ''

# EID, которые стоит подсветить как security-relevant
HOT_EID = {
    '1102','104','4624','4625','4634','4648','4672','4720','4732','4728',
    '7045','1149','21','22','1','3','10','11','13',
}

def read_records(path):
    """Читает все записи с обработкой битых chunk'ов. Возвращает список XML-строк."""
    recs, errs = [], 0
    p = PyEvtxParser(path)
    it = p.records()
    while True:
        try:
            recs.append(next(it)['data'])
        except StopIteration:
            break
        except RuntimeError:
            errs += 1
    return recs, errs

def verify_completeness(path, seen_ids):
    """Сверяет полноту чтения по заголовкам chunk'ов.

    Заголовок chunk'а (`ElfChnk\\x00`, шаг 0x10000) несёт две пары значений:
      * 0x08/0x10 — номера записей (последовательность 1..N) → даёт ожидаемый счётчик;
      * 0x18/0x20 — сами EventRecordID (то, что в XML) → даёт ожидаемый диапазон.

    `seen_ids` — фактически прочитанные EventRecordID. Помимо сверки счётчиков
    ищем ПРОПУСКИ внутри объявленного диапазона идентификаторов: это ловит
    потерю записей даже когда счётчик случайно сошёлся (TODO #8).
    """
    data = open(path, 'rb').read()
    if data[0:8] != b'ElfFile\x00':
        return None
    EMPTY = 0xFFFFFFFFFFFFFFFF  # sentinel в заголовке предвыделенного пустого chunk'а
    off, expected, chunks = 0x1000, 0, 0
    id_lo, id_hi = None, None
    while off + 0x28 < len(data) and data[off:off+8] == b'ElfChnk\x00':
        num_first = struct.unpack('<Q', data[off+0x08:off+0x10])[0]
        num_last  = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
        rec_first = struct.unpack('<Q', data[off+0x18:off+0x20])[0]
        rec_last  = struct.unpack('<Q', data[off+0x20:off+0x28])[0]
        chunks += 1
        off += 0x10000
        if num_last != EMPTY and num_first != EMPTY and num_last >= num_first:
            expected += num_last - num_first + 1
        if rec_last != EMPTY and rec_first != EMPTY and rec_last >= rec_first:
            id_lo = rec_first if id_lo is None else min(id_lo, rec_first)
            id_hi = rec_last if id_hi is None else max(id_hi, rec_last)

    seen = {i for i in seen_ids if i is not None}
    got = len(seen)
    missing = []
    if id_lo is not None and id_hi is not None:
        missing = sorted(set(range(id_lo, id_hi + 1)) - seen)
    complete = (got == expected) and not missing
    return {
        'chunks': chunks, 'expected': expected, 'got': got,
        'id_lo': id_lo, 'id_hi': id_hi, 'missing': missing, 'complete': complete,
    }

# ---------- парсинг полей ----------
def get_eid(xml):
    m = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
    return m.group(1) if m else '?'

def get_record_id(xml):
    """EventRecordID (глобальный идентификатор записи) -> int или None."""
    m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
    return int(m.group(1)) if m else None

def get_utc(xml):
    m = re.search(r'SystemTime="([^"]+)"', xml)
    return m.group(1) if m else ''

def get_provider(xml):
    m = re.search(r'<Provider Name="([^"]+)"', xml)
    return m.group(1) if m else ''

def get_computer(xml):
    m = re.search(r'<Computer>([^<]+)</Computer>', xml)
    return m.group(1) if m else ''

def get_data_fields(xml):
    """Все <Data Name="x">y</Data> + UserData поля -> dict."""
    d = {}
    for m in re.finditer(r'<Data Name="([^"]+)">(.*?)</Data>', xml, re.S):
        d[m.group(1)] = m.group(2).strip()
    # UserData (PrintService и др.)
    ud = re.search(r'<UserData>(.*?)</UserData>', xml, re.S)
    if ud:
        for m in re.finditer(r'<(\w+)>([^<>]+)</\1>', ud.group(1)):
            d.setdefault(m.group(1), m.group(2).strip())
    return d

# ---------- единая модель записи (парсинг один раз) ----------
@dataclass
class EventRecord:
    """Разобранная запись события. Строится один раз через parse_record()."""
    xml: str
    eid: str = '?'
    record_id: Optional[int] = None
    utc: str = ''
    provider: str = ''
    computer: str = ''
    data: Dict[str, str] = field(default_factory=dict)

def _localname(tag: str) -> str:
    """Имя тега без XML-namespace: '{ns}Data' -> 'Data'."""
    return tag.rpartition('}')[2]

def _parse_record_regex(xml: str) -> EventRecord:
    """Fallback-разбор регулярками (для битого/нестандартного XML)."""
    return EventRecord(
        xml=xml, eid=get_eid(xml), record_id=get_record_id(xml),
        utc=get_utc(xml), provider=get_provider(xml),
        computer=get_computer(xml), data=get_data_fields(xml),
    )

def parse_record(xml: str) -> EventRecord:
    """Разбирает XML записи один раз. Основной путь — ElementTree (устойчив к
    атрибутам/namespace/многострочным значениям); при ошибке — fallback на regex.

    Байты вместо str: записи начинаются с `<?xml ... encoding="utf-8"?>`, а
    ET.fromstring на str с декларацией кодировки бросает ValueError."""
    try:
        root = ET.fromstring(xml.encode('utf-8'))
    except (ET.ParseError, ValueError):
        return _parse_record_regex(xml)

    rec = EventRecord(xml=xml)
    for el in root.iter():
        name = _localname(el.tag)
        if name == 'EventID':
            rec.eid = (el.text or '').strip() or rec.eid
        elif name == 'EventRecordID':
            txt = (el.text or '').strip()
            if txt.isdigit():
                rec.record_id = int(txt)
        elif name == 'TimeCreated':
            rec.utc = el.get('SystemTime') or rec.utc
        elif name == 'Provider':
            rec.provider = el.get('Name') or rec.provider
        elif name == 'Computer':
            rec.computer = (el.text or '').strip() or rec.computer
        elif name == 'Data':
            key = el.get('Name')
            if key:
                rec.data[key] = (el.text or '').strip()
        elif name == 'UserData':
            # UserData (PrintService и др.): листья-элементы с текстом
            for leaf in el.iter():
                if leaf is el or len(leaf):
                    continue
                if leaf.text and leaf.text.strip():
                    rec.data.setdefault(_localname(leaf.tag), leaf.text.strip())
    return rec

def to_local(utc_str, offset_hours):
    """ISO UTC -> локальное время со сдвигом."""
    if not utc_str:
        return ''
    try:
        s = utc_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone(timedelta(hours=offset_hours)))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return utc_str[:19]

def parse_dt(s):
    """Гибкий парс времени фильтра."""
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d %H:%M','%Y-%m-%d %H','%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    sys.exit(f"Не понял дату: {s} (формат: 'YYYY-MM-DD HH:MM:SS')")

# ---------- краткая строка события ----------
def summarize_line(rec, offset):
    t = to_local(rec.utc, offset)
    # выбираем самые полезные поля по типу события
    interesting = []
    for key in ('Image','TargetImage','SourceImage','CommandLine','User',
                'SubjectUserName','TargetUserName','ParentImage',
                'DestinationIp','DestinationPort','SourceIp','SourcePort','Initiated',
                'TargetFilename','TargetObject','IpAddress','LogonType','ServiceName'):
        if key in rec.data and rec.data[key]:
            val = rec.data[key]
            if len(val) > 70:
                val = val[:67] + '...'
            interesting.append(f"{key}={val}")
    extra = ' '.join(interesting[:4])
    col = C.R if rec.eid in HOT_EID else C.CY
    return f"{C.DIM}{t}{C.X}  {col}EID {rec.eid:>5}{C.X}  {extra}"

def full_dump(rec, offset):
    print(f"{C.BOLD}{'='*70}{C.X}")
    print(f"{C.R if rec.eid in HOT_EID else C.CY}EID {rec.eid}{C.X}  {C.DIM}{to_local(rec.utc,offset)} (local)  |  {rec.utc} UTC{C.X}")
    print(f"Provider: {rec.provider}  |  Computer: {rec.computer}")
    if rec.data:
        w = max(len(k) for k in rec.data)
        for k, v in rec.data.items():
            print(f"   {C.Y}{k:>{w}}{C.X} = {v}")

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(
        description="Просмотр Windows .evtx на Linux (корректное чтение всех chunk'ов).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument('files', nargs='+', help='.evtx файл(ы), поддерживает маски (*.evtx)')
    ap.add_argument('--eid', help='фильтр по EventID (через запятую: 1,3,1102)')
    ap.add_argument('--grep', help='фильтр: подстрока в сыром XML (регистронезависимо)')
    ap.add_argument('--after', help='события после времени "YYYY-MM-DD HH:MM" (UTC)')
    ap.add_argument('--before', help='события до времени (UTC)')
    ap.add_argument('--tz', type=float, default=3.0, help='сдвиг локального времени в часах (по умолч. +3)')
    ap.add_argument('--summary', action='store_true', help='сводка: распределение EID и диапазон времени')
    ap.add_argument('--full', action='store_true', help='полный дамп всех полей каждого события')
    ap.add_argument('--verify', action='store_true', help='сверка полноты парсинга (chunk-заголовки)')
    ap.add_argument('--csv', metavar='FILE', help='экспорт в CSV')
    ap.add_argument('--json', metavar='FILE', help='экспорт распарсенных событий в JSON')
    ap.add_argument('--limit', type=int, help='показать не более N событий')
    args = ap.parse_args()

    # раскрыть маски
    paths = []
    for f in args.files:
        paths.extend(sorted(glob.glob(f)) or [f])

    eid_filter = set(args.eid.split(',')) if args.eid else None
    after = parse_dt(args.after) if args.after else None
    before = parse_dt(args.before) if args.before else None
    grep = args.grep.lower() if args.grep else None

    all_rows = []  # для csv/json

    for path in paths:
        try:
            recs, errs = read_records(path)
        except Exception as e:
            print(f"{C.R}{path}: ошибка чтения — {e}{C.X}")
            continue

        if args.verify:
            v = verify_completeness(path, (get_record_id(x) for x in recs))
            if v:
                mark = f"{C.G}OK{C.X}" if v['complete'] else f"{C.R}!!! ОБРЕЗКА{C.X}"
                print(f"{C.BOLD}{path}{C.X}: chunks={v['chunks']} заявлено={v['expected']} прочитано={v['got']} {mark}"
                      + (f" (chunk-errors: {errs})" if errs else ""))
                miss = v['missing']
                if miss:
                    sample = ', '.join(str(i) for i in miss[:15])
                    more = f" …(+{len(miss)-15})" if len(miss) > 15 else ""
                    print(f"  {C.R}пропущено EventRecordID: {len(miss)}{C.X}"
                          f"  [{sample}{more}]  (диапазон {v['id_lo']}..{v['id_hi']})")
            else:
                print(f"{path}: не EVTX или не удалось разобрать заголовок")
            continue

        # разбор каждой записи один раз
        records = [parse_record(xml) for xml in recs]

        # фильтрация
        sel = []
        for rec in records:
            if eid_filter and rec.eid not in eid_filter:
                continue
            if grep and grep not in rec.xml.lower():
                continue
            if after or before:
                if not rec.utc:
                    continue
                try:
                    dt = datetime.fromisoformat(rec.utc.replace('Z','+00:00'))
                except Exception:
                    continue
                if after and dt < after:
                    continue
                if before and dt > before:
                    continue
            sel.append(rec)

        if len(paths) > 1:
            print(f"\n{C.BOLD}### {path}{C.X}  ({len(sel)}/{len(recs)} после фильтров"
                  + (f", chunk-errors {errs}" if errs else "") + ")")

        if args.summary:
            from collections import Counter
            cnt = Counter(r.eid for r in sel)
            times = sorted(r.utc for r in sel if r.utc)
            print(f"  Всего: {len(sel)} записей")
            if times:
                print(f"  Диапазон (UTC): {times[0][:19]}  ..  {times[-1][:19]}")
            print("  EventID:")
            for eid, n in cnt.most_common():
                hot = f" {C.R}<-- security-relevant{C.X}" if eid in HOT_EID else ""
                print(f"    {eid:>6}: {n}{hot}")
            continue

        shown = 0
        for rec in sel:
            if args.limit and shown >= args.limit:
                print(f"  {C.DIM}... (ограничено --limit {args.limit}){C.X}")
                break
            if args.full:
                full_dump(rec, args.tz)
            else:
                print(summarize_line(rec, args.tz))
            shown += 1

            if args.csv or args.json:
                d = dict(rec.data)
                d['_EventID'] = rec.eid
                d['_UTC'] = rec.utc
                d['_Local'] = to_local(rec.utc, args.tz)
                d['_Provider'] = rec.provider
                d['_Computer'] = rec.computer
                d['_SourceFile'] = path
                all_rows.append(d)

    # экспорт
    if args.json and all_rows:
        json.dump(all_rows, open(args.json,'w'), ensure_ascii=False, indent=2)
        print(f"\n{C.G}JSON записан: {args.json} ({len(all_rows)} событий){C.X}")
    if args.csv and all_rows:
        keys = []
        for r in all_rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        # порядок: метаполя вперёд
        meta = [k for k in keys if k.startswith('_')]
        rest = [k for k in keys if not k.startswith('_')]
        keys = meta + rest
        with open(args.csv,'w',newline='',encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            w.writeheader()
            w.writerows(all_rows)
        print(f"\n{C.G}CSV записан: {args.csv} ({len(all_rows)} событий){C.X}")

if __name__ == '__main__':
    main()
