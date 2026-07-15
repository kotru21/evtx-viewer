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
from datetime import datetime, timezone, timedelta

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

def verify_completeness(path, got):
    """Сверяет число записей с суммой по заголовкам chunk'ов (ловит обрезку парсера)."""
    data = open(path, 'rb').read()
    if data[0:8] != b'ElfFile\x00':
        return None
    off, expected, chunks = 0x1000, 0, 0
    while off + 0x28 < len(data) and data[off:off+8] == b'ElfChnk\x00':
        first = struct.unpack('<Q', data[off+0x08:off+0x10])[0]
        last  = struct.unpack('<Q', data[off+0x10:off+0x18])[0]
        if last >= first:
            expected += last - first + 1
        chunks += 1
        off += 0x10000
    return {'chunks': chunks, 'expected': expected, 'got': got}

# ---------- парсинг полей ----------
def get_eid(xml):
    m = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
    return m.group(1) if m else '?'

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
def summarize_line(xml, offset):
    eid = get_eid(xml)
    t = to_local(get_utc(xml), offset)
    d = get_data_fields(xml)
    # выбираем самые полезные поля по типу события
    interesting = []
    for key in ('Image','TargetImage','SourceImage','CommandLine','User',
                'SubjectUserName','TargetUserName','ParentImage',
                'DestinationIp','DestinationPort','SourceIp','SourcePort','Initiated',
                'TargetFilename','TargetObject','IpAddress','LogonType','ServiceName'):
        if key in d and d[key]:
            val = d[key]
            if len(val) > 70:
                val = val[:67] + '...'
            interesting.append(f"{key}={val}")
    extra = ' '.join(interesting[:4])
    col = C.R if eid in HOT_EID else C.CY
    return f"{C.DIM}{t}{C.X}  {col}EID {eid:>5}{C.X}  {extra}"

def full_dump(xml, offset):
    eid = get_eid(xml)
    print(f"{C.BOLD}{'='*70}{C.X}")
    print(f"{C.R if eid in HOT_EID else C.CY}EID {eid}{C.X}  {C.DIM}{to_local(get_utc(xml),offset)} (local)  |  {get_utc(xml)} UTC{C.X}")
    print(f"Provider: {get_provider(xml)}  |  Computer: {get_computer(xml)}")
    d = get_data_fields(xml)
    if d:
        w = max(len(k) for k in d)
        for k, v in d.items():
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
            v = verify_completeness(path, len(recs))
            if v:
                ok = v['expected'] == v['got']
                mark = f"{C.G}OK{C.X}" if ok else f"{C.R}!!! ОБРЕЗКА{C.X}"
                print(f"{C.BOLD}{path}{C.X}: chunks={v['chunks']} заявлено={v['expected']} прочитано={v['got']} {mark}"
                      + (f" (chunk-errors: {errs})" if errs else ""))
            else:
                print(f"{path}: не EVTX или не удалось разобрать заголовок")
            continue

        # фильтрация
        sel = []
        for xml in recs:
            if eid_filter and get_eid(xml) not in eid_filter:
                continue
            if grep and grep not in xml.lower():
                continue
            if after or before:
                u = get_utc(xml)
                if not u:
                    continue
                try:
                    dt = datetime.fromisoformat(u.replace('Z','+00:00'))
                except Exception:
                    continue
                if after and dt < after:
                    continue
                if before and dt > before:
                    continue
            sel.append(xml)

        if len(paths) > 1:
            print(f"\n{C.BOLD}### {path}{C.X}  ({len(sel)}/{len(recs)} после фильтров"
                  + (f", chunk-errors {errs}" if errs else "") + ")")

        if args.summary:
            from collections import Counter
            cnt = Counter(get_eid(x) for x in sel)
            times = sorted(get_utc(x) for x in sel if get_utc(x))
            print(f"  Всего: {len(sel)} записей")
            if times:
                print(f"  Диапазон (UTC): {times[0][:19]}  ..  {times[-1][:19]}")
            print("  EventID:")
            for eid, n in cnt.most_common():
                hot = f" {C.R}<-- security-relevant{C.X}" if eid in HOT_EID else ""
                print(f"    {eid:>6}: {n}{hot}")
            continue

        shown = 0
        for xml in sel:
            if args.limit and shown >= args.limit:
                print(f"  {C.DIM}... (ограничено --limit {args.limit}){C.X}")
                break
            if args.full:
                full_dump(xml, args.tz)
            else:
                print(summarize_line(xml, args.tz))
            shown += 1

            if args.csv or args.json:
                d = get_data_fields(xml)
                d['_EventID'] = get_eid(xml)
                d['_UTC'] = get_utc(xml)
                d['_Local'] = to_local(get_utc(xml), args.tz)
                d['_Provider'] = get_provider(xml)
                d['_Computer'] = get_computer(xml)
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
