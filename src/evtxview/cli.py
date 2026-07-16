#!/usr/bin/env python3
"""
evtxview — просмотр и триаж Windows .evtx на любой ОС.

Построен на rust-based парсере `evtx`, который читает ВСЕ chunk'и файла —
в отличие от python-evtx, способного молча остановиться на первом chunk и
потерять большую часть записей. Флаг --verify сверяет полноту чтения.

Примеры:
  evtxview Security.evtx --summary
  evtxview Sysmon.evtx --eid 1,3 --grep spoolsv
  evtxview Sysmon.evtx Security.evtx --timeline --after "2026-05-11 12:57"
  evtxview Security.evtx --eid 1102 --full
  evtxview Sysmon.evtx --eid 1 --csv out.csv
  evtxview Sysmon.evtx --verify        # сверка полноты (chunk-заголовки vs прочитано)
  evtxview *.evtx --summary            # сводка по нескольким файлам
"""

import argparse
import glob
import os
import sys
from datetime import datetime

from evtxview.export import export_row, write_csv, write_json
from evtxview.presets import PRESETS
from evtxview.reader import read_records, verify_completeness
from evtxview.record import get_record_id, parse_record
from evtxview.render import C, full_dump, print_summary, summarize_line
from evtxview.util import force_utf8_output, parse_dt


def build_parser():
    ap = argparse.ArgumentParser(
        description="Просмотр и триаж Windows .evtx (корректное чтение всех chunk'ов).",
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
    ap.add_argument('--timeline', action='store_true', help='единая лента из всех файлов, отсортированная по времени')
    ap.add_argument('--preset', choices=sorted(PRESETS), help='готовое представление (например, process-tree)')
    ap.add_argument('--verify', action='store_true', help='сверка полноты парсинга (chunk-заголовки)')
    ap.add_argument('--csv', metavar='FILE', help='экспорт в CSV')
    ap.add_argument('--json', metavar='FILE', help='экспорт распарсенных событий в JSON')
    ap.add_argument('--limit', type=int, help='показать не более N событий')
    return ap


def filter_records(records, eid_filter, grep, after, before):
    """Отбор записей по EID / подстроке / временному окну (UTC)."""
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
                dt = datetime.fromisoformat(rec.utc.replace('Z', '+00:00'))
            except Exception:
                continue
            if after and dt < after:
                continue
            if before and dt > before:
                continue
        sel.append(rec)
    return sel


def print_verify(path, recs, errs):
    v = verify_completeness(path, (get_record_id(x) for x in recs))
    if not v:
        print(f"{path}: не EVTX или не удалось разобрать заголовок")
        return
    mark = f"{C.G}OK{C.X}" if v['complete'] else f"{C.R}!!! ОБРЕЗКА{C.X}"
    print(f"{C.BOLD}{path}{C.X}: chunks={v['chunks']} заявлено={v['expected']} "
          f"прочитано={v['got']} {mark}" + (f" (chunk-errors: {errs})" if errs else ""))
    if v['range_unreliable']:
        print(f"  {C.R}заголовок chunk'а повреждён: диапазон EventRecordID "
              f"({v['id_lo']}..{v['id_hi']}) неправдоподобно широк — "
              f"проверка пропусков невозможна{C.X}")
        return
    miss = v['missing']
    if miss:
        sample = ', '.join(str(i) for i in miss[:15])
        more = f" …(+{len(miss) - 15})" if len(miss) > 15 else ""
        print(f"  {C.R}пропущено EventRecordID: {len(miss)}{C.X}"
              f"  [{sample}{more}]  (диапазон {v['id_lo']}..{v['id_hi']})")


def render_events(items, args, all_rows):
    """Печать событий (одной строкой или --full) с учётом --limit.

    --limit ограничивает только то, что печатается в терминал. Экспорт в
    CSV/JSON собирает ВСЕ отобранные события независимо от --limit — иначе
    флаг для удобства чтения вывода незаметно урезал бы выгружаемые улики.

    items — последовательность (path, rec, source|None)."""
    exporting = bool(args.csv or args.json)
    shown = 0
    limited = False
    for path, rec, source in items:
        if exporting:
            all_rows.append(export_row(rec, path, args.tz))
        if args.limit and shown >= args.limit:
            if not limited:
                note = ", экспорт включает все события" if exporting else ""
                print(f"  {C.DIM}... (ограничено --limit {args.limit}{note}){C.X}")
                limited = True
            if not exporting:
                break
            continue
        if args.full:
            full_dump(rec, args.tz, source=source)
        else:
            print(summarize_line(rec, args.tz, source=source))
        shown += 1


def main():
    force_utf8_output()
    args = build_parser().parse_args()

    if (args.summary or args.preset) and (args.csv or args.json):
        sys.exit("--csv/--json несовместимы с --summary/--preset: "
                  "эти режимы не строят построчную выборку событий для экспорта")

    paths = []
    for f in args.files:
        paths.extend(sorted(glob.glob(f)) or [f])

    eid_filter = set(args.eid.split(',')) if args.eid else None
    after = parse_dt(args.after) if args.after else None
    before = parse_dt(args.before) if args.before else None
    grep = args.grep.lower() if args.grep else None

    all_rows = []
    timeline = []      # (path, rec) со всех файлов для --timeline
    preset_recs = []   # записи со всех файлов для --preset

    for path in paths:
        try:
            recs, errs = read_records(path)
        except Exception as e:
            print(f"{C.R}{path}: ошибка чтения — {e}{C.X}")
            continue

        if args.verify:
            print_verify(path, recs, errs)
            continue

        sel = filter_records((parse_record(x) for x in recs), eid_filter, grep, after, before)

        if args.preset:
            preset_recs.extend(sel)
            continue

        if args.timeline:
            timeline.extend((path, rec) for rec in sel)
            continue

        if len(paths) > 1:
            print(f"\n{C.BOLD}### {path}{C.X}  ({len(sel)}/{len(recs)} после фильтров"
                  + (f", chunk-errors {errs}" if errs else "") + ")")

        if args.summary:
            print_summary(sel, args.tz)
            continue

        render_events(((path, rec, None) for rec in sel), args, all_rows)

    if args.preset:
        PRESETS[args.preset](preset_recs, args.tz)

    if args.timeline:
        timeline.sort(key=lambda pr: (pr[1].utc == '', pr[1].utc))
        if args.summary:
            print_summary([rec for _, rec in timeline], args.tz, files=len(paths))
        else:
            render_events(((p, rec, os.path.basename(p)) for p, rec in timeline), args, all_rows)

    if args.json and all_rows:
        write_json(all_rows, args.json)
    if args.csv and all_rows:
        write_csv(all_rows, args.csv)


if __name__ == '__main__':
    main()
