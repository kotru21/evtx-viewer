"""Экспорт отобранных событий в CSV/JSON."""

import csv
import json

from evtxview.render import C
from evtxview.util import to_local


def export_row(rec, path, tz):
    """Плоский словарь события: метаполя (_*) + все поля данных."""
    d = dict(rec.data)
    d['_EventID'] = rec.eid
    d['_UTC'] = rec.utc
    d['_Local'] = to_local(rec.utc, tz)
    d['_Provider'] = rec.provider
    d['_Computer'] = rec.computer
    d['_SourceFile'] = path
    return d


def write_json(rows, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"\n{C.G}JSON записан: {path} ({len(rows)} событий){C.X}")


def write_csv(rows, path):
    keys = []
    for r in rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    # порядок колонок: метаполя (_*) впереди, затем поля данных
    meta = [k for k in keys if k.startswith('_')]
    rest = [k for k in keys if not k.startswith('_')]
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=meta + rest, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    print(f"\n{C.G}CSV записан: {path} ({len(rows)} событий){C.X}")
