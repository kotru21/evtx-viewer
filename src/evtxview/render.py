"""Форматирование вывода: цвета, однострочная сводка, полный дамп, статистика."""

import sys
from collections import Counter

from evtxview.config import DEFAULT_CONFIG
from evtxview.util import to_local


class C:
    """ANSI-цвета — включаются только при выводе в терминал."""
    on = sys.stdout.isatty()
    R = '\033[31m' if on else ''; G = '\033[32m' if on else ''
    Y = '\033[33m' if on else ''; B = '\033[34m' if on else ''
    CY = '\033[36m' if on else ''; DIM = '\033[2m' if on else ''
    BOLD = '\033[1m' if on else ''; X = '\033[0m' if on else ''


def summarize_line(rec, offset, source=None, config=DEFAULT_CONFIG):
    t = to_local(rec.utc, offset)
    src = f"  {C.B}[{source}]{C.X}" if source else ''
    interesting = []
    for key in config.summary_fields:
        if key in rec.data and rec.data[key]:
            val = rec.data[key]
            if len(val) > 70:
                val = val[:67] + '...'
            interesting.append(f"{key}={val}")
    extra = ' '.join(interesting[:4])
    col = C.R if rec.eid in config.hot_eids else C.CY
    return f"{C.DIM}{t}{C.X}{src}  {col}EID {rec.eid:>5}{C.X}  {extra}"


def full_dump(rec, offset, source=None, config=DEFAULT_CONFIG):
    print(f"{C.BOLD}{'=' * 70}{C.X}")
    src = f"  {C.B}[{source}]{C.X}" if source else ''
    print(f"{C.R if rec.eid in config.hot_eids else C.CY}EID {rec.eid}{C.X}{src}  "
          f"{C.DIM}{to_local(rec.utc, offset)} (local)  |  {rec.utc} UTC{C.X}")
    print(f"Provider: {rec.provider}  |  Computer: {rec.computer}")
    if rec.data:
        w = max(len(k) for k in rec.data)
        for k, v in rec.data.items():
            print(f"   {C.Y}{k:>{w}}{C.X} = {v}")


def print_summary(recs, tz, files=None, config=DEFAULT_CONFIG):
    """Сводка: количество, диапазон времени, распределение EventID."""
    cnt = Counter(r.eid for r in recs)
    times = sorted(r.utc for r in recs if r.utc)
    suffix = f" ({files} файлов)" if files else ""
    print(f"  Всего: {len(recs)} записей{suffix}")
    if times:
        print(f"  Диапазон (UTC): {times[0][:19]}  ..  {times[-1][:19]}")
    print("  EventID:")
    for eid, n in cnt.most_common():
        hot = f" {C.R}<-- security-relevant{C.X}" if eid in config.hot_eids else ""
        print(f"    {eid:>6}: {n}{hot}")
