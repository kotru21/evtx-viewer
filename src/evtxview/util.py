"""Утилиты: кодировка вывода и работа со временем."""

import re
import sys
from datetime import datetime, timezone, timedelta

_OFFSET_RE = re.compile(r'([+-]\d{2}):?(\d{2})$')


def force_utf8_output():
    """Windows пишет stdout в кодировке локали (cp1251) — кириллица бьётся.
    Принудительно переключаем потоки на UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure:
            try:
                reconfigure(encoding='utf-8')
            except (ValueError, OSError):
                pass


def parse_utc(utc_str):
    """EventRecord.utc (ISO-строка) -> datetime с tzinfo, либо None, если не парсится."""
    if not utc_str:
        return None
    try:
        dt = datetime.fromisoformat(utc_str.replace('Z', '+00:00'))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def to_local(utc_str, offset_hours):
    """ISO UTC -> локальное время со сдвигом. Непарсимую строку отдаём как есть."""
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


def _split_offset(s):
    """Отделяет суффикс явного часового пояса ('+03:00', '+0300', 'Z') от
    остальной строки. Возвращает (строка_без_суффикса, timedelta|None)."""
    s = s.strip()
    if s.endswith(('Z', 'z')):
        return s[:-1].strip(), timedelta(0)
    m = _OFFSET_RE.search(s)
    if m:
        sign = 1 if m.group(1)[0] == '+' else -1
        hours, minutes = int(m.group(1)[1:]), int(m.group(2))
        return s[:m.start()].strip(), sign * timedelta(hours=hours, minutes=minutes)
    return s, None


def parse_dt(s, tz_filter_hours=None):
    """Гибкий парс времени для фильтров --after/--before.

    Значение может нести явный суффикс часового пояса ('2026-05-11 15:57 +03:00',
    '...Z') — он используется как есть и имеет приоритет. Без суффикса значение
    по умолчанию трактуется как UTC; если передан tz_filter_hours (флаг
    --tz-filter), наивное значение трактуется в этом смещении вместо UTC.
    """
    body, offset = _split_offset(s)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d %H', '%Y-%m-%d'):
        try:
            dt = datetime.strptime(body, fmt)
            break
        except ValueError:
            continue
    else:
        sys.exit(f"Не понял дату: {s} (формат: 'YYYY-MM-DD HH:MM:SS', "
                  f"можно с суффиксом часового пояса '+03:00' или 'Z')")

    if offset is not None:
        return dt.replace(tzinfo=timezone(offset))
    if tz_filter_hours is not None:
        return dt.replace(tzinfo=timezone(timedelta(hours=tz_filter_hours)))
    return dt.replace(tzinfo=timezone.utc)
