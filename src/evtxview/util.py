"""Утилиты: кодировка вывода и работа со временем."""

import sys
from datetime import datetime, timezone, timedelta


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


def parse_dt(s):
    """Гибкий парс времени для фильтров --after/--before (UTC)."""
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d %H', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    sys.exit(f"Не понял дату: {s} (формат: 'YYYY-MM-DD HH:MM:SS')")
