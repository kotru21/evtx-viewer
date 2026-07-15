"""Модель записи события и её разбор.

parse_record() — основной путь (ElementTree), устойчивый к namespace,
атрибутам и многострочным значениям, с декодированием XML-сущностей.
Регулярки ниже — fallback для битого/нестандартного XML и точечная выборка.
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Optional


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
    ud = re.search(r'<UserData>(.*?)</UserData>', xml, re.S)
    if ud:
        for m in re.finditer(r'<(\w+)>([^<>]+)</\1>', ud.group(1)):
            d.setdefault(m.group(1), m.group(2).strip())
    return d


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
    """Разбирает XML записи один раз. Основной путь — ElementTree; при ошибке —
    fallback на regex.

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
            for leaf in el.iter():
                if leaf is el or len(leaf):
                    continue
                if leaf.text and leaf.text.strip():
                    rec.data.setdefault(_localname(leaf.tag), leaf.text.strip())
    return rec
