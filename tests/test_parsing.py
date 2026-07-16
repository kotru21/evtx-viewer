"""Юнит-тесты чистых функций разбора полей — без чтения .evtx файлов."""
from datetime import datetime, timedelta, timezone

import pytest

from evtxview.config import DEFAULT_HOT_EIDS as HOT_EID
from evtxview.record import (
    get_data_fields, get_eid, get_provider, get_computer, get_record_id,
    get_utc, parse_record,
)
from evtxview.render import summarize_line
from evtxview.util import parse_dt, to_local

EVENTDATA_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{abc}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-05-11T12:15:49.123456Z"/>
    <Computer>vm1-PC</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd /c whoami</Data>
    <Data Name="User">vm1\\john</Data>
  </EventData>
</Event>"""

USERDATA_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PrintService"/>
    <EventID>823</EventID>
    <TimeCreated SystemTime="2026-05-11T12:44:04.000000Z"/>
    <Computer>vm1-PC</Computer>
  </System>
  <UserData>
    <DocumentPrinted>
      <Module>spoolsv.exe</Module>
      <Status>0x0</Status>
    </DocumentPrinted>
  </UserData>
</Event>"""


def test_get_eid():
    assert get_eid(EVENTDATA_XML) == "1"
    assert get_eid("<Event/>") == "?"


def test_get_utc_provider_computer():
    assert get_utc(EVENTDATA_XML) == "2026-05-11T12:15:49.123456Z"
    assert get_provider(EVENTDATA_XML) == "Microsoft-Windows-Sysmon"
    assert get_computer(EVENTDATA_XML) == "vm1-PC"


def test_get_data_fields_eventdata():
    d = get_data_fields(EVENTDATA_XML)
    assert d["Image"].endswith("cmd.exe")
    assert d["CommandLine"] == "cmd /c whoami"
    assert d["User"] == "vm1\\john"


def test_get_data_fields_userdata_branch():
    d = get_data_fields(USERDATA_XML)
    assert d["Module"] == "spoolsv.exe"
    assert d["Status"] == "0x0"


def test_to_local_offset():
    # UTC 12:15:49 при сдвиге +3 -> 15:15:49
    assert to_local("2026-05-11T12:15:49.000000Z", 3.0) == "2026-05-11 15:15:49"
    assert to_local("", 3.0) == ""


def test_to_local_bad_input_fallback():
    # непарсимую строку возвращаем как есть (обрезав до 19 символов)
    assert to_local("не-дата-2026-xxxxxxxxxxxx", 3.0) == "не-дата-2026-xxxxxx"


def test_get_record_id():
    assert get_record_id("<EventRecordID>13501</EventRecordID>") == 13501
    assert get_record_id("<Event/>") is None


def test_parse_dt_formats():
    assert parse_dt("2026-05-11 12:24") == datetime(2026, 5, 11, 12, 24, tzinfo=timezone.utc)
    assert parse_dt("2026-05-11") == datetime(2026, 5, 11, tzinfo=timezone.utc)


def test_parse_dt_bad_raises():
    with pytest.raises(SystemExit):
        parse_dt("not-a-date")


def test_parse_dt_explicit_offset_suffix():
    dt = parse_dt("2026-05-11 15:57:00 +03:00")
    assert dt == datetime(2026, 5, 11, 15, 57, tzinfo=timezone(timedelta(hours=3)))


def test_parse_dt_explicit_offset_compact():
    # без двоеточия: "+0300"
    dt = parse_dt("2026-05-11 15:57:00+0300")
    assert dt == datetime(2026, 5, 11, 15, 57, tzinfo=timezone(timedelta(hours=3)))


def test_parse_dt_z_suffix_is_utc():
    dt = parse_dt("2026-05-11 12:57:00Z")
    assert dt == datetime(2026, 5, 11, 12, 57, tzinfo=timezone.utc)


def test_parse_dt_negative_offset():
    dt = parse_dt("2026-05-11 07:57:00 -05:00")
    assert dt == datetime(2026, 5, 11, 7, 57, tzinfo=timezone(timedelta(hours=-5)))


def test_parse_dt_utc_and_offset_are_equivalent_instant():
    # 12:57 UTC и 15:57 +03:00 — один и тот же момент времени
    assert parse_dt("2026-05-11 12:57:00") == parse_dt("2026-05-11 15:57:00 +03:00")


def test_parse_dt_naive_defaults_to_utc_without_tz_filter():
    dt = parse_dt("2026-05-11 12:57:00")
    assert dt.tzinfo == timezone.utc


def test_parse_dt_tz_filter_hours_interprets_naive_as_local():
    dt = parse_dt("2026-05-11 15:57:00", tz_filter_hours=3.0)
    assert dt == datetime(2026, 5, 11, 15, 57, tzinfo=timezone(timedelta(hours=3)))
    # эквивалентно тому же моменту, что и явный UTC 12:57
    assert dt == parse_dt("2026-05-11 12:57:00")


def test_parse_dt_explicit_offset_overrides_tz_filter():
    # явный суффикс в значении важнее --tz-filter
    dt = parse_dt("2026-05-11 12:57:00 +00:00", tz_filter_hours=3.0)
    assert dt.utcoffset() == timedelta(0)


def test_summarize_line_truncates_long_values():
    long_cmd = "cmd /c " + "A" * 200
    xml = EVENTDATA_XML.replace("cmd /c whoami", long_cmd)
    line = summarize_line(parse_record(xml), 3.0)
    assert "..." in line
    assert "EID" in line


def test_hot_eid_membership():
    assert "1102" in HOT_EID  # очистка лога
    assert "4625" in HOT_EID  # неуспешный вход


# ---------- parse_record: единая модель ----------
def test_parse_record_eventdata():
    """Основной путь — ElementTree — на XML с декларацией кодировки."""
    xml = '<?xml version="1.0" encoding="utf-8"?>' + EVENTDATA_XML.split("?>", 1)[-1]
    rec = parse_record(xml)
    assert rec.eid == "1"
    assert rec.provider == "Microsoft-Windows-Sysmon"
    assert rec.computer == "vm1-PC"
    assert rec.utc == "2026-05-11T12:15:49.123456Z"
    assert rec.data["CommandLine"] == "cmd /c whoami"


def test_parse_record_userdata_branch():
    rec = parse_record(USERDATA_XML)
    assert rec.eid == "823"
    assert rec.data["Module"] == "spoolsv.exe"
    assert rec.data["Status"] == "0x0"


def test_parse_record_namespaced_multiline():
    """namespace на тегах и многострочное значение — regex это ломало."""
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4104</EventID>"
        '<Provider Name="Microsoft-Windows-PowerShell"/>'
        '<TimeCreated SystemTime="2026-05-11T12:00:00.0Z"/>'
        "<Computer>vm1-PC</Computer></System>"
        '<EventData><Data Name="ScriptBlockText">line1\nline2\nline3</Data></EventData>'
        "</Event>"
    )
    rec = parse_record(xml)
    assert rec.eid == "4104"
    assert rec.data["ScriptBlockText"] == "line1\nline2\nline3"


def test_parse_record_falls_back_on_malformed_xml():
    """Битый XML (незакрытый тег) — не падаем, извлекаем regex-ом что можем."""
    broken = "<Event><System><EventID>4625</EventID><Computer>vm1-PC</Event>"
    rec = parse_record(broken)
    assert rec.eid == "4625"  # получено fallback-регуляркой


def test_parse_record_decodes_xml_entities():
    """Значение с экранированным XML (GroupPolicy GPOInfoList) декодируется,
    а не остаётся сырым &lt;/&gt; как было при regex-разборе."""
    xml = (
        "<Event><System><EventID>5312</EventID></System>"
        '<EventData><Data Name="GPOInfoList">'
        "&lt;GPO&gt;&lt;Name&gt;Local Group Policy&lt;/Name&gt;&lt;/GPO&gt;"
        "</Data></EventData></Event>"
    )
    rec = parse_record(xml)
    assert rec.data["GPOInfoList"] == "<GPO><Name>Local Group Policy</Name></GPO>"


def test_parse_record_captures_self_closing_and_empty():
    """Self-closing <Data Name="x"/> и пустые — не ломают разбор."""
    xml = (
        "<Event><System><EventID>1</EventID></System>"
        '<EventData><Data Name="Empty"/><Data Name="Val">x</Data></EventData></Event>'
    )
    rec = parse_record(xml)
    assert rec.data["Val"] == "x"
    assert rec.data["Empty"] == ""
