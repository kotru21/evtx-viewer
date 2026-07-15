"""Юнит-тесты чистых функций разбора полей — без чтения .evtx файлов."""
from datetime import datetime, timezone

import pytest

from evtxview import cli

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
    assert cli.get_eid(EVENTDATA_XML) == "1"
    assert cli.get_eid("<Event/>") == "?"


def test_get_utc_provider_computer():
    assert cli.get_utc(EVENTDATA_XML) == "2026-05-11T12:15:49.123456Z"
    assert cli.get_provider(EVENTDATA_XML) == "Microsoft-Windows-Sysmon"
    assert cli.get_computer(EVENTDATA_XML) == "vm1-PC"


def test_get_data_fields_eventdata():
    d = cli.get_data_fields(EVENTDATA_XML)
    assert d["Image"].endswith("cmd.exe")
    assert d["CommandLine"] == "cmd /c whoami"
    assert d["User"] == "vm1\\john"


def test_get_data_fields_userdata_branch():
    d = cli.get_data_fields(USERDATA_XML)
    assert d["Module"] == "spoolsv.exe"
    assert d["Status"] == "0x0"


def test_to_local_offset():
    # UTC 12:15:49 при сдвиге +3 -> 15:15:49
    assert cli.to_local("2026-05-11T12:15:49.000000Z", 3.0) == "2026-05-11 15:15:49"
    assert cli.to_local("", 3.0) == ""


def test_parse_dt_formats():
    assert cli.parse_dt("2026-05-11 12:24") == datetime(2026, 5, 11, 12, 24, tzinfo=timezone.utc)
    assert cli.parse_dt("2026-05-11") == datetime(2026, 5, 11, tzinfo=timezone.utc)


def test_parse_dt_bad_raises():
    with pytest.raises(SystemExit):
        cli.parse_dt("not-a-date")


def test_summarize_line_truncates_long_values():
    long_cmd = "cmd /c " + "A" * 200
    xml = EVENTDATA_XML.replace("cmd /c whoami", long_cmd)
    line = cli.summarize_line(xml, 3.0)
    assert "..." in line
    assert "EID" in line


def test_hot_eid_membership():
    assert "1102" in cli.HOT_EID  # очистка лога
    assert "4625" in cli.HOT_EID  # неуспешный вход
