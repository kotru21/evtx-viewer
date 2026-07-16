"""Тесты пресетов анализа."""
from evtxview.record import EventRecord
from evtxview.presets import logon_analysis, process_tree


def proc(guid, pguid, image, pid, utc, cmd=""):
    return EventRecord(
        xml="", eid="1", utc=utc,
        data={
            "ProcessGuid": guid, "ParentProcessGuid": pguid,
            "Image": image, "ProcessId": pid, "CommandLine": cmd,
        },
    )


def test_process_tree_structure(capsys):
    records = [
        proc("P", "X", r"C:\Windows\System32\cmd.exe", "100", "2026-05-11T12:00:00Z"),
        proc("C2", "P", r"C:\Windows\System32\net.exe", "300", "2026-05-11T12:00:05Z", "net user john /add"),
        proc("C1", "P", r"C:\Windows\System32\ipconfig.exe", "200", "2026-05-11T12:00:01Z"),
    ]
    process_tree(records, tz=0)
    out = capsys.readouterr().out
    assert "3 процессов, 1 корней" in out
    assert "cmd.exe (100)" in out
    # дети отсортированы по времени: ipconfig (12:00:01) раньше net (12:00:05)
    assert out.index("ipconfig.exe") < out.index("net.exe")
    # последний ребёнок — с └─, промежуточный — с ├─
    assert "├─ " in out and "└─ " in out
    assert "net user john /add" in out


def test_process_tree_orphan_is_root(capsys):
    # родитель не захвачен в выборке → процесс становится корнем
    records = [proc("A", "MISSING", r"C:\x\a.exe", "1", "2026-05-11T12:00:00Z")]
    process_tree(records, tz=0)
    out = capsys.readouterr().out
    assert "1 процессов, 1 корней" in out
    assert "a.exe (1)" in out


def test_process_tree_no_eid1(capsys):
    records = [EventRecord(xml="", eid="3", utc="2026-05-11T12:00:00Z")]
    process_tree(records, tz=0)
    out = capsys.readouterr().out
    assert "Нет событий Sysmon EID 1" in out


# ---------- logon-analysis ----------
def logon(logon_id, utc, user="vm1", domain="vm1-PC", logon_type="10", ip="10.8.0.2"):
    return EventRecord(
        xml="", eid="4624", utc=utc,
        data={"TargetLogonId": logon_id, "TargetUserName": user,
              "TargetDomainName": domain, "LogonType": logon_type, "IpAddress": ip},
    )


def logoff(logon_id, utc, user="vm1", domain="vm1-PC"):
    return EventRecord(
        xml="", eid="4634", utc=utc,
        data={"TargetLogonId": logon_id, "TargetUserName": user, "TargetDomainName": domain},
    )


def priv(logon_id, utc):
    return EventRecord(xml="", eid="4672", utc=utc, data={"SubjectLogonId": logon_id})


def failed(utc, user="attacker", ip="203.0.113.5", logon_type="3"):
    return EventRecord(
        xml="", eid="4625", utc=utc,
        data={"TargetUserName": user, "IpAddress": ip, "LogonType": logon_type},
    )


def test_logon_analysis_pairs_session_and_duration(capsys):
    records = [
        logon("0x1", "2026-05-11T12:00:00Z"),
        logoff("0x1", "2026-05-11T12:05:30Z"),
    ]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "1 успешных, 0 неуспешных" in out
    assert "vm1-PC\\vm1" in out
    assert "(5:30)" in out
    assert "RemoteInteractive(RDP)" in out
    assert "IP=10.8.0.2" in out


def test_logon_analysis_marks_privileged_session(capsys):
    records = [logon("0x1", "2026-05-11T12:00:00Z"), priv("0x1", "2026-05-11T12:00:01Z")]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "[privileged: 4672]" in out


def test_logon_analysis_open_session_no_logoff(capsys):
    records = [logon("0x1", "2026-05-11T12:00:00Z")]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "нет парного 4634" in out


def test_logon_analysis_lists_failures(capsys):
    records = [failed("2026-05-11T12:00:00Z", user="john")]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "0 успешных, 1 неуспешных" in out
    assert "Неуспешные входы" in out
    assert "john" in out
    assert "203.0.113.5" in out


def test_logon_analysis_detects_brute_force_by_account(capsys):
    # 5 неудач за минуту по одной учётке — порог достигнут
    records = [failed(f"2026-05-11T12:00:{i:02d}Z", user="admin") for i in range(5)]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "Возможный brute-force" in out
    assert "admin" in out


def test_logon_analysis_no_brute_force_below_threshold(capsys):
    records = [failed(f"2026-05-11T12:00:{i:02d}Z", user="john") for i in range(4)]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "brute-force" not in out


def test_logon_analysis_no_brute_force_outside_window(capsys):
    # 5 неудач, но растянуты на часы — порог не должен сработать
    records = [failed(f"2026-05-11T{12+i:02d}:00:00Z", user="john") for i in range(5)]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "brute-force" not in out


def test_logon_analysis_empty(capsys):
    records = [EventRecord(xml="", eid="1", utc="2026-05-11T12:00:00Z")]
    logon_analysis(records, tz=0)
    out = capsys.readouterr().out
    assert "Нет событий входа" in out
