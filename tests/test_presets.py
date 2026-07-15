"""Тесты пресетов анализа."""
from evtxview.record import EventRecord
from evtxview.presets import process_tree


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
