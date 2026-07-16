"""Тесты пресетов анализа."""
from evtxview.record import EventRecord
from evtxview.presets import logon_analysis, network, process_tree, rdp_activity


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


# ---------- network ----------
def conn(utc, dst_ip, dst_port, image, initiated="false", src_ip="10.8.0.2"):
    return EventRecord(
        xml="", eid="3", utc=utc,
        data={"DestinationIp": dst_ip, "DestinationPort": dst_port,
              "Image": image, "Initiated": initiated, "SourceIp": src_ip},
    )


def test_network_groups_by_destination(capsys):
    records = [
        conn("2026-05-11T12:00:00Z", "10.10.10.20", "3389", r"C:\Windows\svchost.exe"),
        conn("2026-05-11T12:00:05Z", "10.10.10.20", "3389", r"C:\Windows\svchost.exe"),
    ]
    network(records, tz=0)
    out = capsys.readouterr().out
    assert "2 событий, 1 назначений" in out
    assert "10.10.10.20:3389" in out
    assert "2 соедин." in out
    assert "svchost.exe" in out


def test_network_flags_unusual_port(capsys):
    records = [conn("2026-05-11T12:00:00Z", "203.0.113.5", "4444", r"C:\Windows\spoolsv.exe")]
    network(records, tz=0)
    out = capsys.readouterr().out
    assert "необычный порт" in out


def test_network_does_not_flag_common_port(capsys):
    records = [conn("2026-05-11T12:00:00Z", "10.10.10.20", "445", "System")]
    network(records, tz=0)
    out = capsys.readouterr().out
    assert "необычный порт" not in out


def test_network_does_not_flag_dynamic_rpc_port(capsys):
    # 49152+ — динамический RPC-диапазон после негоциации через 135, не аномалия
    records = [conn("2026-05-11T12:00:00Z", "10.10.10.20", "49200", "lsass.exe")]
    network(records, tz=0)
    out = capsys.readouterr().out
    assert "необычный порт" not in out


def test_network_flags_outbound_direction(capsys):
    records = [conn("2026-05-11T12:00:00Z", "10.10.10.1", "22", "nmap.exe", initiated="true")]
    network(records, tz=0)
    out = capsys.readouterr().out
    assert "исходящее с этого хоста (1)" in out


def test_network_notable_sorted_first(capsys):
    # частый легитимный трафик (RDP, много соединений) не должен вытеснить
    # редкое, но заметное необычным портом соединение из верхней части вывода
    records = [conn(f"2026-05-11T12:00:{i:02d}Z", "10.10.10.20", "3389", "svchost.exe")
               for i in range(20)]
    records.append(conn("2026-05-11T12:05:00Z", "10.10.10.1", "22", "nmap.exe", initiated="true"))
    network(records, tz=0)
    out = capsys.readouterr().out
    assert out.index("10.10.10.1:22") < out.index("10.10.10.20:3389")


def test_network_empty(capsys):
    records = [EventRecord(xml="", eid="1", utc="2026-05-11T12:00:00Z")]
    network(records, tz=0)
    out = capsys.readouterr().out
    assert "Нет событий Sysmon EID 3" in out


# ---------- rdp ----------
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"


def lsm_event(eid, utc, user="vm1-PC\\john", address="10.8.0.2"):
    return EventRecord(xml="", eid=eid, utc=utc, provider=LSM,
                        data={"User": user, "Address": address})


def rcm_auth(utc, user="john", ip="10.8.0.2"):
    return EventRecord(xml="", eid="1149", utc=utc, provider=RCM,
                        data={"Param1": user, "Param3": ip})


def sec_logon(eid, utc, user="john", domain="vm1-PC", ip="10.8.0.2", logon_type="10"):
    return EventRecord(xml="", eid=eid, utc=utc,
                        data={"TargetUserName": user, "TargetDomainName": domain,
                              "IpAddress": ip, "LogonType": logon_type})


def test_rdp_merges_sources_chronologically(capsys):
    records = [
        lsm_event("21", "2026-05-11T12:00:01Z"),
        rcm_auth("2026-05-11T12:00:00Z"),
        sec_logon("4624", "2026-05-11T12:00:02Z"),
    ]
    rdp_activity(records, tz=0)
    out = capsys.readouterr().out
    assert "3 событий" in out
    lines = [ln for ln in out.splitlines() if "2026-05-11" in ln]
    assert len(lines) == 3
    # аутентификация (1149) раньше логона (21), раньше входа в Security
    assert "аутентификация" in lines[0]
    assert "логон" in lines[1]
    assert "вход (Security 4624)" in lines[2]


def test_rdp_highlights_failed_logon(capsys):
    records = [sec_logon("4625", "2026-05-11T12:00:00Z", user="attacker")]
    rdp_activity(records, tz=0)
    out = capsys.readouterr().out
    assert "НЕУДАЧНЫЙ вход (Security 4625)" in out
    assert "attacker" in out


def test_rdp_ignores_non_rdp_logon_type(capsys):
    # LogonType=2 (Interactive) — не RDP, не должен попасть в вывод
    records = [sec_logon("4624", "2026-05-11T12:00:00Z", logon_type="2")]
    rdp_activity(records, tz=0)
    out = capsys.readouterr().out
    assert "Нет событий RDP-активности" in out


def test_rdp_ignores_eid_collision_from_other_provider(capsys):
    # EID 21 без провайдера LSM не должен трактоваться как RDP-логон
    records = [EventRecord(xml="", eid="21", utc="2026-05-11T12:00:00Z", provider="SomeOtherApp")]
    rdp_activity(records, tz=0)
    out = capsys.readouterr().out
    assert "Нет событий RDP-активности" in out


def test_rdp_empty(capsys):
    records = [EventRecord(xml="", eid="1", utc="2026-05-11T12:00:00Z")]
    rdp_activity(records, tz=0)
    out = capsys.readouterr().out
    assert "Нет событий RDP-активности" in out
