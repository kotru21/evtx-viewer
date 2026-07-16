"""End-to-end тесты CLI через main() (argparse + вывод)."""
import pytest

from evtxview import cli


def run(monkeypatch, capsys, *args):
    monkeypatch.setattr("sys.argv", ["evtxview", *args])
    cli.main()
    return capsys.readouterr().out


def test_summary_output(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--summary")
    assert "Всего: 7 записей" in out  # кириллица не побита
    assert "4624" in out
    assert "security-relevant" in out


def test_eid_filter_single(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--eid", "1102")
    eid_lines = [ln for ln in out.splitlines() if "EID" in ln]
    assert len(eid_lines) == 1
    assert "1102" in eid_lines[0]


def test_verify_ok(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--verify")
    assert "OK" in out
    assert "прочитано=7" in out


def test_limit_caps_output(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--limit", "2")
    eid_lines = [ln for ln in out.splitlines() if ln.strip().startswith("2026")]
    assert len(eid_lines) == 2


def test_limit_does_not_truncate_export(monkeypatch, capsys, tmp_path, security_evtx):
    """--limit ограничивает печать, но не то, что уходит в CSV/JSON."""
    out_file = tmp_path / "out.csv"
    out = run(monkeypatch, capsys, security_evtx, "--limit", "2", "--csv", str(out_file))
    printed = [ln for ln in out.splitlines() if ln.strip().startswith("2026")]
    assert len(printed) == 2
    assert "экспорт включает все события" in out

    import csv as _csv
    with out_file.open(encoding="utf-8") as f:
        rows = list(_csv.DictReader(f))
    assert len(rows) == 7  # все отфильтрованные записи, не только напечатанные


def test_summary_with_csv_rejected(monkeypatch, capsys, tmp_path, security_evtx):
    out_file = tmp_path / "out.csv"
    with pytest.raises(SystemExit):
        run(monkeypatch, capsys, security_evtx, "--summary", "--csv", str(out_file))
    assert not out_file.exists()


def test_preset_with_json_rejected(monkeypatch, capsys, tmp_path, security_evtx):
    out_file = tmp_path / "out.json"
    with pytest.raises(SystemExit):
        run(monkeypatch, capsys, security_evtx, "--preset", "process-tree", "--json", str(out_file))
    assert not out_file.exists()


def test_json_export(monkeypatch, capsys, tmp_path, security_evtx):
    out_file = tmp_path / "out.json"
    out = run(monkeypatch, capsys, security_evtx, "--eid", "1102", "--json", str(out_file))
    assert out_file.exists()
    import json

    rows = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(rows) == 1
    assert rows[0]["_EventID"] == "1102"
    assert rows[0]["SubjectUserName"] == "john"
    assert "JSON" in out


def _event_lines(out):
    """Строки-события в списочном режиме начинаются с даты (без tty — без ANSI)."""
    return [ln for ln in out.splitlines() if ln.strip().startswith("2026")]


# ---------- фильтр по времени (UTC) ----------
def test_after_filter_excludes_earlier(monkeypatch, capsys, security_evtx):
    # 1102 в 12:45 отсекается, остаются 6 событий в 12:57–12:58
    out = run(monkeypatch, capsys, security_evtx, "--after", "2026-05-11 12:50")
    assert len(_event_lines(out)) == 6


def test_before_filter_keeps_only_earlier(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--before", "2026-05-11 12:50")
    lines = _event_lines(out)
    assert len(lines) == 1
    assert "1102" in lines[0]


def test_after_before_window(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx,
              "--after", "2026-05-11 12:46", "--before", "2026-05-11 12:58")
    assert len(_event_lines(out)) == 5


# ---------- grep ----------
def test_grep_matches_raw_xml(monkeypatch, capsys, security_evtx):
    # только событие очистки лога (провайдер Microsoft-Windows-Eventlog)
    out = run(monkeypatch, capsys, security_evtx, "--grep", "eventlog")
    lines = _event_lines(out)
    assert len(lines) == 1
    assert "1102" in lines[0]


# ---------- сдвиг локального времени ----------
def test_tz_offset_in_output(monkeypatch, capsys, security_evtx):
    out0 = run(monkeypatch, capsys, security_evtx, "--eid", "1102", "--tz", "0")
    assert "2026-05-11 12:45:17" in out0
    out3 = run(monkeypatch, capsys, security_evtx, "--eid", "1102", "--tz", "3")
    assert "2026-05-11 15:45:17" in out3


# ---------- CSV-экспорт ----------
def test_csv_export(monkeypatch, capsys, tmp_path, security_evtx):
    out_file = tmp_path / "out.csv"
    run(monkeypatch, capsys, security_evtx, "--eid", "1102", "--csv", str(out_file))
    import csv as _csv

    with out_file.open(encoding="utf-8") as f:
        reader = _csv.DictReader(f)
        assert reader.fieldnames[0] == "_EventID"  # метаполя впереди
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["SubjectUserName"] == "john"
    assert rows[0]["_SourceFile"].endswith("security.evtx")


# ---------- несколько файлов ----------
def test_multifile_headers(monkeypatch, capsys, security_evtx, printservice_evtx):
    out = run(monkeypatch, capsys, security_evtx, printservice_evtx, "--summary")
    assert "security.evtx" in out
    assert "printservice-admin.evtx" in out


# ---------- устойчивость к битому вводу ----------
def test_bad_file_reported_not_crash(monkeypatch, capsys, tmp_path):
    junk = tmp_path / "broken.evtx"
    junk.write_bytes(b"this is not an evtx file")
    out = run(monkeypatch, capsys, str(junk), "--summary")
    assert "broken.evtx" in out  # сообщение об ошибке, без падения


def test_verify_bad_file_reported_not_crash(monkeypatch, capsys, tmp_path):
    junk = tmp_path / "broken.evtx"
    junk.write_bytes(b"not-evtx")
    out = run(monkeypatch, capsys, str(junk), "--verify")
    assert "broken.evtx" in out  # ошибка чтения сообщается, без падения


# ---------- единый таймлайн ----------
def test_timeline_merges_and_sorts(monkeypatch, capsys, security_evtx, printservice_evtx):
    out = run(monkeypatch, capsys, security_evtx, printservice_evtx, "--timeline")
    lines = _event_lines(out)
    assert len(lines) == 11  # 7 + 4 из обоих файлов
    assert all(".evtx]" in ln for ln in lines)  # колонка источника в каждой строке
    # самое раннее событие (printservice, 2026-05-06) — первым
    assert lines[0].startswith("2026-05-06")
    assert "printservice-admin.evtx" in lines[0]
    # строки отсортированы по времени
    stamps = [ln[:19] for ln in lines]
    assert stamps == sorted(stamps)


def test_timeline_merged_summary(monkeypatch, capsys, security_evtx, printservice_evtx):
    out = run(monkeypatch, capsys, security_evtx, printservice_evtx, "--timeline", "--summary")
    assert "Всего: 11 записей (2 файлов)" in out


def test_timeline_respects_limit(monkeypatch, capsys, security_evtx, printservice_evtx):
    out = run(monkeypatch, capsys, security_evtx, printservice_evtx, "--timeline", "--limit", "3")
    assert len(_event_lines(out)) == 3


def test_timeline_with_eid_filter(monkeypatch, capsys, security_evtx, printservice_evtx):
    # только 823 из printservice + 4624 из security, слиты по времени
    out = run(monkeypatch, capsys, security_evtx, printservice_evtx, "--timeline", "--eid", "823,4624")
    lines = _event_lines(out)
    assert len(lines) == 6  # 4x823 + 2x4624
    assert all("EID   823" in ln or "EID  4624" in ln for ln in lines)


# ---------- пресеты (проводка через CLI) ----------
def test_preset_process_tree_wiring(monkeypatch, capsys, security_evtx):
    # в Security нет EID 1 — проверяем, что --preset доходит до пресета
    out = run(monkeypatch, capsys, security_evtx, "--preset", "process-tree")
    assert "Нет событий Sysmon EID 1" in out


def test_preset_logon_analysis_wiring(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--preset", "logon-analysis")
    assert "2 успешных, 0 неуспешных" in out


def test_preset_network_wiring(monkeypatch, capsys, security_evtx):
    # в Security нет EID 3 — проверяем, что --preset доходит до пресета
    out = run(monkeypatch, capsys, security_evtx, "--preset", "network")
    assert "Нет событий Sysmon EID 3" in out


def test_preset_rdp_wiring(monkeypatch, capsys, security_evtx):
    # реальные 4624 LogonType=10 в фикстуре — должны попасть в вывод пресета
    out = run(monkeypatch, capsys, security_evtx, "--preset", "rdp")
    assert "вход (Security 4624)" in out
    assert "vm1-PC\\vm1" in out


def test_preset_invalid_rejected(monkeypatch, capsys, security_evtx):
    with pytest.raises(SystemExit):
        run(monkeypatch, capsys, security_evtx, "--preset", "nope")


# ---------- полный дамп ----------
def test_full_dump_output(monkeypatch, capsys, security_evtx):
    out = run(monkeypatch, capsys, security_evtx, "--eid", "1102", "--full")
    assert "EID 1102" in out
    assert "Provider: Microsoft-Windows-Eventlog" in out
    assert "Computer: vm1-PC" in out
    assert "SubjectUserName = john" in out
