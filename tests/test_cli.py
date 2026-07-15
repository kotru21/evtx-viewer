"""End-to-end тесты CLI через main() (argparse + вывод)."""
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
