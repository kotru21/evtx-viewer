"""Интеграционные тесты на реальных .evtx (золотые ожидания по известным записям)."""
from collections import Counter

from evtxview import cli


def test_read_records_security(security_evtx):
    recs, errs = cli.read_records(security_evtx)
    assert len(recs) == 7
    assert errs == 0


def test_verify_completeness_security(security_evtx):
    recs, _ = cli.read_records(security_evtx)
    v = cli.verify_completeness(security_evtx, len(recs))
    assert v is not None
    assert v["chunks"] >= 1
    assert v["expected"] == v["got"] == 7


def test_security_eid_distribution(security_evtx):
    recs, _ = cli.read_records(security_evtx)
    dist = Counter(cli.get_eid(x) for x in recs)
    assert dist == {"4624": 2, "4634": 2, "1102": 1, "4648": 1, "4672": 1}


def test_security_logclear_fields(security_evtx):
    """Событие 1102 (очистка журнала) должно нести SubjectUserName=john."""
    recs, _ = cli.read_records(security_evtx)
    clear = [x for x in recs if cli.get_eid(x) == "1102"]
    assert len(clear) == 1
    fields = cli.get_data_fields(clear[0])
    assert fields.get("SubjectUserName") == "john"


def test_verify_not_evtx(tmp_path):
    junk = tmp_path / "not.evtx"
    junk.write_bytes(b"NOT-AN-EVTX-FILE")
    assert cli.verify_completeness(str(junk), 0) is None


def test_printservice_userdata(printservice_evtx):
    recs, errs = cli.read_records(printservice_evtx)
    assert len(recs) == 4
    assert errs == 0
    # ветка UserData: у записей нет <EventData>, поля берутся из UserData
    fields = cli.get_data_fields(recs[0])
    assert fields.get("Module") == "spoolsv.exe"
    assert all(cli.get_eid(x) == "823" for x in recs)
