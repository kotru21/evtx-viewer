"""Интеграционные тесты на реальных .evtx (золотые ожидания по известным записям)."""
from collections import Counter

from evtxview.reader import read_records, verify_completeness
from evtxview.record import get_data_fields, get_eid, get_record_id


def test_read_records_security(security_evtx):
    recs, errs = read_records(security_evtx)
    assert len(recs) == 7
    assert errs == 0


def test_verify_completeness_security(security_evtx):
    recs, _ = read_records(security_evtx)
    ids = [get_record_id(x) for x in recs]
    v = verify_completeness(security_evtx, ids)
    assert v is not None
    assert v["chunks"] >= 1
    assert v["expected"] == v["got"] == 7
    assert v["missing"] == []
    assert v["complete"] is True


def test_verify_detects_missing_ids(security_evtx):
    """Если из прочитанного выпала запись — verify обязан заметить пропуск."""
    recs, _ = read_records(security_evtx)
    ids = [get_record_id(x) for x in recs]
    dropped = ids[len(ids) // 2]
    truncated = [i for i in ids if i != dropped]
    v = verify_completeness(security_evtx, truncated)
    assert v["complete"] is False
    assert dropped in v["missing"]
    assert v["got"] == 6


def test_security_eid_distribution(security_evtx):
    recs, _ = read_records(security_evtx)
    dist = Counter(get_eid(x) for x in recs)
    assert dist == {"4624": 2, "4634": 2, "1102": 1, "4648": 1, "4672": 1}


def test_security_logclear_fields(security_evtx):
    """Событие 1102 (очистка журнала) должно нести SubjectUserName=john."""
    recs, _ = read_records(security_evtx)
    clear = [x for x in recs if get_eid(x) == "1102"]
    assert len(clear) == 1
    fields = get_data_fields(clear[0])
    assert fields.get("SubjectUserName") == "john"


def test_verify_empty_file_is_complete(empty_evtx):
    """Пустой файл (предвыделенный chunk с sentinel-заголовком) — это OK, не обрезка."""
    recs, errs = read_records(empty_evtx)
    assert recs == [] and errs == 0
    v = verify_completeness(empty_evtx, [])
    assert v["expected"] == 0
    assert v["got"] == 0
    assert v["missing"] == []
    assert v["complete"] is True
    assert v["id_lo"] is None and v["id_hi"] is None


def test_verify_not_evtx(tmp_path):
    junk = tmp_path / "not.evtx"
    junk.write_bytes(b"NOT-AN-EVTX-FILE")
    assert verify_completeness(str(junk), 0) is None


def test_printservice_userdata(printservice_evtx):
    recs, errs = read_records(printservice_evtx)
    assert len(recs) == 4
    assert errs == 0
    # ветка UserData: у записей нет <EventData>, поля берутся из UserData
    fields = get_data_fields(recs[0])
    assert fields.get("Module") == "spoolsv.exe"
    assert all(get_eid(x) == "823" for x in recs)
