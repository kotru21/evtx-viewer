"""Чтение .evtx и проверка полноты по заголовкам chunk'ов."""

import struct

try:
    from evtx import PyEvtxParser
except ImportError:
    import sys
    sys.exit("Нужен rust-based парсер evtx:  pip install evtx")

EMPTY = 0xFFFFFFFFFFFFFFFF  # sentinel в заголовке предвыделенного пустого chunk'а

# Верхняя граница правдоподобного диапазона EventRecordID в одном файле.
# Реальные .evtx на многие гигабайты не превышают десятков миллионов записей;
# значение на порядки выше — признак повреждённого (или сфабрикованного)
# заголовка chunk'а, а не легитимного файла. Без этой проверки
# set(range(id_lo, id_hi + 1)) на битом заголовке может попытаться
# материализовать диапазон в ~10**19 элементов и уронить процесс по памяти.
MAX_PLAUSIBLE_ID_RANGE = 50_000_000


def read_records(path):
    """Читает все записи, не падая на битых chunk'ах.
    Возвращает (список XML-строк, число chunk-ошибок)."""
    recs, errs = [], 0
    it = PyEvtxParser(path).records()
    while True:
        try:
            recs.append(next(it)['data'])
        except StopIteration:
            break
        except RuntimeError:
            errs += 1
    return recs, errs


def verify_completeness(path, seen_ids):
    """Сверяет полноту чтения по заголовкам chunk'ов.

    Заголовок chunk'а (`ElfChnk\\x00`, шаг 0x10000) несёт две пары значений:
      * 0x08/0x10 — номера записей (последовательность 1..N) → ожидаемый счётчик;
      * 0x18/0x20 — сами EventRecordID (то, что в XML) → ожидаемый диапазон.

    `seen_ids` — фактически прочитанные EventRecordID. Помимо сверки счётчиков
    ищем ПРОПУСКИ внутри объявленного диапазона: это ловит потерю записей даже
    когда счётчик случайно совпал.
    """
    data = open(path, 'rb').read()
    if data[0:8] != b'ElfFile\x00':
        return None
    off, expected, chunks = 0x1000, 0, 0
    id_lo, id_hi = None, None
    while off + 0x28 < len(data) and data[off:off + 8] == b'ElfChnk\x00':
        num_first = struct.unpack('<Q', data[off + 0x08:off + 0x10])[0]
        num_last = struct.unpack('<Q', data[off + 0x10:off + 0x18])[0]
        rec_first = struct.unpack('<Q', data[off + 0x18:off + 0x20])[0]
        rec_last = struct.unpack('<Q', data[off + 0x20:off + 0x28])[0]
        chunks += 1
        off += 0x10000
        if num_last != EMPTY and num_first != EMPTY and num_last >= num_first:
            expected += num_last - num_first + 1
        if rec_last != EMPTY and rec_first != EMPTY and rec_last >= rec_first:
            id_lo = rec_first if id_lo is None else min(id_lo, rec_first)
            id_hi = rec_last if id_hi is None else max(id_hi, rec_last)

    seen = {i for i in seen_ids if i is not None}
    got = len(seen)
    missing = []
    range_unreliable = False
    if id_lo is not None and id_hi is not None:
        if id_hi - id_lo + 1 > MAX_PLAUSIBLE_ID_RANGE:
            # заголовок явно повреждён — не пытаемся перечислить пропуски,
            # но и не выдаём ложный OK: диапазону из такого заголовка нельзя доверять
            range_unreliable = True
        else:
            missing = sorted(set(range(id_lo, id_hi + 1)) - seen)
    complete = (got == expected) and not missing and not range_unreliable
    return {
        'chunks': chunks, 'expected': expected, 'got': got,
        'id_lo': id_lo, 'id_hi': id_hi, 'missing': missing, 'complete': complete,
        'range_unreliable': range_unreliable,
    }
