"""evtxview — корректный просмотр и триаж Windows .evtx (читает все chunk'и)."""

from evtxview.cli import main
from evtxview.reader import read_records, verify_completeness
from evtxview.record import EventRecord, parse_record

__version__ = "0.1.0"
__all__ = ["main", "read_records", "verify_completeness", "EventRecord", "parse_record"]
