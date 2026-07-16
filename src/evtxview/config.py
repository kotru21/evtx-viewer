"""Конфигурация: наборы EID для подсветки и приоритет полей однострочной сводки.

Встроенные значения заданы под Sysmon/Security. Пользователь может
переопределить их под других провайдеров через TOML-конфиг, не трогая код —
см. load_config().
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Optional, Tuple

try:
    import tomllib  # stdlib с Python 3.11
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

# EventID, помечаемые как security-relevant (подсветка + метка в сводке)
DEFAULT_HOT_EIDS = frozenset({
    '1102', '104', '4624', '4625', '4634', '4648', '4672', '4720', '4732', '4728',
    '7045', '1149', '21', '22', '1', '3', '10', '11', '13',
})

# Поля для однострочной сводки события, в порядке приоритета показа
DEFAULT_SUMMARY_FIELDS = (
    'Image', 'TargetImage', 'SourceImage', 'CommandLine', 'User',
    'SubjectUserName', 'TargetUserName', 'ParentImage',
    'DestinationIp', 'DestinationPort', 'SourceIp', 'SourcePort', 'Initiated',
    'TargetFilename', 'TargetObject', 'IpAddress', 'LogonType', 'ServiceName',
)


@dataclass(frozen=True)
class Config:
    hot_eids: FrozenSet[str]
    summary_fields: Tuple[str, ...]


DEFAULT_CONFIG = Config(hot_eids=DEFAULT_HOT_EIDS, summary_fields=DEFAULT_SUMMARY_FIELDS)


def _default_config_path() -> Path:
    return Path.home() / '.config' / 'evtxview' / 'config.toml'


def _validate_str_list(value, key, path):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        sys.exit(f"{path}: поле '{key}' должно быть списком строк")
    return value


def load_config(explicit_path: Optional[str] = None) -> Config:
    """Загружает конфиг и мержит его поверх встроенных дефолтов.

    Порядок поиска: явный `explicit_path` (флаг --config) → переменная
    окружения EVTXVIEW_CONFIG → ~/.config/evtxview/config.toml. Если ни один
    путь не указан явно и файл по умолчанию не существует — тихо используются
    дефолты (это ожидаемый случай для большинства запусков). Если путь указан
    явно (--config / EVTXVIEW_CONFIG), но файла нет или TOML битый — ошибка,
    а не молчаливый откат на дефолты.

    В самом TOML каждый ключ, если присутствует, ПОЛНОСТЬЮ заменяет
    соответствующий дефолт (а не дополняет его):

        [highlight]
        hot_eids = ["1102", "4624", "4625"]

        [summary]
        fields = ["Image", "CommandLine", "User"]
    """
    chosen = explicit_path or os.environ.get('EVTXVIEW_CONFIG')
    is_explicit = bool(chosen)
    path = Path(chosen) if chosen else _default_config_path()

    if not path.is_file():
        if is_explicit:
            sys.exit(f"Конфиг не найден: {path}")
        return DEFAULT_CONFIG

    try:
        with open(path, 'rb') as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"{path}: некорректный TOML — {e}")

    hot_eids = DEFAULT_CONFIG.hot_eids
    summary_fields = DEFAULT_CONFIG.summary_fields

    highlight = data.get('highlight', {})
    if 'hot_eids' in highlight:
        hot_eids = frozenset(_validate_str_list(highlight['hot_eids'], 'highlight.hot_eids', path))

    summary = data.get('summary', {})
    if 'fields' in summary:
        summary_fields = tuple(_validate_str_list(summary['fields'], 'summary.fields', path))

    return Config(hot_eids=hot_eids, summary_fields=summary_fields)
