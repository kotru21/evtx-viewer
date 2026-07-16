"""Общие фикстуры для тестов evtxview.

Тестовые .evtx — из синтетического DFIR-образа (VM1-PC, ransomware-сценарий),
не содержат реальных персональных данных. Пути и известные значения записей
захардкожены как «золотые» ожидания.
"""
from pathlib import Path

import pytest

import evtxview.config as config_mod

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolate_from_machine_config(monkeypatch, tmp_path):
    """Тесты не должны зависеть от реального конфига машины, на которой они
    запускаются: ни от $EVTXVIEW_CONFIG в окружении разработчика/CI, ни от
    ~/.config/evtxview/config.toml, если он там случайно есть."""
    monkeypatch.delenv("EVTXVIEW_CONFIG", raising=False)
    monkeypatch.setattr(config_mod, "_default_config_path", lambda: tmp_path / "unused-config.toml")


@pytest.fixture
def security_evtx() -> str:
    """7 записей Security.evtx: hot-EID (4624/4634/4648/4672) + очистка лога 1102."""
    return str(FIXTURES / "security.evtx")


@pytest.fixture
def printservice_evtx() -> str:
    """4 записи PrintService/Admin — формат UserData (без EventData)."""
    return str(FIXTURES / "printservice-admin.evtx")


@pytest.fixture
def empty_evtx() -> str:
    """0 записей: один предвыделенный пустой chunk (sentinel-заголовок)."""
    return str(FIXTURES / "empty.evtx")
