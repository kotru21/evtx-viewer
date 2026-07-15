"""Общие фикстуры для тестов evtxview.

Тестовые .evtx — из синтетического DFIR-образа (VM1-PC, ransomware-сценарий),
не содержат реальных персональных данных. Пути и известные значения записей
захардкожены как «золотые» ожидания.
"""
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def security_evtx() -> str:
    """7 записей Security.evtx: hot-EID (4624/4634/4648/4672) + очистка лога 1102."""
    return str(FIXTURES / "security.evtx")


@pytest.fixture
def printservice_evtx() -> str:
    """4 записи PrintService/Admin — формат UserData (без EventData)."""
    return str(FIXTURES / "printservice-admin.evtx")
