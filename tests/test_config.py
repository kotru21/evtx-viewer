"""Тесты загрузки и мержа конфига (TODO #5).

Изоляция от реального конфига машины (env var, ~/.config/...) обеспечена
autouse-фикстурой isolate_from_machine_config в conftest.py.
"""
import pytest

from evtxview.config import DEFAULT_CONFIG, load_config


def test_no_config_returns_defaults():
    cfg = load_config(None)
    assert cfg == DEFAULT_CONFIG


def test_explicit_path_missing_file_raises(tmp_path):
    missing = tmp_path / "nope.toml"
    with pytest.raises(SystemExit, match="Конфиг не найден"):
        load_config(str(missing))


def test_malformed_toml_raises_clear_error(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("not [valid", encoding="utf-8")
    with pytest.raises(SystemExit, match="некорректный TOML"):
        load_config(str(bad))


def test_hot_eids_override_replaces_default(tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[highlight]\nhot_eids = ["1102"]\n', encoding="utf-8")
    cfg = load_config(str(cfg_file))
    assert cfg.hot_eids == frozenset({"1102"})
    assert cfg.summary_fields == DEFAULT_CONFIG.summary_fields  # не тронуто


def test_summary_fields_override_replaces_default(tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[summary]\nfields = ["SubjectUserName"]\n', encoding="utf-8")
    cfg = load_config(str(cfg_file))
    assert cfg.summary_fields == ("SubjectUserName",)
    assert cfg.hot_eids == DEFAULT_CONFIG.hot_eids  # не тронуто


def test_both_sections_override(tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text(
        '[highlight]\nhot_eids = ["1", "2"]\n\n[summary]\nfields = ["A", "B"]\n',
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_file))
    assert cfg.hot_eids == frozenset({"1", "2"})
    assert cfg.summary_fields == ("A", "B")


def test_empty_toml_file_keeps_defaults(tmp_path):
    cfg_file = tmp_path / "empty.toml"
    cfg_file.write_text("", encoding="utf-8")
    cfg = load_config(str(cfg_file))
    assert cfg == DEFAULT_CONFIG


def test_hot_eids_wrong_type_raises(tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[highlight]\nhot_eids = "1102"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="должно быть списком строк"):
        load_config(str(cfg_file))


def test_hot_eids_non_string_items_raises(tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[highlight]\nhot_eids = [1102, 4624]\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="должно быть списком строк"):
        load_config(str(cfg_file))


def test_env_var_used_when_no_explicit_path(monkeypatch, tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[highlight]\nhot_eids = ["9999"]\n', encoding="utf-8")
    monkeypatch.setenv("EVTXVIEW_CONFIG", str(cfg_file))
    cfg = load_config(None)
    assert cfg.hot_eids == frozenset({"9999"})


def test_explicit_path_wins_over_env_var(monkeypatch, tmp_path):
    env_cfg = tmp_path / "env.toml"
    env_cfg.write_text('[highlight]\nhot_eids = ["1111"]\n', encoding="utf-8")
    explicit_cfg = tmp_path / "explicit.toml"
    explicit_cfg.write_text('[highlight]\nhot_eids = ["2222"]\n', encoding="utf-8")
    monkeypatch.setenv("EVTXVIEW_CONFIG", str(env_cfg))
    cfg = load_config(str(explicit_cfg))
    assert cfg.hot_eids == frozenset({"2222"})


# ---------- секция объявлена не таблицей (#22) ----------
def test_section_as_scalar_raises_clear_error(tmp_path):
    """`highlight = "x"` вместо `[highlight]` — раньше падало сырым
    TypeError при попытке проиндексировать строку как словарь."""
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('highlight = "hot_eids"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="должна быть таблицей TOML"):
        load_config(str(cfg_file))


def test_section_as_list_raises_clear_error(tmp_path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('summary = ["a", "b"]\n', encoding="utf-8")
    with pytest.raises(SystemExit, match="должна быть таблицей TOML"):
        load_config(str(cfg_file))


# ---------- неизвестные ключи/секции — предупреждение, не тишина (#23) ----------
def test_unknown_key_in_highlight_warns_and_keeps_default(tmp_path, capsys):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[highlight]\nhot_eid = ["1102"]\n', encoding="utf-8")  # опечатка: hot_eid
    cfg = load_config(str(cfg_file))
    assert cfg.hot_eids == DEFAULT_CONFIG.hot_eids  # оверрайд не сработал
    err = capsys.readouterr().err
    assert "highlight.hot_eid" in err
    assert "проигнорирован" in err


def test_unknown_top_level_section_warns(tmp_path, capsys):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[higlight]\nhot_eids = ["1102"]\n', encoding="utf-8")  # опечатка: higlight
    cfg = load_config(str(cfg_file))
    assert cfg == DEFAULT_CONFIG
    err = capsys.readouterr().err
    assert "config.higlight" in err


def test_known_config_produces_no_warnings(tmp_path, capsys):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[highlight]\nhot_eids = ["1102"]\n\n[summary]\nfields = ["Image"]\n',
                         encoding="utf-8")
    load_config(str(cfg_file))
    assert capsys.readouterr().err == ""
