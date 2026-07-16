"""Тесты загрузки и мержа конфига (TODO #5)."""
import pytest

import evtxview.config as config_mod
from evtxview.config import DEFAULT_CONFIG, load_config


def test_no_config_returns_defaults(monkeypatch, tmp_path):
    # путь по умолчанию указывает в пустой каталог — файла там нет
    monkeypatch.setattr(config_mod, "_default_config_path", lambda: tmp_path / "config.toml")
    monkeypatch.delenv("EVTXVIEW_CONFIG", raising=False)
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
