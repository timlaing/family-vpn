"""Regression checks for generated isolated hook environments."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sync_prek_deps", ROOT / "scripts/sync_prek_deps.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def test_nested_requirements_deduplicate_and_stop_cycles(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.lock"
    first.write_text("# dependencies\n-r second.lock\nFlask==3.1.3\n")
    second.write_text("--requirement first.txt\nFlask==3.1.3\npytest==9.1.1\n")
    assert sync.deduplicate(sync.read_requirements(first)) == ["Flask==3.1.3", "pytest==9.1.1"]


def test_stale_generated_block_is_detected_without_writing(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    original = "hooks:\n" + sync.BEGIN_MARKER + "\n" + sync.END_MARKER + "\n"
    config.write_text(original)
    requirements = tmp_path / "requirements.lock"
    requirements.write_text("pytest==9.1.1\n")
    monkeypatch.setattr(sync, "CONFIG_FILE", config)
    assert sync.update_config([requirements], check_only=True) == 1
    assert config.read_text() == original
    assert sync.update_config([requirements], check_only=False) == 0
    assert sync.update_config([requirements], check_only=True) == 0
    assert "pytest==9.1.1" in config.read_text()


def test_missing_markers_fail_without_overwriting(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("repos: []\n")
    monkeypatch.setattr(sync, "CONFIG_FILE", config)
    assert sync.update_config([], check_only=False) == 2
    assert config.read_text() == "repos: []\n"
