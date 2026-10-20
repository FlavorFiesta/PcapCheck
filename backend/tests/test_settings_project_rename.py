import json

from app import settings


def test_default_kb_path_recovers_after_project_directory_rename(tmp_path, monkeypatch):
    new_kb = tmp_path / "PcapCheck" / "docs" / "kb"
    new_kb.mkdir(parents=True)
    config = tmp_path / "settings.json"
    config.write_text(json.dumps({"kb_dir": str(tmp_path / "PcapDoctor" / "docs" / "kb")}), encoding="utf-8")
    monkeypatch.setattr(settings, "_SETTINGS_FILE", config)
    monkeypatch.setattr(settings, "DEFAULT_KB_DIR", new_kb)
    assert settings.load_settings()["kb_dir"] == str(new_kb)
