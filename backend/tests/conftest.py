# -*- coding: utf-8 -*-
"""pytest 共享夹具:把 SQLite 指到会话级临时库,并保证 backend 在 sys.path。"""
import pathlib
import sys
import tempfile
import shutil
import pytest

BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import db  # noqa: E402

_TMP = pathlib.Path(tempfile.mkdtemp(prefix="pcapcheck-test-"))
db.DB_PATH = _TMP / "pcapcheck-test.db"
db.init_db()

CAPTURES = BACKEND_DIR.parent / "tests" / "captures"


@pytest.fixture(scope="session", autouse=True)
def isolate_settings(tmp_path_factory):
    """Never read or rewrite a developer's real settings while running tests."""
    from app import settings
    previous = settings._SETTINGS_FILE
    settings._SETTINGS_FILE = tmp_path_factory.mktemp("settings") / "settings.json"
    try:
        yield
    finally:
        settings._SETTINGS_FILE = previous


def pytest_addoption(parser):
    parser.addoption("--external-captures", action="store_true", default=False,
                     help="Run tests requiring manually acquired external captures")


def pytest_collection_modifyitems(config, items):
    tshark_available = (shutil.which("tshark") is not None or any(
        pathlib.Path(path).is_file() for path in (
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe")))
    for item in items:
        if item.get_closest_marker("external_capture") and not config.getoption("--external-captures"):
            item.add_marker(pytest.mark.skip(reason="External captures are not distributed; enable --external-captures"))
        elif item.get_closest_marker("tshark") and not tshark_available:
            item.add_marker(pytest.mark.skip(reason="Install TShark to run packet decoding integration tests"))
