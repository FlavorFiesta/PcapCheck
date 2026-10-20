# -*- coding: utf-8 -*-
"""Regression tests for the September desktop/backend review findings."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from app import analysis, llm, main as backend_main  # noqa: E402
from app.api import reports  # noqa: E402
from app.live import LiveManager  # noqa: E402
from desktop_gui import main as gui  # noqa: E402


class ImmediateThread:
    def __init__(self, target, args=(), **_kwargs):
        self.target = target
        self.args = args

    def start(self):
        self.target(*self.args)


@pytest.mark.parametrize("hostname", [
    "api.example.ai",
    "db.example.co.uk",
    "service.example.cloud",
    "API.EXAMPLE.COM",
])
def test_mask_text_masks_modern_and_multilevel_domains(hostname):
    assert hostname not in llm.mask_text(f"peer={hostname}", True)


def test_deferred_settings_error_keeps_original_message(monkeypatch):
    callbacks = []
    message = Mock()
    owner = SimpleNamespace(after=lambda _delay, callback: callbacks.append(callback),
                            settings_message=message)
    monkeypatch.setattr(gui.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(gui, "api_request", lambda *_args, **_kwargs: (_ for _ in ()).throw(gui.ApiError("offline")))

    gui.DesktopApp.load_settings_form(owner)
    callbacks.pop()()

    assert "offline" in message.configure.call_args.kwargs["text"]


def test_stale_report_response_is_ignored_after_capture_switch(monkeypatch):
    callbacks = []
    rendered = []
    combo = Mock()
    combo.current.return_value = 0
    owner = SimpleNamespace(
        after=lambda _delay, callback: callbacks.append(callback),
        report_combo=combo,
        report_records=[{"id": "report-a", "capture_id": "capture-a"}],
        capture={"id": "capture-a"},
        render_report=lambda capture, report: rendered.append((capture, report)),
    )
    monkeypatch.setattr(gui.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(gui, "api_request", lambda *_args, **_kwargs: {
        "id": "report-a", "capture_id": "capture-a", "narrative": "done"
    })

    gui.DesktopApp._on_report_selected(owner)
    owner.capture = {"id": "capture-b"}
    callbacks.pop()()

    assert rendered == []


def test_dropped_capture_path_accepts_one_supported_file():
    event_data = r"{C:\captures\office trace.pcapng}"
    assert gui.parse_drop_files(event_data) == [Path(r"C:\captures\office trace.pcapng")]
    assert gui.is_supported_capture(Path(r"C:\captures\office trace.pcapng"))
    assert not gui.is_supported_capture(Path(r"C:\captures\notes.txt"))


def test_completed_import_empty_state_is_not_labeled_diagnosing():
    assert gui.empty_report_title("导入完成，请选择“开始诊断”或“AI直达分析”。") == "待诊断"
    assert gui.empty_report_title("正在生成诊断报告…") == "诊断中"


def test_rule_analysis_uses_long_running_request_timeout(monkeypatch):
    calls = []
    capture = {"id": "capture-a", "name": "a.pcap", "frame_count": 1}
    owner = SimpleNamespace(
        capture=capture,
        report_capture_var=SimpleNamespace(get=lambda: "a"),
        _capture_by_label=lambda _label: capture,
        busy=False,
        _set_busy=lambda _busy: None,
        _render_empty_report=lambda *_args: None,
        root_status=lambda *_args: None,
        after=lambda _delay, callback, *args: callback(*args),
        render_report=lambda *_args: None,
        _load_reports=lambda *_args: None,
        refresh_captures=lambda: None,
    )

    def request(path, method="GET", body=None, timeout=15):
        calls.append((path, method, timeout))
        if path.endswith("/analyze"):
            return {"report_id": "report-a"}
        return {"id": "report-a", "capture_id": "capture-a", "narrative": "done"}

    monkeypatch.setattr(gui.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(gui, "api_request", request)
    gui.DesktopApp.analyze_selected(owner)

    assert calls[0][2] >= 300


def test_rule_report_refreshes_when_ai_narrative_arrives(monkeypatch):
    responses = iter([
        {"id": "report-a", "capture_id": "capture-a", "narrative": ""},
        {"id": "report-a", "capture_id": "capture-a", "narrative": "AI summary"},
    ])
    rendered = []
    owner = SimpleNamespace(
        capture={"id": "capture-a"},
        after=lambda _delay, callback, *args: callback(*args),
        render_report=lambda capture, report: rendered.append((capture, report)),
    )
    monkeypatch.setattr(gui.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(gui, "api_request", lambda *_args, **_kwargs: next(responses))

    gui.DesktopApp._poll_report_narrative(owner, "report-a", {"id": "capture-a"}, attempts=2)

    assert rendered[-1][1]["narrative"] == "AI summary"


def test_ai_sample_keeps_first_160_and_last_40_frames(monkeypatch):
    rows = [{"no": number, "ts": number, "src": "a", "dst": "b", "sport": 1,
             "dport": 2, "proto": "TCP", "length": 60, "info": "", "stream": 0,
             "analysis": "[]", "expert": "[]"} for number in range(1, 251)]
    monkeypatch.setattr(analysis.db, "query", lambda *_args, **_kwargs: rows)

    sample = analysis._load_ai_sample("capture-a", 250)

    assert len(sample) == 200
    assert [frame["no"] for frame in sample[:2]] == [1, 2]
    assert [frame["no"] for frame in sample[-2:]] == [249, 250]
    assert 161 not in {frame["no"] for frame in sample}


def test_report_listing_uses_one_join_query(monkeypatch):
    calls = []
    row = {
        "id": "report-a", "capture_id": "capture-a", "created_at": 1.0,
        "engine": "rules-v1", "analysis_mode": "rules", "findings": "[]",
        "summary": "ok", "narrative": "", "masked": 0, "coverage": "null",
        "capture_name": "a.pcap", "capture_frame_count": 3,
    }

    def query(sql, params=()):
        calls.append((sql, params))
        return [row]

    monkeypatch.setattr(reports.db, "query", query)
    monkeypatch.setattr(reports.db, "query_one",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("N+1 query")))

    result = reports.list_reports(None)

    assert len(calls) == 1
    assert " JOIN " in calls[0][0].upper()
    assert result["reports"][0]["capture_name"] == "a.pcap"


def test_live_status_reuses_interface_cache(monkeypatch):
    manager = LiveManager()
    calls = []
    monkeypatch.setattr("app.live.tshark_service.resolve_tshark", lambda _path=None: "tshark")
    monkeypatch.setattr("app.live.tshark_service.list_interfaces",
                        lambda _tshark: calls.append(1) or [{"idx": 1, "name": "Ethernet"}])

    assert manager.status()["ifaces"]
    assert manager.status()["ifaces"]
    assert len(calls) == 1


def test_backend_shutdown_stops_live_capture(monkeypatch):
    stopped = []
    monkeypatch.setattr(backend_main.MANAGER, "stop", lambda: stopped.append(True) or {"stopped": True})

    backend_main._shutdown()

    assert stopped == [True]
