# -*- coding: utf-8 -*-
"""LLM 网关只负责叙述、脱敏和协议适配,不参与规则判断。"""
from app import llm


def test_mask_text_uses_stable_placeholders():
    out = llm.mask_text("访问 10.0.0.1 和 10.0.0.1 的 api.example.com", True)
    assert out == "访问 <IP-1> 和 <IP-1> 的 <HOST-2>"


def test_generate_narrative_masks_before_chat(monkeypatch):
    seen = {}

    def fake_chat(base_url, api_key, model, messages):
        seen["url"] = base_url
        seen["user"] = messages[-1]["content"]
        return "已复述规则结果。"

    monkeypatch.setattr(llm, "_chat", fake_chat)
    text = llm.generate_narrative(
        [{"tier": "confirmed", "rule_id": "R02_SERVER_RST", "title": "10.0.0.1 发生 RST",
          "evidence_frames": [7], "stats": {"peer": "api.example.com"}}],
        "10.0.0.1 访问 api.example.com",
        {"llm": {"enabled": True, "base_url": "https://example.test/v1", "model": "demo"},
         "masking": {"enabled": True}},
    )
    assert text == "已复述规则结果。"
    assert "10.0.0.1" not in seen["user"]
    assert "api.example.com" not in seen["user"]
    assert "<IP-1>" in seen["user"]
    assert "<HOST-2>" in seen["user"] or "<HOST-1>" in seen["user"]


def test_unconfigured_llm_does_not_call_network(monkeypatch):
    called = False

    def fail(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("未配置 LLM 不应发网络请求")

    monkeypatch.setattr(llm, "_chat", fail)
    assert llm.generate_narrative([{"rule_id": "R01"}], "summary", {"llm": {"enabled": False}}) == ""
    assert called is False


def test_generate_direct_analysis_masks_and_sends_frame_summary(monkeypatch):
    seen = {}

    def fake_chat(base_url, api_key, model, messages):
        seen["user"] = messages[-1]["content"]
        return "AI 直达分析：帧 7 出现异常，建议复核。"

    monkeypatch.setattr(llm, "_chat", fake_chat)
    out = llm.generate_direct_analysis(
        {"name": "sample.pcap", "frame_count": 1, "protocols": '["TCP"]'},
        [{"no": 7, "src": "10.0.0.1", "dst": "api.example.com", "proto": "TCP",
          "info": "RST from 10.0.0.1", "analysis": [], "expert": []}],
        {"llm": {"enabled": True, "base_url": "https://example.test/v1", "model": "demo"},
         "masking": {"enabled": True}},
    )
    assert out.startswith("AI 直达分析")
    assert "10.0.0.1" not in seen["user"]
    assert "api.example.com" not in seen["user"]
    assert '"no":7' in seen["user"]


def test_connection_uses_form_settings_without_persisting(monkeypatch):
    seen = {}

    def fake_chat(base_url, api_key, model, messages):
        seen.update(base_url=base_url, api_key=api_key, model=model, messages=messages)
        return "连接成功。"

    monkeypatch.setattr(llm, "_chat", fake_chat)
    assert llm.test_connection({"llm": {"enabled": True, "base_url": "https://x/v1",
                                         "api_key": "secret", "model": "m"}}) == "连接成功。"
    assert seen["api_key"] == "secret"
    assert seen["messages"][-1]["content"] == "请回复连接成功。"
