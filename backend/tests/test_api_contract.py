# -*- coding: utf-8 -*-
"""客户主流程的 API 契约回归。"""
import pytest
from fastapi import HTTPException

from app.api.reports import _brief_text, _report_html, delete_report
from app.api.settings_api import SettingsBody, kb_article, test_llm as api_test_llm


def test_kb_single_article_returns_full_text():
    article = kb_article("retrans-trend")
    assert article["id"] == "retrans-trend"
    assert article["content"]
    assert "rule_ids" in article


def test_kb_single_article_missing_is_404():
    with pytest.raises(HTTPException) as exc:
        kb_article("does-not-exist")
    assert exc.value.status_code == 404


def test_llm_test_rejects_incomplete_configuration():
    with pytest.raises(HTTPException) as exc:
        api_test_llm(SettingsBody(llm={"enabled": False}))
    assert exc.value.status_code == 400


def test_benign_dns_brief_is_customer_facing_and_rule_grounded():
    brief = _brief_text({"capture_name": "syn-benign-dns.pcap", "findings": []})
    assert brief == (
        "这是一份良性（健康）DNS 流量基线样本，未命中报文检查规则引擎的任何确诊 / 疑似 / 潜在规则，"
        "属于合成测试负样本，预期输出“无故障”。"
    )


def test_ai_direct_brief_is_explicitly_marked():
    brief = _brief_text({"analysis_mode": "ai_direct", "findings": []})
    assert "AI 直达分析" in brief
    assert "跳过本地规则引擎和知识库" in brief


def test_delete_missing_report_is_404():
    with pytest.raises(HTTPException) as exc:
        delete_report("does-not-exist")
    assert exc.value.status_code == 404


def test_html_export_renders_coverage_and_escapes_text():
    content = _report_html(
        {
            "id": "report-1",
            "created_at": 0,
            "capture_id": "capture-1",
            "brief": "brief",
            "summary": "summary",
            "coverage": {
                "expert_errors": 0,
                "expert_warns": 1,
                "unconsumed": 1,
                "unconsumed_frames": [7],
                "note": "<coverage note>",
            },
            "findings": [],
        },
        {"name": "sample.pcap", "frame_count": 7},
    )
    assert "未判定帧:7" in content
    assert "&lt;coverage note&gt;" in content
