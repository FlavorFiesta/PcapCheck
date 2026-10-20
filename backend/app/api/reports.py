# -*- coding: utf-8 -*-
"""reports 路由:列表 / 详情 / 导出(md|html)。"""
from __future__ import annotations

import html
import json
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

from .. import analysis, db, llm
from ..rules.base import TIER_ZH
from ..settings import load_settings

router = APIRouter()


def _brief_text(rep: dict) -> str:
    """生成面向客户的单段简报;不替代规则明细和证据。"""
    if rep.get("analysis_mode") == "ai_direct" or rep.get("engine") == "ai-direct":
        return "本报告由 AI 直达分析生成：已跳过本地规则引擎和知识库关联，结论请结合原始报文进一步核验。"
    findings = rep.get("findings") or []
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except json.JSONDecodeError:
            findings = []
    if not isinstance(findings, list):
        findings = []

    capture_name = str(rep.get("capture_name") or "").lower()
    if not findings and "benign" in capture_name and "dns" in capture_name:
        return ("这是一份良性（健康）DNS 流量基线样本，未命中报文检查规则引擎的任何确诊 / 疑似 / 潜在规则，"
                "属于合成测试负样本，预期输出“无故障”。")
    if not findings:
        return "本次抓包未命中报文检查规则引擎的确诊 / 疑似 / 潜在规则，当前未发现规则定义范围内的异常。"

    counts = {
        "confirmed": sum(1 for f in findings if isinstance(f, dict) and f.get("tier") == "confirmed"),
        "suspect": sum(1 for f in findings if isinstance(f, dict) and f.get("tier") == "suspect"),
        "potential": sum(1 for f in findings if isinstance(f, dict) and f.get("tier") == "potential"),
    }
    labels = (("confirmed", "确诊故障"), ("suspect", "疑似问题"), ("potential", "潜在风险"))
    parts = [f"{label} {counts[key]} 项" for key, label in labels if counts[key]]
    return f"本次抓包共发现{'、'.join(parts)}，请结合证据帧和关联知识库进一步确认。"


def _load(report_id: str) -> dict:
    row = db.query_one("SELECT * FROM reports WHERE id=?", (report_id,))
    if row is None:
        raise HTTPException(404, f"report 不存在:{report_id}")
    rep = db.row_to_dict(row)
    cap = db.query_one("SELECT name,frame_count FROM captures WHERE id=?", (rep["capture_id"],))
    if cap:
        rep["capture_name"] = cap["name"]
        rep["capture_frame_count"] = cap["frame_count"]
    try:
        rep["findings"] = json.loads(rep.get("findings") or "[]")
    except json.JSONDecodeError:
        rep["findings"] = []
    try:
        rep["coverage"] = json.loads(rep.get("coverage") or "null")
    except json.JSONDecodeError:
        rep["coverage"] = None
    rep["brief"] = _brief_text(rep)
    return rep


@router.get("/reports")
def list_reports(capture_id: Optional[str] = Query(None)):
    base_sql = (
        "SELECT reports.*, captures.name AS capture_name, "
        "captures.frame_count AS capture_frame_count FROM reports "
        "LEFT JOIN captures ON captures.id=reports.capture_id"
    )
    if capture_id:
        rows = db.query(base_sql + " WHERE reports.capture_id=? ORDER BY reports.created_at DESC",
                        (capture_id,))
    else:
        rows = db.query(base_sql + " ORDER BY reports.created_at DESC")
    out = []
    for r in rows:
        rep = db.row_to_dict(r)
        try:
            rep["findings"] = json.loads(rep.get("findings") or "[]")
        except json.JSONDecodeError:
            rep["findings"] = []
        try:
            rep["coverage"] = json.loads(rep.get("coverage") or "null")
        except json.JSONDecodeError:
            rep["coverage"] = None
        rep["brief"] = _brief_text(rep)
        out.append(rep)
    return {"reports": out}


@router.get("/reports/{report_id}")
def report_detail(report_id: str):
    return _load(report_id)


@router.post("/reports/{report_id}/ai")
def report_ai(report_id: str):
    """按用户请求生成一次 AI 分析;规则报告只复述 findings,AI 直达报告重跑抓包摘要分析。"""
    rep = _load(report_id)
    settings = load_settings()
    if not llm.is_configured(settings):
        raise HTTPException(400, "AI 配置不完整:请到系统设置启用并填写 Base URL、模型")
    if rep.get("analysis_mode") == "ai_direct" or rep.get("engine") == "ai-direct":
        cap_row = db.query_one("SELECT * FROM captures WHERE id=?", (rep["capture_id"],))
        if cap_row is None:
            raise HTTPException(404, f"capture 不存在:{rep['capture_id']}")
        text = llm.generate_direct_analysis(
            db.row_to_dict(cap_row), analysis._load_frames(rep["capture_id"]), settings)
    else:
        text = llm.generate_narrative(rep.get("findings") or [], rep.get("summary") or "", settings)
    if not text:
        raise HTTPException(502, "AI 未返回有效分析,请检查云端 API 配置或网络")
    db.execute("UPDATE reports SET narrative=? WHERE id=?", (text, report_id))
    return _load(report_id)


@router.delete("/reports/{report_id}")
def delete_report(report_id: str):
    """删除单份历史报告,不删除对应抓包文件。"""
    _load(report_id)
    db.execute("DELETE FROM reports WHERE id=?", (report_id,))
    return {"deleted": report_id}


# ---------------------------------------------------------------- 导出
def _coverage_lines_md(coverage) -> list:
    if not coverage:
        return []
    if coverage.get("mode") == "ai_direct":
        return [f"- 分析方式:AI 直达分析(跳过本地规则引擎和知识库关联),共使用 {coverage.get('frame_count', 0)} 帧摘要。"]
    n, m, k = coverage.get("expert_errors", 0), coverage.get("expert_warns", 0), coverage.get("unconsumed", 0)
    lines = [f"- 覆盖范围:专家层 error/warn 帧共 {n + m}"
             f"(error {n} / warn {m}),其中 {k} 帧超出 V1 规则范围未判定。"]
    if coverage.get("unconsumed_frames"):
        lines.append(f"  - 未判定帧:{', '.join(map(str, coverage['unconsumed_frames'][:30]))}"
                     + ("…" if len(coverage["unconsumed_frames"]) > 30 else ""))
    if coverage.get("note"):
        lines.append(f"  - 口径:{coverage['note']}")
    return lines


def _report_markdown(rep: dict, capture: Optional[dict]) -> str:
    lines = [
        f"# 报文检查诊断报告:{rep['id']}",
        "",
        f"- 生成时间:{_fmt_ts(rep['created_at'])}",
        f"- 抓包文件:{capture['name'] if capture else rep['capture_id']}"
        f"({capture['frame_count']} 帧)" if capture else "",
        f"- 分析方式:{'AI 直达分析(跳过本地规则和知识库)' if rep.get('analysis_mode') == 'ai_direct' else '本地规则引擎'}",
        f"- 简报:{rep.get('brief') or _brief_text(rep)}",
        f"- 摘要:{rep.get('summary') or ''}",
        "",
    ]
    lines += _coverage_lines_md(rep.get("coverage"))
    lines.append("")
    for f in rep.get("findings") or []:
        tier_zh = TIER_ZH.get(f.get("tier"), f.get("tier"))
        lines.append(f"## [{tier_zh}] {f.get('title')}")
        lines.append("")
        lines.append(f"- 规则:`{f.get('rule_id')}`(档位:{f.get('tier')})")
        ev = f.get("evidence_frames") or []
        lines.append(f"- 证据帧(共 {len(ev)}):{', '.join(map(str, ev[:20]))}"
                     + ("…" if len(ev) > 20 else ""))
        stats = f.get("stats") or {}
        if stats:
            lines.append("- 关键统计:")
            for k, v in stats.items():
                lines.append(f"  - {k}: {v}")
        if f.get("suggestion"):
            lines.append(f"- 处置建议:{f['suggestion']}")
        if f.get("kb_ids"):
            lines.append(f"- 关联知识库:{', '.join(f['kb_ids'])}")
        lines.append("")
    if rep.get("narrative"):
        lines += ["## AI 叙述(仅复述,不构成结论)", "", rep["narrative"], ""]
    lines.append("> " + ("本报告由 AI 直达分析生成,未运行本地规则引擎或知识库,请结合原始报文核验。"
                          if rep.get("analysis_mode") == "ai_direct"
                          else "本报告由确定性规则引擎生成,证据均可跳转核对;AI 叙述仅为复述。"))
    return "\n".join(lines)


def _coverage_lines_html(coverage) -> list:
    if not coverage:
        return []
    if coverage.get("mode") == "ai_direct":
        return [f"<p><b>分析方式:</b>AI 直达分析(跳过本地规则引擎和知识库关联),共使用 {coverage.get('frame_count', 0)} 帧摘要。</p>"]
    e = html.escape
    n, m, k = coverage.get("expert_errors", 0), coverage.get("expert_warns", 0), coverage.get("unconsumed", 0)
    parts = [f"<p><b>覆盖范围:</b>专家层 error/warn 帧共 {n + m}"
             f"(error {n} / warn {m}),其中 {k} 帧超出 V1 规则范围未判定。"]
    if coverage.get("unconsumed_frames"):
        parts.append(f"未判定帧:{e(', '.join(map(str, coverage['unconsumed_frames'][:30])))}"
                     + ("…" if len(coverage["unconsumed_frames"]) > 30 else "") + "。")
    if coverage.get("note"):
        parts.append(f"<small>口径:{e(str(coverage['note']))}</small>")
    parts.append("</p>")
    return ["".join(parts)]


def _report_html(rep: dict, capture: Optional[dict]) -> str:
    e = html.escape
    parts = [
        "<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>",
        f"<title>报文检查诊断报告 {e(str(rep['id']))}</title>",
        "<style>body{font-family:'Microsoft YaHei',sans-serif;margin:32px;max-width:900px}",
        ".tier-confirmed{color:#b00020}.tier-suspect{color:#b26a00}.tier-potential{color:#00695c}",
        "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px}",
        "</style></head><body>",
        f"<h1>报文检查诊断报告:{e(str(rep['id']))}</h1>",
        f"<p>生成时间:{e(_fmt_ts(rep['created_at']))} | "
        f"抓包文件:{e(str(capture['name'] if capture else rep['capture_id']))}</p>",
        f"<p><b>分析方式:</b>{e('AI 直达分析(跳过本地规则和知识库)' if rep.get('analysis_mode') == 'ai_direct' else '本地规则引擎')}</p>",
        f"<p><b>简报:</b>{e(rep.get('brief') or _brief_text(rep))}</p>",
        f"<p><b>摘要:</b>{e(rep.get('summary') or '')}</p>",
    ]
    parts += _coverage_lines_html(rep.get("coverage"))
    for f in rep.get("findings") or []:
        tier = f.get("tier")
        parts.append(
            f"<h2 class='tier-{e(str(tier))}'>[{e(TIER_ZH.get(tier, tier or ''))}] "
            f"{e(str(f.get('title')))}</h2>")
        ev = f.get("evidence_frames") or []
        parts.append(f"<p>规则:<code>{e(str(f.get('rule_id')))}</code> | "
                     f"证据帧(共 {len(ev)}):{e(', '.join(map(str, ev[:20])))}"
                     + ("…" if len(ev) > 20 else "") + "</p>")
        stats = f.get("stats") or {}
        if stats:
            rows = "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>"
                           for k, v in stats.items())
            parts.append(f"<table>{rows}</table>")
        if f.get("suggestion"):
            parts.append(f"<p><b>处置建议:</b>{e(str(f['suggestion']))}</p>")
        if f.get("kb_ids"):
            parts.append(f"<p><b>关联知识库:</b>{e(', '.join(f['kb_ids']))}</p>")
    if rep.get("narrative"):
        parts.append(f"<h2>AI 叙述(仅复述,不构成结论)</h2><p>{e(rep['narrative'])}</p>")
    footer = ("本报告由 AI 直达分析生成,未运行本地规则引擎或知识库,请结合原始报文核验。"
              if rep.get("analysis_mode") == "ai_direct"
              else "本报告由确定性规则引擎生成,证据均可跳转核对;AI 叙述仅为复述。")
    parts.append(f"<hr><p>{e(footer)}</p>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _fmt_ts(ts) -> str:
    import datetime
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(ts)


@router.get("/reports/{report_id}/export")
def export_report(report_id: str, format: str = Query("md")):
    rep = _load(report_id)
    capture_row = db.query_one("SELECT * FROM captures WHERE id=?", (rep["capture_id"],))
    capture = db.row_to_dict(capture_row) if capture_row else None
    fmt = (format or "md").lower()
    fname_base = f"pcapcheck-report-{report_id}"
    if fmt == "html":
        content = _report_html(rep, capture)
        return HTMLResponse(content=content,
                            headers={"Content-Disposition":
                                     f'attachment; filename="{fname_base}.html"'})
    if fmt == "md":
        content = _report_markdown(rep, capture)
        return PlainTextResponse(content=content,
                                 headers={"Content-Disposition":
                                          f'attachment; filename="{fname_base}.md"'})
    raise HTTPException(400, "format 仅支持 md|html")
