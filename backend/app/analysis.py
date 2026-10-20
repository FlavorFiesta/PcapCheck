# -*- coding: utf-8 -*-
"""一键诊断管线:读帧 -> 跑规则 -> 匹配知识库 -> 生成报告入库(+可选 LLM 叙述)。

默认模式的结论来自规则引擎;另有 ai_direct 模式直接把抓包摘要交给 LLM,
跳过本地规则和知识库,并在报告中明确标记分析方式。
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List

from . import db, kb, llm, tshark_service
from . import rules as rules_pkg
from .rules.base import Finding, RuleContext, TIER_ZH, classify_severity

log = logging.getLogger(__name__)


def _load_frames(capture_id: str) -> List[Dict[str, Any]]:
    rows = db.query(
        "SELECT no,ts,src,dst,sport,dport,proto,length,info,stream,analysis,expert "
        "FROM frames WHERE capture_id=? ORDER BY no", (capture_id,))
    return _decode_frames(rows)


def _decode_frames(rows) -> List[Dict[str, Any]]:
    """Decode DB frame rows into the structure consumed by rules and LLMs."""
    frames = []
    for r in rows:
        try:
            frame_analysis = json.loads(r["analysis"] or "[]")
        except json.JSONDecodeError:
            frame_analysis = []
        try:
            expert = json.loads(r["expert"] or "[]")
        except json.JSONDecodeError:
            expert = []
        frames.append({
            "no": r["no"], "ts": r["ts"], "src": r["src"], "dst": r["dst"],
            "sport": r["sport"], "dport": r["dport"], "proto": r["proto"],
            "length": r["length"], "info": r["info"], "stream": r["stream"],
            "analysis": frame_analysis, "expert": expert,
        })
    return frames


def _load_ai_sample(capture_id: str, frame_count: int) -> List[Dict[str, Any]]:
    """Load at most 200 representative frames without materializing the full capture."""
    columns = "no,ts,src,dst,sport,dport,proto,length,info,stream,analysis,expert"
    if frame_count <= 200:
        rows = db.query(
            f"SELECT {columns} FROM frames WHERE capture_id=? ORDER BY no LIMIT 200",
            (capture_id,),
        )
    else:
        rows = db.query(
            f"SELECT {columns} FROM frames WHERE capture_id=? AND "
            "(no IN (SELECT no FROM frames WHERE capture_id=? ORDER BY no LIMIT 160) OR "
            "no IN (SELECT no FROM frames WHERE capture_id=? ORDER BY no DESC LIMIT 40)) "
            "ORDER BY no",
            (capture_id, capture_id, capture_id),
        )
    if len(rows) > 200:  # Defensive for alternative DB adapters and test doubles.
        rows = list(rows[:160]) + list(rows[-40:])
    return _decode_frames(rows)


def _load_z_stats(path: str) -> Dict[str, Any]:
    """已解析的 -z 统计(尽力而为,失败不阻塞分析)。"""
    tshark = tshark_service.resolve_tshark()
    stats: Dict[str, Any] = {}
    if not tshark:
        return stats
    try:
        stats["io"] = tshark_service.get_stats_io(tshark, path, 1)
    except Exception as e:
        log.warning("io 统计失败(忽略):%s", e)
    try:
        stats["conversations_tcp"] = tshark_service.get_stats_conversations(tshark, path, "tcp")
    except Exception as e:
        log.warning("tcp 会话统计失败(忽略):%s", e)
    return stats


def _expert_frames(frames: List[Dict[str, Any]]):
    """按 _ws.expert.severity 分类 error/warn 帧号(实测口径,见 rules/base.classify_severity):

    - error: 0x800000(如 Malformed Packet);
    - warn:  0x600000(如 lost_segment / Connection reset);
    - 0x400000 是 note(retransmission/FIN)、0x200000 是 chat(SYN),不计入。
    同帧既有 error 又有 warn 时计入 error;severity 是逐 expert 项判断的
    (一帧多条 expert 会以数组形式逐项解析)。
    """
    error_nos, warn_nos = set(), set()
    for f in frames:
        has_error = has_warn = False
        for e in f.get("expert") or []:
            cls = classify_severity(e.get("severity"))
            if cls == "error":
                has_error = True
            elif cls == "warn":
                has_warn = True
        if has_error:
            error_nos.add(f["no"])
        elif has_warn:
            warn_nos.add(f["no"])
    return error_nos, warn_nos


def _coverage(findings_dicts: List[Dict[str, Any]], frames: List[Dict[str, Any]]) -> Dict[str, Any]:
    """报告覆盖范围:error/warn 专家帧总数 + 未被任何 V1 规则证据覆盖的数量。

    consumed = 所有 finding 的证据帧号并集(口径:证据清单)。
    """
    error_nos, warn_nos = _expert_frames(frames)
    consumed: set = set()
    for fd in findings_dicts:
        consumed.update(fd.get("evidence_frames") or [])
    unconsumed = sorted((error_nos | warn_nos) - consumed)
    n, m, k = len(error_nos), len(warn_nos), len(unconsumed)
    return {
        "expert_errors": n,
        "expert_warns": m,
        "unconsumed": k,
        "unconsumed_frames": unconsumed[:50],
        "note": ("consumed 口径 = 帧号出现在任一 finding 的证据帧清单;"
                 "severity 分类:0x800000=error,0x600000=warn(0x400000=note/0x200000=chat 不计入)。"),
    }


def analyze_capture(capture_id: str, mode: str = "rules") -> str:
    """执行诊断并写 reports 表,返回 report_id。

    ``mode=ai_direct`` 不调用规则引擎、不匹配知识库,直接根据抓包摘要生成 AI 首页分析。
    """
    row = db.query_one("SELECT * FROM captures WHERE id=?", (capture_id,))
    if row is None:
        raise KeyError(f"capture 不存在:{capture_id}")
    cap = db.row_to_dict(row)
    if cap["status"] != "ready":
        raise ValueError(f"capture 尚未就绪(status={cap['status']})")

    from . import settings as app_settings
    st = app_settings.load_settings()

    if mode == "ai_direct":
        if not llm.is_configured(st):
            raise ValueError("AI 配置不完整:请到系统设置启用并填写 Base URL、模型")
        total_frames = int(cap.get("frame_count") or 0)
        frames = _load_ai_sample(capture_id, total_frames)
        narrative = llm.generate_direct_analysis(cap, frames, st)
        if not narrative:
            raise RuntimeError("AI 未返回有效分析,请检查云端 API 配置或网络")
        sample_note = f"，抽样分析 {len(frames)} 帧" if total_frames > len(frames) else ""
        summary = (f"AI 直达分析：抓包共 {total_frames} 帧{sample_note};本次跳过本地规则引擎和知识库关联。"
                   "模型结论需结合原始报文进一步核验。")
        coverage = {
            "mode": "ai_direct", "local_rules_skipped": True,
            "local_kb_skipped": True, "frame_count": total_frames,
            "sampled_frames": len(frames),
            "note": "AI 直达分析只使用抓包摘要,未运行本地规则引擎和知识库匹配。",
        }
        report_id = uuid.uuid4().hex[:12]
        db.execute(
            "INSERT INTO reports(id,capture_id,created_at,engine,analysis_mode,findings,summary,narrative,masked,coverage) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (report_id, capture_id, datetime.now().timestamp(), "ai-direct", "ai_direct", "[]",
             summary, narrative, 1 if (st.get("masking") or {}).get("enabled", False) else 0,
             json.dumps(coverage, ensure_ascii=False)),
        )
        return report_id

    if mode != "rules":
        raise ValueError("mode 仅支持 rules|ai_direct")

    frames = _load_frames(capture_id)
    zstats = _load_z_stats(cap["path"])
    ctx = RuleContext(capture_id=capture_id, capture=cap, frames=frames, stats=zstats)
    findings: List[Finding] = rules_pkg.run_all(ctx)
    findings_dicts = [f.to_dict() for f in findings]

    # 知识库兜底:按命中规则匹配文章(目录为空时得到空列表,不报错)
    kb_dir = st.get("kb_dir")
    for fd in findings_dicts:
        try:
            fd["kb_ids"] = kb.match_kb_ids([fd["rule_id"]], kb_dir)
        except Exception:
            fd["kb_ids"] = []

    n_conf = sum(1 for f in findings_dicts if f["tier"] == "confirmed")
    n_susp = sum(1 for f in findings_dicts if f["tier"] == "suspect")
    n_pot = sum(1 for f in findings_dicts if f["tier"] == "potential")
    top = next((f for f in findings_dicts if f["tier"] == "confirmed"), None)
    summary = (
        f"共 {len(frames)} 帧;确诊 {n_conf} 项、疑似 {n_susp} 项、潜在风险 {n_pot} 项。"
        + (f"最关键问题:{top['title']}。" if top else "未发现确诊级故障。"))

    # 覆盖范围声明(不许静默漏报)
    coverage = _coverage(findings_dicts, frames)
    summary += (f"专家层 error/warn 帧共 {coverage['expert_errors'] + coverage['expert_warns']},"
                f"其中 {coverage['unconsumed']} 帧超出 V1 规则范围未判定。")

    report_id = uuid.uuid4().hex[:12]
    db.execute(
        "INSERT INTO reports(id,capture_id,created_at,engine,analysis_mode,findings,summary,narrative,masked,coverage) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (report_id, capture_id, datetime.now().timestamp(), f"rules-v1({len(rules_pkg.all_rule_ids())})", "rules",
         json.dumps(findings_dicts, ensure_ascii=False), summary, "",
         1 if (st.get("masking") or {}).get("enabled", False) else 0,
         json.dumps(coverage, ensure_ascii=False)))

    # LLM 叙述:后台线程,失败不影响报告
    if llm.is_configured(st) and findings_dicts:
        threading.Thread(target=_fill_narrative, args=(report_id, findings_dicts, summary, st),
                         name=f"llm-{report_id}", daemon=True).start()
    return report_id


def _fill_narrative(report_id: str, findings: List[Dict[str, Any]],
                    summary: str, settings: Dict[str, Any]) -> None:
    text = llm.generate_narrative(findings, summary, settings)
    if text:
        try:
            db.execute("UPDATE reports SET narrative=? WHERE id=?", (text, report_id))
        except Exception:
            log.exception("narrative 写库失败")
