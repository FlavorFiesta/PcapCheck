# -*- coding: utf-8 -*-
"""U17_EXPERT_FALLBACK(潜在):超出专用规则范围的专家级告警兜底。

触发(全部满足):
- 存在未被其它规则消费的 warn(0x600000)/error(0x800000)级 expert 帧 ≥1
  (消费判定沿用 analysis.py 口径:帧号出现在任一 finding 证据集,由 registry
  第二阶段注入 ctx.consumed);
- 该帧的 warn/error 消息文本不含 "common at capture start"(捕获起点伪影豁免)。

结论:「存在 N 条专家级告警超出专用规则范围,建议人工查看」,证据给样本帧号。
本规则不下确定性结论,只做"不静默漏报"的兜底提示。
"""
from __future__ import annotations

from collections import Counter

from ..rules.base import (Finding, RuleContext, SEV_ERROR, SEV_WARN,
                          cap_evidence, classify_severity)
from ..rules.registry import register

ARTIFACT_MARKER = "common at capture start"


@register("U17_EXPERT_FALLBACK", needs_consumed=True)
def check(ctx: RuleContext):
    consumed = ctx.consumed or set()
    hits = []          # 未消费且有非伪影 warn/error 的帧
    sev_counter: Counter = Counter()
    msgs: Counter = Counter()
    for f in ctx.frames:
        if f["no"] in consumed:
            continue
        has_relevant = False
        for e in f.get("expert") or []:
            cls = classify_severity(e.get("severity"))
            if cls not in ("warn", "error"):
                continue
            msg = e.get("message") or ""
            if ARTIFACT_MARKER in msg.lower():
                continue  # 捕获起点伪影豁免
            has_relevant = True
            sev_counter[cls] += 1
            msgs[msg] += 1
        if has_relevant:
            hits.append(f)
    if not hits:
        return None
    return Finding(
        rule_id="U17_EXPERT_FALLBACK",
        tier="potential",
        title=f"存在 {len(hits)} 条专家级告警超出专用规则范围,建议人工查看",
        evidence_frames=cap_evidence(hits),
        stats={
            "unconsumed_warn_error_frames": len(hits),
            "severity": dict(sev_counter),
            "sample_messages": dict(msgs.most_common(6)),
        },
        suggestion=(
            "这些专家级告警(error/warn)未被任何专用规则覆盖,建议人工逐条查看"
            "(证据帧号可跳转核对);常见来源:协议实现异常、中间盒改包、"
            "非标准协议用法,确认是否与故障时间点相关。"
        ),
    )
