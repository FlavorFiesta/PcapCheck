# -*- coding: utf-8 -*-
"""U16_MALFORMED(疑似):畸形帧检测。

触发(满足其一,≥1 帧):
- _ws.malformed 为真(导入时打 "malformed" 标签);
- expert 项 severity=error(0x800000)且 group=Malformed(实测掩码 0x7000000,
  epan/expert.h 的 PI_MALFORMED << 24)。

结论:「存在 N 个畸形帧(解码失败/字段异常)」;建议指向对端实现问题 /
中间盒改包 / 抓包口位错。
"""
from __future__ import annotations

from collections import Counter

from ..rules.base import Finding, RuleContext, cap_evidence, classify_severity
from ..rules.registry import register

# epan/expert.h PI_MALFORMED 在 group 位域中的编码(实测 _ws.expert.group=117440512)
GROUP_MALFORMED = 0x7000000


def _is_malformed_frame(frame: dict) -> bool:
    if "malformed" in frame.get("analysis", []):
        return True
    for e in frame.get("expert") or []:
        if classify_severity(e.get("severity")) == "error" and _group_of(e) == GROUP_MALFORMED:
            return True
    return False


def _group_of(item: dict):
    try:
        return int(item.get("group"))
    except (TypeError, ValueError):
        return None


@register("U16_MALFORMED")
def check(ctx: RuleContext):
    hits = [f for f in ctx.frames if _is_malformed_frame(f)]
    if not hits:
        return None
    msgs = Counter()
    for f in hits:
        m = [e.get("message") for e in f.get("expert") or [] if e.get("message")]
        if not m and "malformed" in f.get("analysis", []):
            m = ["Malformed Packet"]
        for x in m:
            msgs[x] += 1
    return Finding(
        rule_id="U16_MALFORMED",
        tier="suspect",
        title=f"存在 {len(hits)} 个畸形帧(解码失败/字段异常)",
        evidence_frames=cap_evidence(hits),
        stats={
            "malformed_frames": len(hits),
            "sample_messages": dict(list(msgs.most_common(5))),
        },
        suggestion=(
            "畸形帧通常是解码失败或字段异常:优先排查对端协议实现问题(版本/长度字段不符)、"
            "中间盒改包或截断(NAT/防火墙/负载均衡),以及抓包口位错、链路误码;"
            "确认抓包点可靠后,把样本帧提供给对端定位。"
        ),
    )
