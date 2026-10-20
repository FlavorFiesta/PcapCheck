# -*- coding: utf-8 -*-
"""S09 IPv4 路径 MTU 反馈(疑似，需要联动流量验证)。

出现 ICMP type=3 code=4(Fragmentation Needed,需要分片但 DF 置位)即命中:
路径上存在比发送方假设更小的 MTU；收到反馈不等于黑洞。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext, cap_evidence, tagged
from ..rules.registry import register


@register("S09_MTU_BLACKHOLE")
def check(ctx: RuleContext):
    hits = []
    for f in tagged(ctx.frames, "icmp"):
        for t in f.get("analysis", []):
            if t == "icmp=3/4":
                hits.append(f)
                break
    if not hits:
        return None
    reporters = sorted({f.get("src") for f in hits if f.get("src")})
    return Finding(
        rule_id="S09_MTU_BLACKHOLE",
        tier="suspect",
        title="观察到 IPv4 路径 MTU 反馈(ICMP Fragmentation Needed)",
        evidence_frames=cap_evidence(hits),
        stats={
            "icmp_frag_needed_count": len(hits),
            "reporters": reporters[:10],
        },
        suggestion=(
            "该 ICMP 可能是正常 PMTU 发现反馈，不能单独证明黑洞。结合大包重传和 ACK 推进"
            "检查各跳 MTU；若反馈无法到达发送端，再核对防火墙 ICMP 3/4 策略与隧道 MSS。"
        ),
    )
