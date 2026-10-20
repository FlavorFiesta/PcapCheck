# -*- coding: utf-8 -*-
"""S11 TCP 握手 RTT 异常(疑似)。

SYN -> SYN-ACK 的 ack_rtt > 阈值(默认 1s)。握手慢说明服务端响应慢或路径 RTT 高/丢包重传。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext, cap_evidence, tag_value, tagged
from ..rules.registry import register
from ..rules import thresholds as th


@register("S11_HANDSHAKE_RTT")
def check(ctx: RuleContext):
    hits = []
    for f in tagged(ctx.frames, "ack_rtt"):
        # 仅看 SYN-ACK 帧(握手 RTT;导入时只对带 SYN 的帧打 ack_rtt 标签)
        if "synack" not in f.get("analysis", []):
            continue
        try:
            rtt = float(tag_value(f, "ack_rtt") or "0")
        except ValueError:
            continue
        if rtt > th.S11_RTT_SEC:
            hits.append((f, rtt))
    if not hits:
        return None
    max_rtt = max(r for _, r in hits)
    streams = sorted({f["stream"] for f, _ in hits if f.get("stream") is not None})
    return Finding(
        rule_id="S11_HANDSHAKE_RTT",
        tier="suspect",
        title=f"TCP 握手 RTT 异常(SYN→SYN-ACK > {th.S11_RTT_SEC:g}s)",
        evidence_frames=cap_evidence([f for f, _ in hits]),
        stats={
            "slow_handshakes": len(hits),
            "max_rtt_sec": round(max_rtt, 3),
            "streams_affected": len(streams),
            "sample_streams": streams[:10],
        },
        suggestion=(
            "建连慢通常源于服务端过载(accept 队列堆积)、路径高时延或 SYN 丢包重传:"
            "确认服务端负载与 backlog,核查链路 RTT 与中间设备限速。"
        ),
    )
