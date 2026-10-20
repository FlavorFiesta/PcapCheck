# -*- coding: utf-8 -*-
"""S08 乱序比例异常(疑似)。

TCP 乱序帧占比超过阈值且数量达到下限。常见于多路径/链路切换、QoS 重排序或丢包重传。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext, cap_evidence, fmt_ratio, tagged, tcp_frames
from ..rules.registry import register
from ..rules import thresholds as th


@register("S08_OUT_OF_ORDER")
def check(ctx: RuleContext):
    tcp = tcp_frames(ctx.frames)
    ooo = tagged(tcp, "out_of_order")
    ratio = fmt_ratio(len(ooo), len(tcp))
    fire = ((len(ooo) >= th.S08_MIN_COUNT and ratio >= th.S08_RATIO) or
            (len(ooo) >= th.S08_ALT_MIN_COUNT and ratio >= th.S08_ALT_RATIO))
    if not fire:
        return None
    streams = sorted({f["stream"] for f in ooo if f.get("stream") is not None})
    return Finding(
        rule_id="S08_OUT_OF_ORDER",
        tier="suspect",
        title="TCP 乱序比例异常",
        evidence_frames=cap_evidence(ooo),
        stats={
            "out_of_order_frames": len(ooo),
            "tcp_frames": len(tcp),
            "ratio": ratio,
            "streams_affected": len(streams),
            "sample_streams": streams[:10],
        },
        suggestion=(
            "乱序偏高会造成接收端性能下降:排查等价路由/多链路负载均衡导致的路径差异,"
            "确认是否发生链路切换;若乱序伴随丢包,优先处理链路质量问题。"
        ),
    )
