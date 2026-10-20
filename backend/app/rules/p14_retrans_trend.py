# -*- coding: utf-8 -*-
"""P14 重传比例偏高趋势(潜在)。

按时间序在 TCP 帧上滑窗(默认 10 帧),窗口内重传占比 > 5% 即命中,
报告占比最高的窗口,反映「趋势」而非瞬时单点。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext, fmt_ratio, tagged, tcp_frames
from ..rules.registry import register
from ..rules import thresholds as th


@register("P14_RETRANS_TREND")
def check(ctx: RuleContext):
    tcp = tcp_frames(ctx.frames)
    if len(tcp) < th.P14_WINDOW:
        return None
    retrans = tagged(tcp, "retransmission")
    if not retrans:
        return None
    retx_nos = {f["no"] for f in retrans}

    best_ratio = 0.0
    best_window = []  # 窗口内的重传帧号
    w = th.P14_WINDOW
    for i in range(0, len(tcp) - w + 1):
        win = tcp[i:i + w]
        n = sum(1 for f in win if f["no"] in retx_nos)
        if n == 0:
            continue
        ratio = n / len(win)
        if ratio > best_ratio:
            best_ratio = ratio
            best_window = [f["no"] for f in win if f["no"] in retx_nos]
    if best_ratio <= th.P14_RATIO:
        return None
    return Finding(
        rule_id="P14_RETRANS_TREND",
        tier="potential",
        title="重传比例偏高趋势",
        evidence_frames=best_window[:50],
        stats={
            "max_window_ratio": round(best_ratio, 4),
            "window_frames": th.P14_WINDOW,
            "retrans_count": len(retrans),
            "tcp_frames": len(tcp),
            "overall_ratio": fmt_ratio(len(retrans), len(tcp)),
        },
        suggestion=(
            "窗口内重传占比超过 5%,链路质量存在劣化趋势:持续观测该方向流量,"
            "排查无线信号、链路拥塞与中间设备丢包,避免发展为重传风暴。"
        ),
    )
