# -*- coding: utf-8 -*-
"""R07 持续零窗口(确诊)。

接收方持续通告零窗口(zero_window)或发送方持续打满对端窗口(window_full),
且帧数/持续时间达到阈值,判定为接收方处理能力不足导致的流量停滞。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext, cap_evidence, tagged
from ..rules.registry import register
from ..rules import thresholds as th


@register("R07_ZERO_WINDOW")
def check(ctx: RuleContext):
    zw = tagged(ctx.frames, "zero_window")
    wf = tagged(ctx.frames, "window_full")
    if not zw and not wf:
        return None
    all_f = sorted(zw + wf, key=lambda f: f["no"])
    duration = (all_f[-1]["ts"] - all_f[0]["ts"]) if len(all_f) > 1 else 0.0
    if not (len(zw) >= th.R07_ZERO_WINDOW_MIN or
            len(wf) >= th.R07_WINDOW_FULL_MIN or
            duration >= th.R07_MIN_DURATION_SEC):
        return None
    streams = sorted({f["stream"] for f in all_f if f.get("stream") is not None})
    return Finding(
        rule_id="R07_ZERO_WINDOW",
        tier="confirmed",
        title="TCP 零窗口持续:接收方应用处理不过来",
        evidence_frames=cap_evidence(all_f),
        stats={
            "zero_window_frames": len(zw),
            "window_full_frames": len(wf),
            "duration_sec": round(duration, 3),
            "streams_affected": len(streams),
            "sample_streams": streams[:10],
        },
        suggestion=(
            "零窗口说明对端应用来不及消费数据:排查接收方进程 CPU/内存、阻塞点与磁盘 IO,"
            "确认应用是否有死锁或慢查询;若接收端为代理/中间件,检查其缓冲与下游依赖。"
        ),
    )
