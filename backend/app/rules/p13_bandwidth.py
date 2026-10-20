# -*- coding: utf-8 -*-
"""P13 带宽趋于饱和(潜在)。

把全部帧按秒分桶统计字节数,若连续 >= N 秒每秒字节数都超过阈值(默认 100 Mbps),
判定带宽趋于饱和。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext
from ..rules.registry import register
from ..rules import thresholds as th


@register("P13_BANDWIDTH_SATURATION")
def check(ctx: RuleContext):
    frames = ctx.frames
    if len(frames) < 2:
        return None
    t0 = frames[0]["ts"]
    buckets: dict = {}
    for f in frames:
        try:
            sec = int(f["ts"] - t0)
        except (TypeError, ValueError):
            continue
        if sec < 0:
            sec = 0
        buckets[sec] = buckets.get(sec, 0) + (f.get("length") or 0)

    # 找最长连续高位秒段
    best_len = 0
    best_start = None
    cur_len = 0
    cur_start = None
    sec = 0
    total_secs = max(buckets) + 1 if buckets else 0
    for sec in range(total_secs):
        b = buckets.get(sec, 0)
        if b >= th.P13_BPS_THRESHOLD:  # 每秒字节数,即 B/s
            if cur_len == 0:
                cur_start = sec
            cur_len += 1
            if cur_len > best_len:
                best_len, best_start = cur_len, cur_start
        else:
            cur_len = 0
    if best_len < th.P13_SUSTAIN_SEC:
        return None

    hi_secs = [s for s in range(best_start, best_start + best_len)]
    avg_bps = sum(buckets.get(s, 0) for s in hi_secs) / best_len
    evidence_pool = [f for f in frames if best_start <= int(f["ts"] - t0) < best_start + best_len]
    return Finding(
        rule_id="P13_BANDWIDTH_SATURATION",
        tier="potential",
        title="带宽趋于饱和:每秒字节数持续高位",
        evidence_frames=[f["no"] for f in evidence_pool[:50]],
        stats={
            "sustain_sec": best_len,
            "avg_bytes_per_sec": int(avg_bps),
            "max_bytes_per_sec": max(buckets.get(s, 0) for s in hi_secs),
            "threshold_mbps": round(th.P13_BPS_THRESHOLD * 8 / 1e6, 1),
            "window_start_sec": best_start,
        },
        suggestion=(
            "链路利用率持续高位,新业务可能出现丢包与时延抖动:核对链路带宽与峰值时段,"
            "评估扩容或做流量整形;结合会话表找出占带宽最大的主机/会话。"
        ),
    )
