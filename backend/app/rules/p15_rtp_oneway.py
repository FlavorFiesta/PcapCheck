# -*- coding: utf-8 -*-
"""P15 RTP 单向音频(潜在)。

按 UDP 流聚合带 SSRC 的 RTP 帧:某条流内 RTP 只出现在一个方向(对端没有任何 RTP 回包)
且帧数达到阈值,判定为疑似单向音频。
"""
from __future__ import annotations

from collections import defaultdict

from ..rules.base import Finding, RuleContext, cap_evidence
from ..rules.registry import register
from ..rules import thresholds as th


def _rtp_frames(ctx: RuleContext):
    out = []
    for f in ctx.frames:
        for t in f.get("analysis", []):
            if t.startswith("rtp_ssrc="):
                out.append(f)
                break
    return out


@register("P15_RTP_ONEWAY")
def check(ctx: RuleContext):
    rtp = _rtp_frames(ctx)
    if not rtp:
        return None
    streams: dict = defaultdict(list)
    for f in rtp:
        key = f.get("stream") if f.get("stream") is not None else \
            (f.get("src"), f.get("sport"), f.get("dst"), f.get("dport"))
        streams[key].append(f)

    findings = []
    for key, frames in streams.items():
        dirs: dict = defaultdict(list)  # (src,sport,dst,dport) -> frames
        ssrcs: set = set()
        for f in frames:
            dirs[(f.get("src"), f.get("sport"), f.get("dst"), f.get("dport"))].append(f)
            ssrcs.update(t[len("rtp_ssrc="):] for t in f.get("analysis", [])
                         if t.startswith("rtp_ssrc="))
        if len(dirs) != 1 or len(frames) < th.P15_MIN_FRAMES:
            continue
        direction, dframes = next(iter(dirs.items()))
        duration = dframes[-1]["ts"] - dframes[0]["ts"]
        findings.append(Finding(
            rule_id="P15_RTP_ONEWAY",
            tier="potential",
            title="RTP 单向音频(仅一个方向有媒体流)",
            evidence_frames=cap_evidence(dframes),
            stats={
                "stream": key,
                "ssrcs": sorted(ssrcs),
                "direction": f"{direction[0]}:{direction[1]} -> {direction[2]}:{direction[3]}",
                "rtp_frames": len(dframes),
                "duration_sec": round(duration, 3),
            },
            suggestion=(
                "只有单方向 RTP 媒体流,通话大概率听不到对方声音:排查对端是否未回送 RTP"
                "(防火墙/ALG 拦截、NAT 对称限制、SIP 信令 SDP 地址错误),"
                "并确认抓包点是否完整覆盖双向流量。"
            ),
        ))
    return findings
