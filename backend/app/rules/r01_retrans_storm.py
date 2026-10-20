# -*- coding: utf-8 -*-
"""R01 TCP 重传风暴(确诊)。

同一捕获内 TCP 重传帧数量达到阈值,或重传占比异常偏高,判定为重传风暴。
典型原因:链路丢包、劣质 Wi-Fi、中间设备丢包、对端接收能力异常。
"""
from __future__ import annotations

from ..rules.base import Finding, RuleContext, cap_evidence, fmt_ratio, tagged, tcp_frames
from ..rules.registry import register
from ..rules import thresholds as th


@register("R01_RETRANS_STORM")
def check(ctx: RuleContext):
    tcp = tcp_frames(ctx.frames)
    retx = tagged(tcp, "retransmission")
    count = len(retx)
    ratio = fmt_ratio(count, len(tcp))
    if not (count >= th.R01_RETRANS_MIN_COUNT or
            (count >= th.R01_RETRANS_RATIO_MIN_COUNT and ratio >= th.R01_RETRANS_RATIO)):
        return None
    streams = sorted({f["stream"] for f in retx if f.get("stream") is not None})
    return Finding(
        rule_id="R01_RETRANS_STORM",
        tier="confirmed",
        title="TCP 重传风暴",
        evidence_frames=cap_evidence(retx),
        stats={
            "retrans_count": count,
            "tcp_frames": len(tcp),
            "retrans_ratio": ratio,
            "streams_affected": len(streams),
            "sample_streams": streams[:10],
        },
        suggestion=(
            "重传集中说明链路存在丢包:优先检查物理链路/无线信号质量与中间设备端口错包计数,"
            "确认是否存在带宽拥塞或双工/速率协商问题;若重传集中在单一会话,"
            "重点排查该会话两端主机与路径上的防火墙、代理设备。"
        ),
    )
