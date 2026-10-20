# -*- coding: utf-8 -*-
"""S12 HTTP 5xx 集中(疑似)。

HTTP 响应状态码 >= 500 的数量达到阈值即命中,说明服务端/网关侧出错。
"""
from __future__ import annotations

from collections import Counter

from ..rules.base import Finding, RuleContext, cap_evidence, tag_value, tagged
from ..rules.registry import register
from ..rules import thresholds as th


@register("S12_HTTP_5XX")
def check(ctx: RuleContext):
    hits = []
    for f in tagged(ctx.frames, "http_code"):
        try:
            code = int(tag_value(f, "http_code") or "0")
        except ValueError:
            continue
        if code >= 500:
            hits.append((f, code))
    if len(hits) < th.S12_MIN_COUNT:
        return None
    counter = Counter(str(c) for _, c in hits)
    return Finding(
        rule_id="S12_HTTP_5XX",
        tier="suspect",
        title=f"HTTP 5xx 服务端错误集中(共 {len(hits)} 次)",
        evidence_frames=cap_evidence([f for f, _ in hits]),
        stats={
            "count_5xx": len(hits),
            "codes": dict(counter),
        },
        suggestion=(
            "5xx 表示服务端内部/网关错误:结合响应体与时间点检查应用日志、上游依赖(数据库/缓存)"
            "健康度;502/504 优先查反向代理与后端连通性,500/503 查应用异常与限流配置。"
        ),
    )
