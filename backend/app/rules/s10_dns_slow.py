# -*- coding: utf-8 -*-
"""S10 DNS 响应慢(疑似)。

同一 (流, 查询名) 内,查询帧与其后首个响应帧间隔 > 阈值(默认 1s,可在 thresholds 配置)。
"""
from __future__ import annotations

from collections import defaultdict, deque

from ..rules.base import Finding, RuleContext, cap_evidence, tag_value
from ..rules.registry import register
from ..rules import thresholds as th


@register("S10_DNS_SLOW")
def check(ctx: RuleContext):
    pending: dict = defaultdict(deque)   # (stream, qname) -> 查询帧队列
    slow = []                            # (response_frame, delay, qname)
    delays_all = []
    for f in ctx.frames:
        qname = tag_value(f, "dns_qname")
        if not qname:
            continue
        key = (f.get("stream"), qname)
        if "dns_resp" in f.get("analysis", []):
            q = pending.get(key)
            while q and q[0]["ts"] > f["ts"]:
                q.popleft()
            if q:
                query = q.popleft()
                delay = f["ts"] - query["ts"]
                delays_all.append(delay)
                if delay > th.S10_SLOW_SEC:
                    slow.append((f, delay, qname))
        else:
            pending[key].append(f)
    if not slow:
        return None
    slow.sort(key=lambda x: -x[1])
    return Finding(
        rule_id="S10_DNS_SLOW",
        tier="suspect",
        title=f"DNS 响应慢(> {th.S10_SLOW_SEC:g}s)",
        evidence_frames=cap_evidence([f for f, _, _ in slow]),
        stats={
            "slow_count": len(slow),
            "max_delay_sec": round(max(d for _, d, _ in slow), 3),
            "avg_delay_sec": round(sum(d for _, d, _ in slow) / len(slow), 3),
            "total_dns_pairs": len(delays_all),
            "samples": [
                {"query_name": n, "delay_sec": round(d, 3), "response_frame": f["no"]}
                for f, d, n in slow[:10]
            ],
        },
        suggestion=(
            "DNS 问答间隔过长会导致业务卡顿:检查递归服务器到上游的链路与负载,"
            "排查是否存在丢包重试(看查询是否重复出现),必要时增加本地缓存/备用 DNS。"
        ),
    )
