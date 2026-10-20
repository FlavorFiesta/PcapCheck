# -*- coding: utf-8 -*-
"""R03 DNS SERVFAIL / NXDOMAIN(确诊)。

DNS 响应 rcode=2(SERVFAIL)或 rcode=3(NXDOMAIN)即命中。
"""
from __future__ import annotations

from collections import Counter

from ..rules.base import Finding, RuleContext, cap_evidence, tag_value, tagged
from ..rules.registry import register
from ..rules import thresholds as th

_RCODE_NAME = {2: "SERVFAIL(服务器内部失败)", 3: "NXDOMAIN(域名不存在)"}


@register("R03_DNS_FAILURE")
def check(ctx: RuleContext):
    bad = []
    for f in tagged(ctx.frames, "dns_rcode"):
        try:
            rcode = int(tag_value(f, "dns_rcode") or "0")
        except ValueError:
            continue
        if rcode in th.R03_BAD_RCODES:
            bad.append((f, rcode))
    if not bad:
        return None
    counter = Counter(rcode for _, rcode in bad)
    names = [tag_value(f, "dns_qname") for f, _ in bad]
    names = [n for n in names if n]
    parts = ";".join(f"{_RCODE_NAME.get(r, r)}×{c}" for r, c in counter.most_common())
    return Finding(
        rule_id="R03_DNS_FAILURE",
        tier="confirmed",
        title=f"DNS 解析失败({parts})",
        evidence_frames=cap_evidence([f for f, _ in bad]),
        stats={
            "rcode_2_servfail": counter.get(2, 0),
            "rcode_3_nxdomain": counter.get(3, 0),
            "failed_queries": len(bad),
            "sample_names": list(dict.fromkeys(names))[:10],
        },
        suggestion=(
            "NXDOMAIN 多为域名写错或域名已下线;SERVFAIL 多为权威/递归服务器异常或 DNSSEC 校验"
            "失败。先确认域名拼写,再换公共 DNS(如 223.5.5.5 / 114.114.114.114)对比测试,"
            "并检查本机 DNS 配置与内网 DNS 服务器的转发策略。"
        ),
    )
