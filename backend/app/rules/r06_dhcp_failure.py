# -*- coding: utf-8 -*-
"""R06 DHCP NAK / 失败(确诊)。

命中 DHCP 消息类型 NAK(6)或 DECLINE(4):
- NAK:服务器拒绝客户端的续约/请求,客户端地址获取失败;
- DECLINE:客户端检测到地址冲突主动拒绝服务器提供的 OFFER。
"""
from __future__ import annotations

from collections import Counter

from ..rules.base import Finding, RuleContext, cap_evidence, tag_value, tagged
from ..rules.registry import register
from ..rules import thresholds as th


@register("R06_DHCP_FAILURE")
def check(ctx: RuleContext):
    nak, decline = [], []
    for f in tagged(ctx.frames, "dhcp_msg"):
        try:
            msg = int(tag_value(f, "dhcp_msg") or "0")
        except ValueError:
            continue
        if msg == th.R06_NAK_MSG:
            nak.append(f)
        elif msg == th.R06_DECLINE_MSG:
            decline.append(f)
    if not nak and not decline:
        return None
    if nak:
        title = "DHCP NAK:地址申请被服务器拒绝"
    else:
        title = "DHCP DECLINE:客户端检测到地址冲突"
    servers = Counter(f.get("src") for f in nak if f.get("src"))
    return Finding(
        rule_id="R06_DHCP_FAILURE",
        tier="confirmed",
        title=title,
        evidence_frames=cap_evidence(nak + decline),
        stats={
            "nak_count": len(nak),
            "decline_count": len(decline),
            "nak_servers": dict(servers),
        },
        suggestion=(
            "NAK 多因客户端请求的地址已不在服务器作用域、租约冲突或服务器迁移;"
            "DECLINE 说明 Offer 的地址已被占用,排查私接 DHCP/静态 IP 冲突。"
            "检查 DHCP 服务器作用域与中继配置,必要时释放续约(ipconfig /release && /renew)复测。"
        ),
    )
