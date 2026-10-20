# -*- coding: utf-8 -*-
"""R05 ARP IP 冲突(确诊)。

同一发送 IP 在 ARP 报文中由 >=2 个不同 MAC 宣告(含 gratuitous ARP 冲突),判定 IP 冲突。
数据来源:导入时为每个 ARP 帧打的 `arp_sender=<ip>|<mac>` 标签。
"""
from __future__ import annotations

from collections import defaultdict

from ..rules.base import Finding, RuleContext, cap_evidence
from ..rules.registry import register
from ..rules import thresholds as th


@register("R05_ARP_CONFLICT")
def check(ctx: RuleContext):
    ip_macs: dict = defaultdict(lambda: defaultdict(list))  # ip -> mac -> [frame]
    for f in ctx.frames:
        for t in f.get("analysis", []):
            if t.startswith("arp_sender="):
                payload = t[len("arp_sender="):]
                ip, _, mac = payload.partition("|")
                if ip:
                    ip_macs[ip][mac or "?"].append(f)
    findings = []
    for ip, macs in ip_macs.items():
        if len(macs) < th.R05_MIN_MACS:
            continue
        frames = sorted((f for lst in macs.values() for f in lst), key=lambda f: f["no"])
        findings.append(Finding(
            rule_id="R05_ARP_CONFLICT",
            tier="confirmed",
            title=f"ARP IP 地址冲突:{ip}",
            evidence_frames=cap_evidence(frames),
            stats={
                "ip": ip,
                "mac_count": len(macs),
                "macs": {m: len(lst) for m, lst in macs.items()},
                "conflict_frames": len(frames),
            },
            suggestion=(
                "同一 IP 被多个 MAC 使用:常见于私接设备误配静态地址或 ARP 欺骗/病毒。"
                "在接入交换机上查 MAC 地址表定位端口,执行 IP-MAC 绑定或启用动态 ARP 检测(DAI)。"
            ),
        ))
    return findings
