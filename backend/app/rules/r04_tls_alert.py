# -*- coding: utf-8 -*-
"""R04 TLS alert —— 证书过期/握手失败(确诊)。

命中 tls.alert_message.desc ∈ {40,41,42,43,44,45,46,112}
(契约列出 40/41/42/43/44/46/112;45=CertificateExpired 即「证书过期」的线上的编码,
 与规则标题语义一致,一并纳入)。
"""
from __future__ import annotations

from collections import Counter

from ..rules.base import Finding, RuleContext, cap_evidence, tag_value, tagged
from ..rules.registry import register
from ..rules import thresholds as th
from ..tshark_service import tls_alert_name


@register("R04_TLS_ALERT")
def check(ctx: RuleContext):
    alerts = []
    for f in tagged(ctx.frames, "tls_alert"):
        desc = tag_value(f, "tls_alert")
        if desc and desc.split(".")[0] in th.R04_ALERT_DESCS:
            alerts.append((f, desc))
    if not alerts:
        return None
    counter = Counter(desc for _, desc in alerts)
    top_desc, top_n = counter.most_common(1)[0]
    return Finding(
        rule_id="R04_TLS_ALERT",
        tier="confirmed",
        title=f"TLS 告警:{tls_alert_name(top_desc)}",
        evidence_frames=cap_evidence([f for f, _ in alerts]),
        stats={
            "alert_count": len(alerts),
            "desc_counts": dict(counter),
            "desc_meanings": {d: tls_alert_name(d) for d in counter},
        },
        suggestion=(
            "握手失败/证书类告警:确认服务器证书是否过期、证书链是否完整、系统时间是否正确;"
            "desc=40 握手失败常见于加密套件/TLS 版本不匹配或被中间设备拦截;"
            "desc=112 多为 SNI/虚拟主机名配置错误。核对客户端与服务端的 TLS 策略后重试。"
        ),
    )
