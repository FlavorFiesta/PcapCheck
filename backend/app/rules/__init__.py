# -*- coding: utf-8 -*-
"""规则引擎包:import 即完成全部规则注册。"""
from __future__ import annotations

from . import (  # noqa: F401  按档位顺序导入以注册
    r01_retrans_storm,
    r02_server_rst,
    r03_dns_failure,
    r04_tls_alert,
    r05_arp_conflict,
    r06_dhcp_failure,
    r07_zero_window,
    s08_out_of_order,
    s09_mtu_blackhole,
    s10_dns_slow,
    s11_handshake_rtt,
    s12_http_5xx,
    p13_bandwidth,
    p14_retrans_trend,
    p15_rtp_oneway,
    u16_malformed,
    u17_expert_fallback,
    coverage_expansion,
)
from .base import Finding, RuleContext, TIER_ORDER, TIER_ZH  # noqa: F401
from .registry import all_rule_ids, register, run_all  # noqa: F401
