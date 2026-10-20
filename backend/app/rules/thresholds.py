# -*- coding: utf-8 -*-
"""规则引擎 V1 阈值集中配置(方案.md 定稿的 15 条规则)。"""
from __future__ import annotations

# ---- 确诊 ----
# R01 TCP 重传风暴:重传帧数达到下限,或占比超阈值(且次数达到下限)
R01_RETRANS_MIN_COUNT = 10
R01_RETRANS_RATIO = 0.15
R01_RETRANS_RATIO_MIN_COUNT = 5

# R02 服务端中途 RST:流内出现 RST 且未走 FIN 优雅关闭
R02_MIN_RST_PER_STREAM = 1

# R03 DNS SERVFAIL(2)/ NXDOMAIN(3)
R03_BAD_RCODES = (2, 3)

# R04 TLS alert desc 白名单(证书过期/握手失败类)
R04_ALERT_DESCS = ("40", "41", "42", "43", "44", "45", "46", "112")

# R05 ARP IP 冲突:同一发送 IP 出现 >= 2 个不同 MAC
R05_MIN_MACS = 2

# R06 DHCP NAK / DECLINE
R06_NAK_MSG = 6
R06_DECLINE_MSG = 4

# R07 持续零窗口
R07_ZERO_WINDOW_MIN = 3          # zero_window 帧数阈值
R07_WINDOW_FULL_MIN = 5          # window_full 帧数阈值
R07_MIN_DURATION_SEC = 3.0       # 或零窗口现象持续秒数

# ---- 疑似 ----
# S08 乱序比例异常:(count>=5 且 ratio>=0.10) 或 (count>=2 且 ratio>=0.20)
S08_MIN_COUNT = 5
S08_RATIO = 0.10
S08_ALT_MIN_COUNT = 2
S08_ALT_RATIO = 0.20

# S10 DNS 响应慢
S10_SLOW_SEC = 1.0

# S11 TCP 握手 RTT 异常(SYN -> SYN-ACK)
S11_RTT_SEC = 1.0

# S12 HTTP 5xx 集中
S12_MIN_COUNT = 3

# ---- 潜在 ----
# P13 带宽趋于饱和:每秒字节数持续高位
P13_BPS_THRESHOLD = 12_500_000   # 100 Mbps
P13_SUSTAIN_SEC = 10             # 持续秒数

# P14 重传比例偏高趋势:滑动窗口内重传占比
P14_WINDOW = 10
P14_RATIO = 0.05

# P15 RTP 单向音频
P15_MIN_FRAMES = 10
