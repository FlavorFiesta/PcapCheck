---
title: IPv6 Packet Too Big 与路径 MTU 排查
rule_ids: [S22_IPV6_PACKET_TOO_BIG]
protocols: [IPv6, ICMPv6, TCP]
symptoms: IPv6 小包正常、大包停滞、隧道内业务卡顿
severity: 低(潜在)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S22 发现 ICMPv6 Type 2（Packet Too Big）后仅提示复核。这是 IPv6 路径 MTU 发现的重要反馈，单独出现可能属于正常工作。真正的黑洞可能发生在反馈被拦截时，发送端一侧反而看不到 Packet Too Big。

## 排查步骤

查看 ICMPv6 报文通告的 MTU、来源路由器和引用的原始流，关联同一流的大包重传、ACK 是否推进及端点是否调整发送大小。若客户端可见反馈而仍持续大包重传，检查主机或隧道设备的 MTU 处理；若发送端看不到反馈，分别在中间链路与发送端抓包，定位 ICMPv6 过滤位置。IPv6 路由器不能按 IPv4 模式替端点分片。

## 处置建议

调整隧道/overlay MTU 与 TCP MSS，允许必需的 ICMPv6；依据实际抓包点区分正常反馈和黑洞。IPv4 的 `ping -f` 测试不能直接套用到 IPv6。

来源：[RFC 8201：IPv6 PMTUD](https://www.rfc-editor.org/info/rfc8201/)；[RFC 4443：ICMPv6](https://www.rfc-editor.org/info/rfc4443/)。

## 正常反例

发送端收到 PTB 后降低包长且传输继续，说明路径 MTU 发现发挥了作用；不应因为存在 PTB 就发出“黑洞确诊”。
