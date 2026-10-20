---
title: DHCP 发现或请求重试后无响应
rule_ids: [S20_DHCP_TIMEOUT]
protocols: [DHCP, UDP]
symptoms: 终端长时间拿不到地址、重复 DISCOVER 或 REQUEST、续约失败
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S20 使用 DHCP 事务 ID（可用时结合客户端 MAC）归并事务。重复 DISCOVER 后未见 OFFER，或重复 REQUEST 后未见 ACK/NAK，且抓包末尾留有观察时间时，给出疑似提示。R06 处理的是已经出现 NAK/DECLINE 的显式失败，两类现象应分开看。

## 排查步骤

检查 `dhcp.id`、`dhcp.hw.mac_addr`、`dhcp.option.dhcp` 和中继 `giaddr`，按客户端还原 DORA/续租过程。终端侧无 OFFER 时，在接入交换机、中继及服务器端抓包，判断请求是否到达服务器和回包在哪一段消失。两个合法服务器都发 OFFER 是协议允许的，不应自动判为私接设备；核对授权清单后再判断。

## 处置建议

核查 DHCP 服务状态、作用域、地址池、中继、DHCP Snooping 与 VLAN；没有服务器日志时，不能由无 OFFER 单独确诊地址池耗尽。确保抓包覆盖完整重试过程及双向流量。

来源：[RFC 2131：DHCP](https://www.rfc-editor.org/info/rfc2131/)。

## 正常反例

抓包若只包含客户端广播方向，OFFER/ACK 可能通过其它路径返回而未被本镜像口采集；收到 NAK 则应转由 R06 分析。续租期的单播 REQUEST 与首次申请的广播 DISCOVER 不应混为同一阶段。
