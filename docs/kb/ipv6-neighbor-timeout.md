---
title: IPv6 邻居请求重试后无通告
rule_ids: [S21_IPV6_NEIGHBOR_TIMEOUT]
protocols: [IPv6, ICMPv6, NDP]
symptoms: IPv6 地址可见但同链路目标不通、默认网关偶发失联
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S21 对同一目标地址观测到重复 Neighbor Solicitation（ICMPv6 135），而没有 Neighbor Advertisement（136），且抓包末尾留有观察时间时提示疑似邻居不可达。它不能证明目标主机宕机；NA 可能因单向镜像或抓包点不在目标链路而不可见。

## 排查步骤

检查 `icmpv6.nd.ns.target_address`、`icmpv6.nd.na.target_address`、源 IPv6 和目的组播地址。确认 NS/NA 在同一二层链路都可捕获，再查看 VLAN、组播侦听、安全策略与目标网卡状态。IPv6 地址与默认路由还依赖 RS/RA、SLAAC/DAD；若只有特定站点故障，核查 RA 前缀/路由生命周期与 DHCPv6 配置，不能把所有 IPv6 失败归入邻居发现。

来源：[RFC 4861：Neighbor Discovery](https://www.rfc-editor.org/info/rfc4861/)；[RFC 4862：SLAAC](https://www.rfc-editor.org/info/rfc4862/)。

## 正常反例与处置

NS 发送到目标的 solicited-node 组播地址；如果镜像口未复制该组播组或目标回来的单播 NA，就会看到虚假的“无应答”。重复 NS 也可能是终端正在验证邻居可达性，而不是已经发生业务失败。应同时确认目标主机实际业务报文是否通过。若观察到 NA 且端点仍不通，应继续检查路由、策略与上层端口，而非继续归咎于邻居发现。

IPv6 默认网关通过 Router Advertisement 宣告。检查 RA 的路由器生命周期、前缀和 MTU 是否与网络配置一致；短时看不到周期性 RA 不足以证明路由器未发送，抓包需要覆盖完整宣告周期，并可主动触发 RS 复核。
