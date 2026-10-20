---
title: 跨区访问不通(办公网 ↔ 数据中心 / DMZ)专题
rule_ids: [R02_SERVER_RST, S11_HANDSHAKE_RTT, S09_MTU_BLACKHOLE]
protocols: [TCP, ICMP, DNS, ARP]
symptoms: 跨网段系统打不开、间歇性通断、ping 通业务不通、只通小包
severity: 高
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

跨区流量必经防火墙/路由策略,「不通」按止步阶段分四类:DNS 解析失败(名字阶段)、请求未到达对端(ACL/路由无回程)、请求可达但响应不回(NAT 错配/回程路由)、握手成后应用拒绝(服务或安全策略)。两端同时抓包看报文「死在哪一跳」是最快的定位法,.ping 通只证明 ICMP 路径,不代表 TCP 业务路径。

## 判断标准(报文特征)

- 客户端侧只见 SYN(`tcp.flags.syn==1 && tcp.flags.ack==0`)反复重传、无 SYN-ACK:ACL 拦截或回程路由缺失。
- 收到 `icmp.type==3` 且 code==13(Admin Prohibited):策略明确拒绝;code==1(Host Unreachable):路由不可达。
- SYN-ACK 到达但随后被 RST(`tcp.flags.reset==1`,联动 R02):中间安全设备注入或应用层拒绝。
- ping 通、TCP 大包不通:MTU 黑洞(联动 S09,`icmp.type==3 && icmp.code==4`)。

## 报文证据特征

- DNS 阶段:`dns.flags.rcode!=0` 先排除解析问题(联动 R03)。
- 两端对齐 `frame.time_epoch`:源端有 SYN、目的端没有→中途被丢;目的端有 SYN 但响应未回到源端→回程问题。
- 防火墙注入 RST 特征:`ip.ttl` 与真实服务端回包差异明显、RST 与 SYN-ACK 竞争到达。

## 排查步骤

1. 两端同时抓包:`tshark -i <网卡> -w a.pcap -f "host <对端IP>"`,两端同步执行并记录起始时间。
2. 分阶段过滤:先 `dns.flags.rcode!=0`,再 `tcp.flags.syn==1 && tcp.flags.ack==0`,再 `tcp.flags.reset==1`,最后 `icmp.type==3`。
3. 对齐两端证据:`tshark -r a.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.flags -e frame.number | more`
4. 逐跳 ICMP 探测配合防火墙会话日志,比对命中的策略 ID。

## 处置建议

按止步阶段处置:解析失败修 DNS;无回程/ACL 修路由与策略并复核双向放行;NAT 错配修正地址池与转换规则;应用层拒绝联系系统管理员。变更后必须双端复抓验证,报告注明各阶段的帧号证据。
