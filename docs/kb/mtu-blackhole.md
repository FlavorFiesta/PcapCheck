---
title: 路径 MTU 受限与疑似黑洞
rule_ids: [S09_MTU_BLACKHOLE]
protocols: [ICMP, TCP]
symptoms: 大包不通小包通、HTTPS 卡在握手后、文件传输停滞、VPN 内部分网站打不开
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

路径上某段链路 MTU 小于发送端假设(典型:VPN/GRE/PPPoE 封装额外开销)。发送端报文带 DF 位不分片,中间路由器只能回 ICMP type=3 code=4(Fragmentation Needed)告知下一跳 MTU。若该 ICMP 被防火墙丢弃,发送端收不到通知,连接在大数据段时反复卡死——即「黑洞」。小包(握手、DNS)正常是典型症状。

## 判断标准

当前 S09 在出现 `icmp.type==3 && icmp.code==4` 时提示复核路径 MTU。这可能是正常的 PMTU 反馈，不能仅凭该包判断黑洞；如果 ICMP 在路径上被丢弃，发送端抓包反而可能看不到它。需结合大包反复重传、ACK 不前进及双端抓包判断。

## 报文证据特征

- 过滤器 `icmp.type==3 && icmp.code==4`,ICMP 包内引用原发数据报头部;详情树中「MTU of next hop」字段给出路径最小 MTU(常见 1452、1476、1492)。
- 触发它的 TCP 数据帧 `ip.flags.df==1` 且 `tcp.len` 接近发送端 MTU(如 1460)。
- 黑洞特征:同一流内数据段反复重发(`tcp.analysis.retransmission`)却始终无窗口/ACK 推进。

## 排查步骤

1. 提取通告 MTU 与来源:`tshark -r <文件>.pcap -Y "icmp.type==3 && icmp.code==4" -T fields -e frame.number -e ip.src -e ip.dst -e icmp.mtu`
2. 找到被卡的数据流:`tshark -r <文件>.pcap -Y "ip.flags.df==1 && tcp.len>1400" -T fields -e frame.number -e ip.dst -e tcp.len`,结合重传过滤器 `tcp.analysis.retransmission && tcp.len>1400` 确认卡死位置。
3. 各跳实测:Windows `ping -f -l <大小> <目标>`(载荷大小=MTU−28)逐跳逼近;或 `pathping`。
4. 复现黑洞:确认第 1 步的 ICMP 来源设备与其入方向 ACL 是否放行 ICMP。

## 处置建议

出口/隧道设备可按实际封装开销调整 TCP MSS 或接口 MTU。传统 IPv4 PMTUD 需要 ICMP 3/4 反馈可达；PLPMTUD 则可在不依赖 ICMP 交付的情况下探测路径 MTU。IPv6 另见 Packet Too Big 专题，不能沿用 IPv4 的 ping DF 测试方式。

来源：[RFC 1191](https://www.rfc-editor.org/info/rfc1191/)；[RFC 4821](https://www.rfc-editor.org/info/rfc4821/)；[RFC 8201](https://www.rfc-editor.org/info/rfc8201/)。
