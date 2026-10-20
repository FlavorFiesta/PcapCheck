---
title: 代理 / VPN 场景抓包要点专题
rule_ids: [S09_MTU_BLACKHOLE, S11_HANDSHAKE_RTT]
protocols: [TCP, TLS, UDP, ICMP, GRE]
symptoms: VPN 内部分系统打不开、走代理后抓不到真实地址、大文件传输停滞、建连慢
severity: 中
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

代理/VPN 改变了报文形态与可见性:VPN 对外层加封装(GRE `ip.proto==47`、UDP 封装等)导致 MTU 缩水;代理会在代理点终结 TCP(系统代理)或只是改写转发(透明代理),抓包看到的对端不一定是真实服务器。DNS 也在代理下失真——本地查询可能被代答。抓包前先明确「抓的是哪一层」。

## 判断标准(报文特征)

- 双端同时抓包对齐:用绝对时间 `frame.time_epoch` 比对两端同一报文,判断丢包发生在隧道内还是隧道外。
- MTU 缩水:内层抓到 `icmp.type==3 && icmp.code==4` 或大包重传(`tcp.analysis.retransmission && tcp.len>1300`)。
- 握手慢:SYN-ACK 的 `tcp.analysis.ack_rtt > 1`,若客户端侧 SYN-ACK 慢、服务端侧正常,时延在代理/隧道路径上。

## 报文证据特征

- 透明代理痕迹:SYN-ACK 的 `ip.ttl` 与服务端系统不符、SYN-ACK 先于路由预期到达、RST 帧来源 TTL 异常(联动 R02)。
- 系统代理痕迹:客户端抓包中 TLS ClientHello 的 SNI 是代理地址,或 TCP 直接与本地代理进程端口建连。
- VPN 内 ping 通但 TCP 不通:典型 MTU 黑洞或安全策略只放 ICMP。

## 排查步骤

1. 两端同时抓包:`tshark -i <网卡> -w client.pcap -f "host <服务端IP>"` 与服务端同步执行,用 `frame.time_epoch` 对齐。
2. 核对 MTU 链路:客户端 `ping -f -l 1372 <VPN网关>` 逐步逼近,同时在隧道口抓 `icmp.type==3`。
3. 握手分层计时:`tshark -r client.pcap -Y "tcp.flags.syn==1" -T fields -e frame.number -e frame.time_relative -e tcp.stream -e tcp.analysis.ack_rtt`
4. DNS 复核:绕开代理直接 `nslookup <域名> <真实DNS>` 对比本地代答结果。

## 处置建议

VPN 出口做 MSS Clamping 并放行 ICMP 3/4;明确代理模式并统一抓包口径(在代理两端分别确认);对 QUIC(UDP 443)被代理阻断导致的回退,提前在策略中明确。报告结论需注明抓包点位于隧道内层还是外层。
