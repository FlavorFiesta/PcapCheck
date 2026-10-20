---
title: VXLAN Overlay 典型故障专题
rule_ids: [R05_ARP_CONFLICT, S09_MTU_BLACKHOLE]
protocols: [VXLAN, UDP, ARP, ICMP, BGP]
symptoms: 跨主机同网段不通、大包不通小包通、虚机迁移后邻居错乱、部分 VNI 不通
severity: 中
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

VXLAN 把二层帧封进 UDP 4789,由 VTEP 打外层头,underlay 负责转发。典型故障:两端 VTEP 的 VNI 与 VLAN 映射不一致(单边通)、underlay MTU 预留不足(overlay 内 1500 的包加 50~58 字节封装后被丢,ICMP 3/4 又被吞即 MTU 黑洞)、EVPN MAC/IP 路由未同步或 MAC 漂移处理异常、ARP 抑制(Arp Suppression)表错误导致泛洪缺失。

## 判断标准(报文特征)

- 在 VTEP 上游抓包看外层:`udp.port==4789`,字段 `vxlan.vni` 核对两端 VNI 是否一致。
- MTU:underlay 抓到 `icmp.type==3 && icmp.code==4`;overlay 内 `tcp.len` 接近 1460 的流反复重传。
- EVPN 控制面:`bgp.type==2`(UPDATE)中 `bgp.evpn.nlri.rt` 路由类型(2=MAC/IP 通告、5=IP 前缀);MAC 漂移看 MAC Mobility 扩展团组的序列号(`bgp.ext_com_evpn.mmac.seq`)是否持续增长。

## 报文证据特征

- 同 VNI 两端互 ping 通、TCP 大包不通:MTU 类;互 ping 都不通但同宿主机内通:VNI/映射类。
- overlay 内抓到同一 IP 双 MAC 应答 ARP:真冲突或迁移残留(联动 R05,需结合 `bgp.ext_com_evpn.mmac.flags.sticky`)。
- 外层 UDP 校验和/源端口随流变化属正常,勿误判。

## 排查步骤

1. 双端同时抓 underlay:`tshark -i <网卡> -w vtep1.pcap -Y "udp.port==4789" -T fields -e frame.number -e ip.src -e ip.dst -e vxlan.vni`(配合 -w 落盘)。
2. 核对 VNI 与内层:`tshark -r vtep1.pcap -Y "vxlan" -T fields -e vxlan.vni -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort | uniq -c`。
3. 测 underlay MTU:VTEP 之间 `ping -f -l 1472 <对端VTEP>`,不通则逐档下调定位。
4. 控制面对账:两 VTEP 上分别抓 `bgp`,比对 `bgp.evpn.nlri.rt==2` 的 MAC/IP 通告是否互相收到。

## 处置建议

统一 VNI/VLAN 映射与 MTU(underlay ≥1550 或开启 VTEP 分片/MSS Clamping 并放行 ICMP 3/4);EVPN 场景核对 RT 导入导出与 BGP 邻居;MAC 漂移风暴则排查虚机迁移/双挂;ARP 抑制异常先回退泛洪验证转发面。
