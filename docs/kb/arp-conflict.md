---
title: ARP IP 地址冲突
rule_ids: [R05_ARP_CONFLICT]
protocols: [ARP]
symptoms: 时通时断、网关时有时无、部分终端被踢下线、交换机报 IP 冲突日志
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

同一 IPv4 地址由多个 MAC 宣告时，终端的 IP→MAC 邻居映射可能反复变化，造成流量时断时续。这不等同于交换机的 MAC→端口漂移。常见原因有重复静态配置、虚拟机克隆或 ARP 欺骗；也需排除网关高可用切换、代理 ARP 和计划内迁移。

## 判断标准

报文快速分析工具规则 R05(确诊):ARP 报文中同一发送 IP(`arp.src.proto_ipv4`)由 ≥2 个不同 MAC(`arp.src.hw_mac`)宣告。Wireshark 自带检测:`arp.duplicate-address-detected==1`。

## 报文证据特征

- 过滤器 `arp.src.proto_ipv4==<冲突IP> && arp.opcode==2`,可见两个不同源 MAC。
- 免费 ARP(gratuitous):`arp.isgratuitous==1`,请求包内目标 IP 等于发送者 IP。
- Wireshark 对冲突免费 ARP 打标记:`arp.duplicate-address-detected==1` / `arp.duplicate-address-frame==1`。

## 排查步骤

1. 找出冲突 IP 与参与 MAC:`tshark -r <文件>.pcap -Y "arp.duplicate-address-detected==1 || arp.isgratuitous==1" -T fields -e frame.number -e arp.src.proto_ipv4 -e arp.src.hw_mac -e eth.src`
2. 统计各 MAC 应答次数定位「强势方」:`tshark -r <文件>.pcap -Y "arp.opcode==2" -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort | uniq -c | sort -rn`
3. 在接入/汇聚交换机查 MAC 地址表找到 MAC 所在端口,顺着跳线定位物理设备。

## 处置建议

先定位并隔离冲突源(下电或改地址),恢复网关 MAC 表;随后收敛:接入层启用 DAI(Dynamic ARP Inspection)与 IP-MAC 绑定,关键地址(网关、服务器)做静态绑定,并核查是否存在私接 DHCP/路由器。冲突源修复后,在网关主动发一次免费 ARP 刷新全网终端缓存,可立即恢复通信,不必等待缓存老化。
