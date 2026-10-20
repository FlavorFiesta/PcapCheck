---
title: DHCP NAK / DECLINE:地址获取失败
rule_ids: [R06_DHCP_FAILURE]
protocols: [DHCP]
symptoms: 终端拿不到地址、提示「无法获取 IP」、拿到 169.254.x.x、重连后地址失效
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

DHCP 四步(DISCOVER→OFFER→REQUEST→ACK)中两类失败信号:NAK(消息类型 6)表示服务器拒绝客户端的 REQUEST/续约,常见于请求的地址已不在本作用域、租约表冲突、服务器迁移或存在私接 DHCP 抢答;DECLINE(消息类型 4)表示客户端检测到 OFFER 的地址已被占用(ARP 探测冲突)而主动拒绝,指向静态 IP 冲突或私接设备。

## 判断标准

报文快速分析工具规则 R06(确诊):出现 `dhcp.option.dhcp==6`(NAK)或 `dhcp.option.dhcp==4`(DECLINE)。NAK 关注其来源服务器 IP;DECLINE 后正常流程应重新 DISCOVER 换地址。

## 报文证据特征

- 过滤器 `dhcp.option.dhcp==6`(NAK)或 `dhcp.option.dhcp==4`(DECLINE)。
- NAK 帧的 `ip.src` 即拒绝服务器,应与 `dhcp.option.dhcp_server_id`(Option 54)一致。
- 客户端侧以 `udp.dstport==68` 的广播收包;反复 DISCOVER(`dhcp.option.dhcp==1`)说明未获地址,最终自配 169.254/16。

## 排查步骤

1. 还原完整四步过程:`tshark -r <文件>.pcap -Y "dhcp" -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e dhcp.option.dhcp -e dhcp.option.requested_ip -e dhcp.option.dhcp_server_id`
2. 确认网段内 DHCP 服务器:`tshark -r <文件>.pcap -Y "dhcp.option.dhcp==2 || dhcp.option.dhcp==5" -T fields -e dhcp.option.dhcp_server_id`；多个 server_id 可能来自合法冗余服务器，需与授权清单、作用域及中继配置比对后才能判断是否私接。

参考：[RFC 2131 DHCP](https://www.rfc-editor.org/info/rfc2131/)。
3. 现场复测:`tshark -i <网卡> -f "udp port 67 or udp port 68"` 后执行 `ipconfig /release && ipconfig /renew`。

## 处置建议

NAK:核对客户端请求网段与服务器作用域/中继(ip helper)配置,清理旧租约,排查作用域耗尽与迁移遗留。DECLINE:排查静态 IP 冲突与私接设备,必要时缩短租约、开启地址冲突检测。网络侧启用 DHCP Snooping 只允许合法端口提供 OFFER。
