---
title: 无线漫游掉线专题
rule_ids: []
protocols: [802.11, EAPOL, ARP, DHCP, ICMP]
symptoms: 移动中断网几秒、漫游后视频会议卡断、终端乒乓重连、跨 AP 切换丢包
severity: 高
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

漫游 = 终端断开旧 AP、向新 AP 发 Reassociation Request 重新关联;期间上行数据必然中断。开销主要在三处:扫描信道、重新关联、802.1X 网络重跑完整 EAP 认证(秒级,非 802.1X 网络用缓存密钥只需毫秒级四次握手)。漫游迟缓、失败或在新旧 AP 间来回震荡(乒乓)都会被用户感知为「掉线」。

## 判断标准(报文特征)

- 空口抓包需监听模式网卡并锁定信道。Deauth:`wlan.fc.type_subtype==0x0c`;Disassoc:`wlan.fc.type_subtype==0x0a`;漫游标志:Reassociation Request `wlan.fc.type_subtype==0x02`。
- 正常漫游只有一次 reassoc;短时间内多个 deauth 或反复 reassoc 到不同 `wlan.bssid` 即乒乓。
- 信号劣化佐证:`wlan_radio.signal_dbm < -65` 起逐步变差;空口重传 `wlan.fc.retry==1` 占比升高。

## 报文证据特征

- 漫游耗时 = Reassoc Request 到新 AP 发出 EAPOL Key 第 4 次握手(或 ARP/DHCP 恢复)的间隔。
- 漫游后 DHCP 单播续约(`dhcp.option.dhcp==3`)正常;若重新走完整 DISCOVER,说明网关侧认为终端已下线。

## 排查步骤

1. 管理帧时间线:`tshark -r <文件>.pcap -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a || wlan.fc.type_subtype==0x02" -T fields -e frame.number -e frame.time_relative -e wlan.sa -e wlan.bssid -e wlan.fc.type_subtype`
2. 信号与重传:`tshark -r <文件>.pcap -Y "wlan_radio.signal_dbm" -T fields -e frame.number -e wlan.sa -e wlan_radio.signal_dbm -e wlan_radio.data_rate`
3. 有线侧核对断网窗口:在接入交换机镜像口抓 `arp || icmp`,与空口漫游时间对齐。

## 处置建议

调优漫游触发(min-RSSI、802.11k/v 引导)避免「抱死弱信号」;治理乒乓:检查 AP 间重叠覆盖与功率均衡;802.1X 网络开启 PMK 缓存/OKC 缩短重认证;剔除终端侧激进省电策略。复测时用iperf+漫游路径全程空口抓包。
