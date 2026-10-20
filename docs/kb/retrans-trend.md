---
title: 重传比例偏高趋势
rule_ids: [P14_RETRANS_TREND]
protocols: [TCP]
symptoms: 网络时好时坏、某些时段偶发卡顿、无线区域体验不稳
severity: 低(潜在)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

重传总量未达到「风暴」级别(R01 阈值),但在短时间内窗口化观察,重传占比已明显偏高。这说明链路存在间歇性丢包或劣化趋势,常见于无线信号边缘、线路老化、光衰临界、拥塞初期。它是预警信号:不处理可能发展为 R01 重传风暴。

## 判断标准

报文快速分析工具规则 P14(潜在):按时间序在 TCP 帧上取 10 帧滑动窗口,窗口内重传(`tcp.analysis.retransmission`)占比 >5%,报告占比最高的窗口帧号与整体占比。整体占比 <R01 阈值时,本规则用于暴露「局部恶化」。

## 报文证据特征

- `tcp.analysis.retransmission` 帧在时间轴上成簇出现而非均匀分布,簇内密集。
- 与 RTO 重传联动:`tcp.analysis.rto` 说明丢包未被重复 ACK 覆盖,性质更重。
- 若抓包点在无线旁路,可对照 `wlan.fc.retry==1`(802.11 MAC 层重传)区分空口丢包与有线丢包。

## 排查步骤

1. 全览重传占比:`tshark -r <文件>.pcap -Y "tcp.analysis.retransmission" -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.stream`
2. 看时间分布是否成簇:`tshark -r <文件>.pcap -q -z io,stat,1,"COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission"`
3. 对比 RTO 型与快速重传:`tshark -r <文件>.pcap -Y "tcp.analysis.rto" -T fields -e frame.number | more`
4. 换点复测:分别在客户端侧与上联口抓包,定位丢包发生在接入段还是骨干段。

## 处置建议

按簇出现的时间与位置查链路:无线区域查 AP 信号与干扰;有线查光模块/光衰与端口 CRC 计数;拥塞则联动 P13 处理容量。建立基线后定期复测,连续恶化再升级处置。
