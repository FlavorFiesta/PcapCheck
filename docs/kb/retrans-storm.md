---
title: TCP 重传风暴
rule_ids: [R01_RETRANS_STORM]
protocols: [TCP]
symptoms: 上网卡顿、传输反复停顿、应用超时、下载速度骤降
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

发送端在收到重复 ACK 或重传超时(RTO)后重发已发出的报文段。少量重传属正常拥塞控制;短时间内大量重传说明路径持续丢包,吞吐量会被 TCP 退避算法压垮,表现为业务卡顿、超时。

## 判断标准

报文快速分析工具规则 R01(确诊):重传帧数 ≥10,或重传帧数 ≥5 且占 TCP 帧比例 ≥15%。低于该量级按 P14(趋势)处理。

## 报文证据特征

- Wireshark 显示过滤器 `tcp.analysis.retransmission` 命中;伴随标签 `tcp.analysis.fast_retransmission`(3 个重复 ACK 触发)或 `tcp.analysis.rto`(超时触发)。
- 重传帧的 `tcp.seq` 与此前某帧相同,`tcp.len` 亦相同。
- 常见伴随 `tcp.analysis.lost_segment`(接收端视角的序号缺口)与大量 `tcp.analysis.duplicate_ack`。

## 排查步骤

1. 列出重传帧及五元组:`tshark -r <文件>.pcap -Y "tcp.analysis.retransmission" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.seq`
2. 确认集中在哪几条流:`tshark -r <文件>.pcap -q -z conv,tcp` 对比重传流与总流量。
3. 按秒看重传时间分布:`tshark -r <文件>.pcap -q -z io,stat,1,"COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission"`
4. 判断丢包位置:单一流集中→查该会话两端与路径设备;多流同时爆发→查公共链路(交换机端口 error 计数、无线 RF、带宽占用)。

## 处置建议

先分清「链路丢包」与「对端处理能力不足」(后者常伴随零窗口)。物理链路:检查光衰/网线/端口错包计数;无线:看信号强度与重传率;中间设备:核查防火墙、代理的会话与限流策略。若重传集中在单一会话,重点抓取两端及中间路径复测。
