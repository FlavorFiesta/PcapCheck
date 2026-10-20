---
title: TCP 乱序比例异常
rule_ids: [S08_OUT_OF_ORDER]
protocols: [TCP]
symptoms: 长连接吞吐不稳、偶发卡顿、大流量传输性能低于链路标称
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

IP 网络不保证按序到达。报文经不等价路径(ECMP/多链路哈希不同)、设备 QoS 重排序、或丢包后重传补位,都会造成接收端乱序。少量乱序无碍;比例偏高会触发接收端大量重复 ACK 与不必要重传,吞吐量显著下降。

## 判断标准

报文快速分析工具规则 S08(疑似):乱序帧 ≥5 且占 TCP 帧比例 ≥10%,过滤器 `tcp.analysis.out_of_order`。注意与重传区分:乱序帧是「后发先至」,重传是「同序号再发一次」。

## 报文证据特征

- `tcp.analysis.out_of_order` 是 Wireshark 根据同方向下一预期序号等条件给出的疑似乱序标记；当前段的序号小于下一预期序号，且需结合重传时序判断。
- 伴随 `tcp.analysis.duplicate_ack` 增多；若出现 `tcp.analysis.lost_segment`，还需排除抓包起点、镜像丢包和单向采集，不可直接确认为真实链路丢包。

来源：[Wireshark TCP Analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)。
- 乱序方向固定单向:多为路径不对称(上行/下行走不同链路)。

## 排查步骤

1. 统计乱序分布:`tshark -r <文件>.pcap -Y "tcp.analysis.out_of_order" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.stream`
2. 按流占比排序:`tshark -r <文件>.pcap -q -z conv,tcp` 结合乱序流号,确认集中在哪些会话。
3. 与丢包比对:`tshark -r <文件>.pcap -Y "tcp.analysis.lost_segment" -T fields -e frame.number | wc -l` 判断是纯乱序还是丢包型乱序。
4. 核对路径:是否 ECMP/聚合链路哈希、QoS 重排序、无线与有线混跑;在路径两端同时抓包比对到达顺序。

## 处置建议

等价路由场景考虑按流哈希(基于五元组)保证单流同路径;排查链路切换/震荡日志;QoS 设备调整重排序策略。纯乱序可先观察,伴随丢包优先处理链路质量;持续恶化再复核 R01/R14。
