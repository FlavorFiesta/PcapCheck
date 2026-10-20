---
title: TCP 握手 RTT 异常(SYN→SYN-ACK 过慢)
rule_ids: [S11_HANDSHAKE_RTT]
protocols: [TCP]
symptoms: 建连慢、每次请求都要等、高峰期偶发超时、接口首次调用慢
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

三次握手中 SYN 到 SYN-ACK 的间隔近似等于「服务端处理时延 + 路径往返 RTT」。超过 1 秒通常说明:服务端过载(accept 队列堆积、CPU 打满)、路径时延高(跨地域/绕行)、或首个 SYN 丢包后客户端重传兜底(SYN 重传补位时握手自然变慢一倍以上)。

## 判断标准

报文快速分析工具规则 S11(疑似):SYN-ACK 帧的 `tcp.analysis.ack_rtt` > 1.0 秒(仅对带 SYN 的帧统计)。同屏对照 `tcp.analysis.initial_rtt` 可复核。若 SYN-ACK 之前出现多个 SYN(`tcp.flags.syn==1 && !tcp.flags.ack==1` 同流多次),则是丢包重传型。

## 报文证据特征

- SYN-ACK 帧过滤器:`tcp.flags.syn==1 && tcp.flags.ack==1`,字段 `tcp.analysis.ack_rtt` 显示距 SYN 的秒数。
- 丢包型:同流首个 SYN 后隔约 1s/2s/4s(指数退避)再发 SYN,`tcp.analysis.rto` 不标记 SYN,需看重发。
- 服务端过载型:RTT 稳定偏大且无 SYN 重传,常伴随 R02(RST)或零窗口。

## 排查步骤

1. 列出慢握手:`tshark -r <文件>.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1 && tcp.analysis.ack_rtt > 1" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.analysis.ack_rtt -e tcp.stream`
2. 检查同流 SYN 重传:`tshark -r <文件>.pcap -Y "tcp.flags.syn==1" -T fields -e frame.number -e frame.time_relative -e tcp.stream -e tcp.flags.ack`
3. 区分故障域:客户端侧抓包慢而服务端侧抓包快→路径问题;两侧都慢→服务端问题;服务端侧看 SYN-ACK 也慢则查 backlog(`ss -lnt` 的 Recv-Q)与负载。

## 处置建议

服务端:扩容/优化 accept 队列与线程模型,查周期性 GC 或定时任务抖动。路径:核对路由绕行、运营商链路质量与中间设备限速。客户端:确认无本地代理强行转发。持续观测 S12/R02 是否同步恶化。
