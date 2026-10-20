---
title: TCP 零窗口持续:接收方应用处理不过来
rule_ids: [R07_ZERO_WINDOW]
protocols: [TCP]
symptoms: 数据传输周期性停顿、导出/同步任务奇慢、服务响应超时
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

TCP 靠接收窗口做流控。接收端应用取走数据的速度跟不上时,内核缓冲堆积,通告窗口缩至 0(zero window);发送端停止发数据并周期性发零窗口探测。这不是链路问题,而是接收方(或其下游依赖)处理能力不足,典型于文件服务、备份任务、代理/中间件缓冲打满的场景。

## 判断标准

报文快速分析工具规则 R07(确诊):`tcp.analysis.zero_window` 帧 ≥3,或 `tcp.analysis.window_full` 帧 ≥5,或现象持续 ≥3 秒。window_full 是发送方视角——窗口已被对端通告值打满。

## 报文证据特征

- 接收方回包 `tcp.window_size_value==0`(过滤器 `tcp.analysis.zero_window`)。
- 后续接收方随应用消费发 `tcp.analysis.window_update` 窗口恢复,若长期无 update 则应用已停滞。
- 发送方周期性探测:小包(`tcp.len==0`)间隔约等于 RTO,伴随 `tcp.analysis.keep_alive` 时需区分。

## 排查步骤

1. 定位零窗口所在流与方向:`tshark -r <文件>.pcap -Y "tcp.analysis.zero_window || tcp.analysis.window_full" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.stream -e tcp.window_size_value`
2. 看现象持续时长与窗口恢复速度:`tshark -r <文件>.pcap -Y "tcp.stream==<N> && (tcp.analysis.zero_window || tcp.analysis.window_update)" -T fields -e frame.number -e frame.time_relative -e tcp.window_size_value`
3. 到接收端主机排查:进程 CPU/内存/磁盘 IO、连接数、下游依赖(数据库、后端存储)是否阻塞。

## 处置建议

优先解决接收方瓶颈:扩容应用实例或线程池、修复死锁/慢查询、增加缓冲与异步化。若接收端是代理/中间件,检查其背压与下游限流配置。抓包侧同时观察 R01/R14,确认是否叠加链路问题;避免盲目调大 TCP 缓冲掩盖应用问题。
