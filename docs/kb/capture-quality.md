---
title: 抓包质量与截断帧判断
rule_ids: [U23_CAPTURE_TRUNCATED]
protocols: [PCAP, TCP, UDP]
symptoms: 解析异常、协议字段缺失、单向报文、疑似重传或校验和错误
severity: 低(潜在)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

U23 在 `frame.cap_len < frame.len` 时提示抓包帧截断。截断是采集证据不完整，并不等于链路上真实报文畸形。报告可能因此缺失应用层字段，甚至将后续重组异常误读为协议故障。

## 排查步骤

1. 用 `tshark -r <文件>.pcap -T fields -e frame.number -e frame.len -e frame.cap_len` 比较原始帧长与捕获长度。
2. 核查抓包 snaplen、接口丢包计数、镜像方向和采集起止时间。只在一个方向看见 SYN 或 DNS 查询时，不能直接推断对端未回复。
3. 本机出口抓包出现校验和异常或超大 TCP 包时，先核查网卡校验和卸载、TSO/GSO，再到线侧或对端复抓确认；校验和在网卡发送前可能尚未填好。
4. 如果镜像设备复制了报文，按五元组、序号、时间和抓包端口识别重复镜像，避免把它算作重传。

## 处置建议

重新以足够 snaplen、双向镜像和连续时间窗采集；报告标注抓包点和采集范围。缺少抓包质量前提时，缺包和无响应规则只能作为疑似线索。

来源：[Wireshark：Checksum Offloading](https://wiki.wireshark.org/CaptureSetup/Offloading)；[Wireshark：TCP Analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)。
