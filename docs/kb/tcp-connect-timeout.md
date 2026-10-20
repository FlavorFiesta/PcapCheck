---
title: TCP 建连重试后无响应
rule_ids: [S18_TCP_CONNECT_TIMEOUT]
protocols: [TCP]
symptoms: 业务连接超时、客户端只见 SYN、服务端端口看似不可达
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S18 对同一 TCP 流观测到至少两次 SYN，抓包结束前仍有观察时间，却没有 SYN-ACK 或 RST 时提示疑似建连超时。只见一个 SYN 或在最后一帧附近出现 SYN 时不报警，防止截短抓包误判。

## 报文证据与排查

按 `tcp.stream` 检查重发 SYN 的源/目的地址与端口。对端发送 RST 常代表端口拒绝或中间设备代答，与静默无响应不同。客户端只见 SYN，可能是请求未到、回程丢失、目标未监听、策略静默丢弃，也可能是镜像口只复制单向流量；不能单靠一侧抓包确定断点。

在客户端、服务端及必要的策略设备两侧同时抓包，对齐 SYN/SYN-ACK 帧号与时间，再看路由、ACL、NAT、监听端口和防火墙会话日志。抓包时间必须覆盖完整重试窗口。

来源：[RFC 9293：TCP](https://www.rfc-editor.org/info/rfc9293/)；[Wireshark：TCP Analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)。

## 正常反例

如果只抓到客户端方向，或抓包窗口在 SYN 重试后很快结束，不能认为服务端没有答复。连接到拒绝服务端口收到的 RST，是另一个排障分支。
