---
title: 畸形报文与协议解码异常
rule_ids: [U16_MALFORMED]
protocols: [TCP, UDP, IP]
symptoms: Wireshark 显示 Malformed Packet、字段解析中断、应用协议无法解码
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

U16 收集 `_ws.malformed` 或专家层 Malformed 且为 error 的帧。这意味着解码器认为某些字节不符合它当前采用的协议结构，不直接证明网络链路损坏或对端发出了非法报文。

## 排查步骤

先比较 `frame.cap_len` 与 `frame.len` 排除 snaplen 截断，再查看报文是否被错误地按某个端口协议解码。对照同一会话的正常包、服务端实现和协议版本；如果复抓的线侧原始字节仍异常，再检查中间盒改写及对端协议实现。多种流同时出现畸形时，应先检查抓包文件完整性和采集方式。

## 处置建议

保存问题帧、抓包点、解码设置和原始字节供复现。只凭一帧专家告警不要断定硬件误码；真实物理错帧通常会被网卡丢弃，未必能进入普通抓包。与业务失败时间对齐后再排故。

来源：[Wireshark：Checksums](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html)。

## 正常反例

非标准端口、加密载荷或抓包截断导致的解码失败，未必意味着发送端违反协议；应保留原始二进制及解码设置供复核。
