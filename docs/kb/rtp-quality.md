---
title: RTP 丢包、抖动与单向媒体排查
rule_ids: [P15_RTP_ONEWAY]
protocols: [RTP, RTCP, SIP, UDP]
symptoms: 通话杂音、断续、延迟、单向无声、会议画面卡顿
severity: 中
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断范围

当前 P15 只提示抓包点可见的单向 RTP，不自动计算丢包率和抖动。要评估媒体质量，需按同一 SSRC 的 RTP 序号、时间戳和到达时间计算丢包、乱序、抖动，并结合 RTCP 接收报告与端点抖动缓冲。若抓包点只看见一个方向，不能把它当成真实单向音频。

## 排查步骤

先看 SIP/SDP 协商的媒体地址、端口和方向属性，再在双方媒体路径分别抓包。核对 RTP 序号缺口、接收端 RTCP 丢包和抖动，以及双端 RTP 是否出现在相同时间窗。区分短时拥塞、Wi-Fi 空口重传、NAT/ALG 改写和编解码协商问题；信令 200 OK 只能说明会话接受，无法证明媒体已经双向通畅。

静音抑制、保留音乐、单向视频或一侧主动不发媒体可能是业务正常行为。除帧级证据外应结合用户报告的故障时间、SBC 媒体统计和终端日志。

来源：[RFC 3550：RTP](https://www.rfc-editor.org/info/rfc3550/)；[Wireshark：RTP Statistics](https://wiki.wireshark.org/RTP_statistics)。
