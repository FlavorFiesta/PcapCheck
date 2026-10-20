---
title: RTP 单向音频(仅一个方向有媒体流)
rule_ids: [P15_RTP_ONEWAY]
protocols: [RTP, SIP]
symptoms: 通话听不到对方声音、一方静音、录音只有一半、视频会议单边黑屏
severity: 低(潜在)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

VoIP 语音走 RTP 双向媒体流。任一方向缺失即单向音频:对端未回送 RTP,或回包被路径丢弃。常见成因:防火墙/ALG 拦截 UDP 媒体端口、NAT 对称限制、SIP 信令 SDP 里写的地址不可达(内网地址被写进公网信令)、或抓包点不完整造成假象。

## 判断标准

报文快速分析工具规则 P15(潜在):按 UDP 流聚合带 `rtp.ssrc` 的帧,某流 RTP 只出现在一个方向且帧数 ≥10。SIP 通话先看信令,再看媒体:`sip.Method=="INVITE"` 与 `sdp.media` 确认协商端口。

## 报文证据特征

- 单向 RTP:过滤器 `rtp.ssrc==<SSRC>` 命中帧的 `ip.src` 全部相同,反方向同端口对无 RTP。
- 缺失方向的呼叫端口持续无包:对端防火墙丢弃;若对端回的是 ICMP unreachable,则是端口不可达/地址错误。
- 信令正常(200 OK 双向到达)而媒体单向:问题定位在媒体路径 NAT/防火墙,而非 SIP 服务器。

## 排查步骤

1. 列出 RTP 流与方向:`tshark -r <文件>.pcap -Y "rtp" -T fields -e rtp.ssrc -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e rtp.p_type | sort | uniq -c`
2. 核对 SDP 协商端口:`tshark -r <文件>.pcap -Y "sdp.media" -T fields -e frame.number -e sdp.connection_info -e sdp.media -e sdp.media_attr` 对照实际媒体端口是否一致。
3. 在缺失方向的两端(话机侧与出口防火墙侧)分别抓包,确认包「没发出」还是「被丢弃」。
4. 检查防火墙 SIP ALG 是否改写 SDP 造成端口/地址错乱。

## 处置建议

关闭或正确配置 SIP ALG;媒体路径放行协商的 RTP/RTCP 端口段;NAT 环境启用 STUN/ICE 或固定媒体地址出口;SIP 服务器侧修正对外通告地址。复测时确保抓包点覆盖双向(交换机镜像双向)。
