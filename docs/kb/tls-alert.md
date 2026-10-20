---
title: TLS 告警:证书过期 / 握手失败
rule_ids: [R04_TLS_ALERT]
protocols: [TLS]
symptoms: HTTPS 打不开、客户端报证书错误、握手失败、接口调用 443 不通
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

TLS 握手或会话中任一方发现不可恢复的错误,即发送 alert 消息并终止连接。desc=45(certificate_expired)为证书过期;desc=40(handshake_failure)多为加密套件/TLS 版本不匹配或被中间设备拦截;desc=112(unrecognized_name)多为 SNI 与服务端虚拟主机配置不符;42/43/44/46 为证书校验类错误。

## 判断标准

当前 R04 依据可解码的 `tls.alert_message.desc` ∈ {40,41,42,43,44,45,46,112} 命中，没有按 alert level 过滤；报告只能说明抓到了这些告警描述，不能单凭它确诊证书过期或握手根因。TLS 1.3 的后续告警通常加密，未解密抓包看不到描述；TLS 1.3 的 level 字段也不应按旧版语义直接解释。

## 报文证据特征

- 过滤器 `tls.alert_message.desc==45`(证书过期)或 `tls.alert_message.desc==40` 等。
- alert 帧前一般能看到 `tls.handshake.type==1`(ClientHello),可从中取 `tls.handshake.extensions_server_name` 核对访问的域名。
- 证书过期还可直接查服务端证书:`tls.handshake.type==11` 后在 Certificate 详情看 Not After 时间。
- 告警由哪一方发出很关键:客户端发出多为证书/信任问题,服务端发出多为版本与套件不匹配。

## 排查步骤

1. 列出告警帧:`tshark -r <文件>.pcap -Y "tls.alert_message" -T fields -e frame.number -e ip.src -e ip.dst -e tls.alert_message.level -e tls.alert_message.desc`
2. 提取告警关联的访问域名:`tshark -r <文件>.pcap -Y "tls.handshake.type==1" -T fields -e frame.number -e tls.handshake.extensions_server_name`
3. 在线取服务器证书链检查有效期:`tshark -i <网卡> -f "tcp port 443" -Y "tls.handshake.type==11" -V`(配合浏览器或 openssl s_client 复核)。

## 处置建议

desc=45/42/44:更新服务器证书与证书链、校对系统时间。desc=40:核对客户端与服务端 TLS 版本与套件策略,排查中间 TLS 解密设备。desc=112:修正 SNI/虚拟主机名。内网自签证书需在客户端统一信任。

来源：[RFC 8446 TLS 1.3](https://www.rfc-editor.org/info/rfc8446/)。
