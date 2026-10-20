---
title: DNS 解析失败(SERVFAIL / NXDOMAIN)
rule_ids: [R03_DNS_FAILURE]
protocols: [DNS]
symptoms: 部分网站打不开、内网系统域名解析失败、报「无法找到服务器」
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

DNS 响应以 RCODE 报告解析结果:rcode=2(SERVFAIL)表示递归服务器内部失败,常见于权威服务器故障、上游链路问题或 DNSSEC 校验失败;rcode=3(NXDOMAIN)表示权威侧确认域名不存在,常见于域名拼写错误、已下线,或内网专用域名被发到公网 DNS。

## 判断标准

报文快速分析工具规则 R03(确诊):响应帧 `dns.flags.rcode` 为 2 或 3。rcode=3 时重点看 qname 是否属于内网域;rcode=2 时同一域名反复失败说明递归链路故障。

## 报文证据特征

- 过滤器 `dns.flags.rcode==3` 或 `dns.flags.rcode==2`;响应帧 `dns.flags.response==1`。
- 失败响应中 `dns.qry.name` 与请求一致但 answers 计数为 0。
- NXDOMAIN 前若出现同一 qname 的多次重复查询,说明客户端在重试。

## 排查步骤

1. 列出失败查询:`tshark -r <文件>.pcap -Y "dns.flags.rcode==2 || dns.flags.rcode==3" -T fields -e frame.number -e dns.qry.name -e dns.flags.rcode -e ip.src -e ip.dst`
2. 区分内网域与公网域失败:`tshark -r <文件>.pcap -Y "dns.flags.rcode==3" -T fields -e dns.qry.name` 检查后缀。
3. 向其他递归服务器对比测试:`tshark -i <网卡> -f "udp port 53" -Y "dns.flags.rcode!=0" -c 20`(配合 nslookup 指定 223.5.5.5)。
4. rcode=2 时抓递归服务器出口,确认其到权威的查询是否超时。

## 处置建议

先核对域名拼写与存活;内网专用域名必须由内网 DNS 服务(或转发/条件转发)应答,客户端配置改指内网 DNS;SERVFAIL 检查递归服务器负载、上游与 DNSSEC 时钟;必要时增加本地缓存与备用 DNS。
