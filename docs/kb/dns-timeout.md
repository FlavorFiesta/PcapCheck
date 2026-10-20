---
title: DNS 查询重试后无应答
rule_ids: [S19_DNS_TIMEOUT]
protocols: [DNS, UDP, TCP]
symptoms: 首次访问一直等待、域名解析超时、同一查询反复发送
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S19 按查询端点、事务 ID、域名和记录类型识别重复查询；至少两次查询且在抓包尾部留有观察时间，仍未见对应响应时提示疑似超时。它与已收到 SERVFAIL/NXDOMAIN 的 R03、已收到慢响应的 S10 是不同场景。

## 排查步骤

用 `dns.id`、`dns.qry.name`、`dns.qry.type`、源/目的地址和端口核对每次问答；确认客户端抓包确实覆盖响应方向。对照 DNS 服务器入口与出口抓包，判断请求未到、服务器无应答还是回包未到客户端。若收到设置 TC 位的 UDP 响应，继续检查 TCP 53 的重试与结果；若采用 DoH/DoT，加密流量需要终端或递归服务器日志才能判断 DNS 事务。

## 处置建议

检查递归服务负载、上游转发、UDP/TCP 53 策略和丢包；不要把无应答直接归因为域名不存在。对重复事务 ID、源端口重用和抓包结束边界保留疑似级别。

来源：[RFC 1035：DNS](https://www.rfc-editor.org/info/rfc1035/)；[RFC 7766：DNS over TCP](https://www.rfc-editor.org/info/rfc7766/)。

## 正常反例

只看到一次查询且抓包立即结束，无法判断是否超时；某些程序会并行访问多个 DNS 服务器，必须分别核对端点与事务。
