---
title: DNS 响应慢(问答间隔过长)
rule_ids: [S10_DNS_SLOW]
protocols: [DNS]
symptoms: 打开网页首字节慢、内网系统偶发卡顿、应用冷启动慢
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

DNS 正常解析在局域网内毫秒级完成。问答间隔超过 1 秒,通常源于递归服务器上游链路慢、权威服务器响应慢、DNSSEC 校验开销,或查询丢包后依赖客户端重试兜底。应用每次冷解析都被拖长,表现为「首次访问慢、刷新后快(命中缓存)」。

## 判断标准

报文快速分析工具规则 S10(疑似):同一 (流, 查询名) 内查询帧与其后首个响应帧间隔 >1.0 秒,统计值给出最大/平均时延与慢查询样本。过滤器辅助:`dns.time > 1`。

## 报文证据特征

- 响应帧 Wireshark 自带「Response time」字段:`dns.time > 1` 直接筛出慢响应。
- 慢响应对应的查询若在同一流内出现两次,说明丢了首查询或服务器超时后客户端重试。
- 需排除抓包点影响的时延:客户端侧抓包测得的间隔最真实。

## 排查步骤

1. 列出慢响应与耗时:`tshark -r <文件>.pcap -Y "dns.time > 1" -T fields -e frame.number -e dns.qry.name -e dns.time -e ip.src`
2. 看是否存在重复查询(丢包重试):`tshark -r <文件>.pcap -Y "dns.flags.response==0" -T fields -e frame.number -e dns.qry.name -e dns.id` 按 dns.id 找同 ID 多次请求。
3. 对比内外 DNS:`tshark -r <文件>.pcap -z dns,tree` 看按服务器的响应分布,再分别对内网 DNS 与公共 DNS(223.5.5.5)用 nslookup 计时复测。
4. 在递归服务器上确认到上游的链路时延与负载。

## 处置建议

优化递归服务器上游与负载;部署/扩大本地 DNS 缓存与常用域名预取;为关键业务配置就近的备用 DNS;处理查询丢包(链路质量或服务器限速)。若只有特定权威域慢,联系该域管理员或调整转发。
