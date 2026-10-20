---
title: HTTP 5xx 服务端错误集中
rule_ids: [S12_HTTP_5XX]
protocols: [HTTP]
symptoms: 页面偶发报错、接口返回 500/502/504、运维群报障集中于某系统
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

5xx 是服务端侧错误码:500 应用内部异常;502/504 是反向代理/网关在后端拿不到结果(后端宕机、超时、连接拒绝);503 常为限流或主动摘除。抓包只能定位「错在服务端侧、哪些请求、什么频率」,根因要结合应用日志与上游依赖判断。

## 判断标准

报文快速分析工具规则 S12(疑似):HTTP 响应状态码 ≥500 的数量 ≥3 次,统计各码占比。过滤器:`http.response.code>=500`。

## 报文证据特征

- 过滤器 `http.response.code>=500`,字段 `http.response.code`、`http.host`、`http.request.uri`。
- 502/504 响应体常含 nginx/Apache/网关标识,说明错误由代理层产生而非应用本身。
- 504 前常见请求发出后长时间无响应(对照 `frame.time_relative`);502 可能伴随同主机新连接被 RST(联动 R02)。

## 排查步骤

1. 列出全部 5xx 请求:`tshark -r <文件>.pcap -Y "http.response.code>=500" -T fields -e frame.number -e frame.time_relative -e ip.dst -e http.host -e http.request.uri -e http.response.code`
2. 按状态码与 URI 聚类:`tshark -r <文件>.pcap -Y "http.response.code>=500" -T fields -e http.response.code -e http.host | sort | uniq -c | sort -rn`
3. 测量失败请求的响应时延,504 型看是否集中在固定超时值(如 30s/60s)。
4. 结合时间点查应用日志、数据库/缓存健康度;502/504 优先核对反向代理 upstream 配置与后端进程存活。

## 处置建议

500/503:修复应用异常与限流配置,扩容热点实例。502/504:恢复后端连接(进程、端口、健康检查),调合理超时与重试策略。抓包层面联动 R02(RST)、R07(零窗口)、S11(握手慢)判断是否由网络/容量问题诱发。
