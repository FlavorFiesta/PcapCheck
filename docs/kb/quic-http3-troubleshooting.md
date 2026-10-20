---
title: QUIC 与 HTTP/3 建连排查
rule_ids: []
protocols: [QUIC, HTTP3, UDP, TLS]
symptoms: UDP 443 服务连接慢、浏览器从 HTTP/3 回退到 HTTP/2、移动网络切换时断流
severity: 中
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断范围

当前版本没有 QUIC 专用自动规则，本文供人工排查。QUIC 在 UDP 上实现加密连接与多路复用；仅凭 TCP 重传、HTTP 5xx 或 TLS alert 规则不能覆盖 HTTP/3 的传输异常。即使可看到部分包头和连接 ID，应用请求及多数错误细节仍需解密或终端日志。

## 排查步骤

在客户端与服务端同时间窗抓 UDP 443，核对是否出现 Initial、握手后持续流量、路径切换与重复建连。用浏览器网络日志确认是否确实协商 HTTP/3，还是已回退 HTTP/2；测试时同时检查 UDP 出入方向、防火墙/代理策略与 NAT 映射寿命。若同一业务在 TCP 443 正常而 UDP 443 无回包，优先核对 UDP 路径，但仍需双端证据判断断点。

对空闲一段时间后断流的情况，核对双方协商的 idle timeout、NAT 空闲超时与客户端重建行为。不要把正常连接迁移、密钥更新或主动关闭直接判为故障。

来源：[RFC 9000：QUIC](https://www.rfc-editor.org/info/rfc9000/)；[RFC 9114：HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)。
