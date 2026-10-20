---
title: HTTP/2 流重置与连接错误
rule_ids: [S26_HTTP2_STREAM_ERROR]
protocols: [HTTP2, TCP, TLS]
symptoms: 请求被取消、接口偶发失败、代理报告流级错误
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S26 对可见 HTTP/2 RST_STREAM 和 GOAWAY 的非零错误码给出疑似提示，并排除 NO_ERROR 和常见的 CANCEL。它表示流或连接出现协议层中止线索，不证明网络路径本身异常。浏览器在切换页面、取消请求或重试时也会正常产生流重置。

## 排查步骤

按 `http2.streamid` 关联 HEADERS、DATA、RST_STREAM、GOAWAY，再核对服务端及代理日志中的错误码和请求 ID。区分单条流失败与整条连接关闭：单流失败多查应用、超时和资源限制；整连接失败再查代理、服务端重启、HTTP/2 参数和 TCP/TLS 断开。请求只有部分 DATA 时，应确认内容是否因加密而不可见。

HTTPS 上的 HTTP/2 未解密时，通常看不到这些帧字段。没有 HTTP/2 解码结果不能推断不存在流级错误；需要终端会话密钥或服务器日志辅助。若同时出现 5xx，结合请求响应链判断谁先出错。

来源：[RFC 9113：HTTP/2](https://www.rfc-editor.org/info/rfc9113/)。

正常反例：客户端主动取消已过期请求时可能发送 RST_STREAM；先对照业务是否真的失败。
