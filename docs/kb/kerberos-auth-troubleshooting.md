---
title: Kerberos 与域认证网络排查
rule_ids: []
protocols: [Kerberos, DNS, TCP, UDP, SMB]
symptoms: 共享认证失败、登录循环、访问域内服务时回退身份验证
severity: 中
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断范围

当前版本没有 Kerberos 专用自动规则，本文是 Windows 办公网的人工排查路径。先确认客户端能解析域控和服务 SPN 所需名称，再看票据请求是否到达 KDC；有 TGS 响应仍不能保证服务端接受票据。网络抓包可定位报文交换阶段，账号、信任关系和服务端权限仍需系统日志判断。

## 排查步骤

按时间关联 DNS、Kerberos AS/TGS、SMB Session Setup 或 HTTP Negotiate。检查域控选择、客户端与服务器时钟、SPN 是否与访问名一致、票据是否过期，以及 TCP/UDP 88 和目标业务端口是否可达。若 SMB 返回登录失败，结合域控安全日志和服务端事件；若返回共享拒绝访问，进一步看共享与文件系统权限。

IPv6/IPv4 双栈环境要核对客户端实际选择的地址和服务端监听，避免只测试一个地址族。不要把所有 NTSTATUS 错误都归入“网络不通”；明确阶段、返回码和抓包点后再下结论。

来源：[Microsoft：SMB 认证与共享连接失败](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/negotiate-session-setup-tree-connect-fails)；[RFC 4120：Kerberos](https://www.rfc-editor.org/info/rfc4120/)。
