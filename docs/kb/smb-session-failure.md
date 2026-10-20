---
title: SMB 共享协商与认证失败
rule_ids: [S24_SMB_SESSION_FAILURE]
protocols: [SMB2, SMB3, TCP, Kerberos]
symptoms: 网络共享打不开、提示拒绝访问或登录失败、共享名不存在
severity: 中(疑似)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 判断标准

S24 对 SMB2/3 的 Negotiate、Session Setup 与 Tree Connect 阶段提取 NTSTATUS；只提示明确的拒绝访问、登录失败、共享名不存在和网络名称失效等返回码。`STATUS_MORE_PROCESSING_REQUIRED` 常是认证过程的中间步骤，不能当成最终失败。

## 排查步骤

以 `smb2.cmd`、`smb2.nt_status`、服务器地址和时间线还原流程。Negotiate 未完成时先查 TCP 445、版本/签名/加密策略；Session Setup 失败时检查域控、账号、Kerberos 票据和 SPN；Tree Connect 拒绝访问时核对共享与 NTFS 权限。密码错误、权限不足和共享名错误都可能在同一客户端表现为“打不开”，应以返回码及服务器事件日志区分。

SMB 数据流若已成功建连但传输慢，先核查应用读写、磁盘、CPU 与防病毒扫描，再对照 TCP 重传、零窗口及 RTT；不能仅凭低吞吐判定网络故障。加密 SMB 会限制文件操作的可见性，但协商阶段仍能给出线索。

来源：[Microsoft：SMB 连接失败](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/negotiate-session-setup-tree-connect-fails)；[Microsoft：SMB 慢传输](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/slow-smb-file-transfer)。

正常反例：认证挑战的中间状态不应计作最终登录失败；只有明确错误码和失败的业务操作同时出现，才进入根因排查。
