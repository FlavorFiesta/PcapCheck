---
title: 802.1X / NAC 认证失败专题
rule_ids: []
protocols: [EAPOL, EAP, RADIUS, DHCP]
symptoms: 端口认证失败、终端无法上网、反复弹认证、认证通过但拿不到地址
severity: 高
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

802.1X 三角色:Supplicant(终端)↔ Authenticator(交换机/AP,EAPOL 承载)↔ AAA 服务器(RADIUS)。认证链任一环节失败即不通:终端不响应 EAPOL Request/Identity(无 supplicant 或防火墙拦截)、EAP 方法协商失败(证书/协议不支持)、RADIUS Access-Reject(账号/证书/VLAN 策略)、认证成功但 DHCP 阶段失败(端口未放行/安全策略)。

## 判断标准(报文特征)

- EAPOL 帧过滤器 `eapol`;EAP 结果:`eap.code==4`(Failure)/`eap.code==3`(Success)。
- RADIUS 结果:`radius.code==3`(Access-Reject)/`radius.code==2`(Access-Accept)/`radius.code==11`(Access-Challenge)。
- EAP 方法:`eap.type==1`(Identity)、`eap.type==13`(EAP-TLS)、`eap.type==25`(PEAP);Identity 反复请求无响应 = 终端 supplicant 问题。

## 报文证据特征

- 终端收到 EAP Request/Identity 后长时间无 Response:supplicant 未启用/被拦。
- `eap.code==4` 前若在 EAP-TLS 握手中断:证书过期或不被信任;RADIUS Reject 的 Reply-Message/Error-Cause 属性(详情树查看)给出拒绝原因。
- 认证 Success 后无 DHCP DISCOVER:交换机端口授权状态或 ACL 未放行。

## 排查步骤

1. 全览认证过程:`tshark -r <文件>.pcap -Y "eapol || radius" -T fields -e frame.number -e frame.time_relative -e ip.src -e eap.code -e eap.type -e radius.code`
2. 定位失败点:先看 EAP 是否走到 Success/Failure,再看 RADIUS 是否 Accept;只有 EAPOL 无 RADIUS 说明 Authenticator 与 AAA 之间不通。
3. 核对 AAA 侧日志与 `radius.code==3` 的时间点;检查客户端证书有效期与系统时间。
4. 认证通过仍不通:在交换机镜像口抓 `udp port 67 or udp port 68` 看 DHCP 是否被放行。

## 处置建议

终端:统一 supplicant 配置与证书分发,校对时间同步;AAA:核对账号策略、证书链、NAS 共享密钥;交换机:检查 dot1x 端口控制方向与 Guest VLAN/MAB 兜底。上线后复测:认证→DHCP→网关 ARP→ICMP 逐段确认。
