---
title: 服务端中途 RST,连接被异常重置
rule_ids: [R02_SERVER_RST]
protocols: [TCP]
symptoms: 连接中途断开、请求随机失败、客户端报「连接被重置」
severity: 高(确诊)
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

TCP 正常关闭靠 FIN 四次挥手;以 RST 结束属于异常重置,对端数据可能尚未送达应用。RST 可由服务端(进程崩溃重启、accept 队列溢出、空闲超时强拆)、客户端(异常退出)或中间设备(防火墙注入、负载均衡限流)发出,方向决定排查目标。

## 判断标准

当前 R02 将连接建立过程可见时的服务端/客户端 RST 分别报告；仅见单侧 FIN 后被 RST 的半关闭连接给出疑似提示；连接建立不可见时不强行判断来源。若双向均已优雅关闭，则忽略关闭后的残留 RST。RST 本身是连接被重置的证据，根因仍需结合端点与中间设备日志。

## 报文证据特征

- 过滤器 `tcp.flags.reset==1`,且同流 `tcp.flags.fin==1` 零命中。
- RST 帧通常 `tcp.window_size_value==0`,部分实现附带 `tcp.len==0`。
- 中间设备注入的 RST 常具有特征:RST 与 FIN/数据几乎同帧到达、TTL(`ip.ttl`)与正常服务端回包明显不同、RST 先于服务端响应出现。

## 排查步骤

1. 找出所有 RST 帧:`tshark -r <文件>.pcap -Y "tcp.flags.reset==1" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.ttl -e frame.time_relative`
2. 按 `tcp.stream` 逐条回看完整会话中的 SYN、FIN、RST；单帧过滤 `!tcp.flags.fin` 无法证明整条流没有 FIN。
3. 按流归并观察是哪类服务(目的端口)集中被 RST。
4. 对比 RST 帧与服务端正常回包的 `ip.ttl`,判断 RST 是否由路径中间设备伪造。

## 处置建议

RST 来自服务端:查服务进程日志与存活、listen backlog 溢出、防火墙/负载均衡的空闲与限流配置。RST 来自客户端:查客户端崩溃与代理设置。TTL 异常或 RST 先行:查安全设备/上网行为管理的 RST 注入策略。
