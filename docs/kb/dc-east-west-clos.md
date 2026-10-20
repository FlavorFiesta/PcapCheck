---
title: 数据中心东西向流量排查(CLOS 架构)专题
rule_ids: [S08_OUT_OF_ORDER, P13_BANDWIDTH_SATURATION]
protocols: [TCP, UDP, ICMP, ARP, BGP]
symptoms: 跨机架互访慢、微服务调用抖动、迁移后性能下降、部分路径不通
severity: 中
---

> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据

## 机理

Spine-Leaf 两级 CLOS 中,同层 Leaf 间流量经 Spine 存在多条等价路径,靠 ECMP 哈希按流分摊。东西向故障多源于:哈希不均导致个别链路打满(局部拥塞)、链路/路由故障收敛期间乱序丢包、Leaf-Spine MTU 不一致(常见 underlay 9000 与 overlay 分片问题)、安全组/微分段拦截。南北向测试正常不代表东西向正常,必须在路径两端抓包。

## 判断标准(报文特征)

- ECMP 乱序:`tcp.analysis.out_of_order` 比例升高且方向固定,对应多路径时延差异。
- 局部拥塞:对流统计 `-z conv,tcp` 中 Bytes 集中于个别对,伴随重传(`tcp.analysis.retransmission`)。
- MTU 不一致:`icmp.type==3 && icmp.code==4`(联动 S09)。
- 定位断点:traceroute 的 `icmp.type==11`(Time Exceeded)逐跳回包在哪一跳消失。

## 报文证据特征

- 乱序帧的到达顺序与发送顺序差异集中在固定流上:哈希极化特征。
- 双端抓包对齐(`frame.time_epoch`):发送端有、接收端无→路径丢;两端都有但应用慢→主机/中间件问题。
- ARP 请求跨 Leaf 无应答:检查 overlay/网关与广播域配置(联动 VXLAN 专题)。

## 排查步骤

1. 两端同时抓包:`tshark -i <网卡> -w src.pcap -f "host <对端IP> and port <端口>"` 在源/目的服务器同步执行。
2. 乱序与重传分布:`tshark -r src.pcap -Y "tcp.analysis.out_of_order || tcp.analysis.retransmission" -T fields -e frame.number -e frame.time_relative -e tcp.stream`
3. 会话级带宽:`tshark -r src.pcap -q -z conv,tcp` 与 Leaf-Spine 链路利用率交叉比对。
4. 逐跳验证:`tshark -i <网卡> -Y "icmp.type==11 || icmp.type==3"` 配合 traceroute,确认 MTU 与断点跳。

## 处置建议

哈希不均:调整 ECMP 哈希因子(端口/标签)或启用自适应路由;拥塞:扩链路或引入优先级队列;MTU:统一 underlay 9000 并核对 overlay 开销预留;微分段:核对安全组策略命中日志后再下结论。
