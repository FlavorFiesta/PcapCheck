# -*- coding: utf-8 -*-
"""R02 服务端中途 RST(确诊)—— 三档语义:

1. 双向都出现过 FIN 之后的 RST:优雅关闭已完成,RST 属拆除残留,不报;
2. 只有单向 FIN 之后的 RST:半关闭被 RST 掐断,报 suspect「半关闭后 RST」,
   stats 注明哪一方未优雅关闭;
3. 无任何 FIN 的 RST:
   - 流内可见 SYN/SYN-ACK(连接建立可见)→ confirmed,按 RST 发送方分
     「服务端中途 RST」/「TCP 连接被中途 RST 重置(客户端发起)」;
   - 流内无 SYN/SYN-ACK(连接建立不可见,如抓包起点在连接中段)→ 不得断言
     「服务端」(对等端口场景靠端口号猜方向不可靠),降 suspect 中性标题
     「TCP 连接被 RST 重置(连接建立不可见)」。

FIN/RST 判定一律用 tcp.flags.fin / tcp.flags.reset 字段本身(导入时打的
fin/reset 标签),帧集合来自 base.tcp_frames()(已修正 col.Protocol 盲区)。
同一档位的流聚合为一个 Finding;多档时 confirmed 在前。
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..rules.base import Finding, RuleContext, cap_evidence, is_tcp
from ..rules.registry import register
from ..rules import thresholds as th

CASE_ORDER = ["confirmed_server", "confirmed_client", "half_closed", "neutral"]

_CASE_TITLE = {
    "confirmed_server": "服务端中途 RST,连接被异常重置",
    "confirmed_client": "TCP 连接被中途 RST 重置(客户端发起)",
    "half_closed": "TCP 半关闭后 RST(对端未优雅关闭)",
    "neutral": "TCP 连接被 RST 重置(连接建立不可见)",
}


def _server_port(frames: List[dict]) -> Optional[int]:
    """服务端端口:首个 SYN 帧的目的端口;仅见 SYN-ACK 时取其源端口;否则 None。"""
    for f in frames:
        tags = f.get("analysis", [])
        if "syn" in tags:
            return f.get("dport")
    for f in frames:
        if "synack" in f.get("analysis", []):
            return f.get("sport")
    return None


def _side_of(frame: dict, server_port: Optional[int]) -> str:
    """帧发送方的角色标签;server_port 未知时用 地址:端口 标识。"""
    if server_port is None:
        return f"{frame.get('src')}:{frame.get('sport')}"
    return "server" if frame.get("sport") == server_port else "client"


@register("R02_SERVER_RST")
def check(ctx: RuleContext):
    buckets: Dict[str, dict] = {}  # case -> {streams, rst_frames, fin_frames, sides...}
    for _sid, frames in group_tcp_by_stream(ctx.frames).items():
        tags_per = [set(f.get("analysis", [])) for f in frames]
        rst_frames = [f for f, t in zip(frames, tags_per) if "reset" in t]
        if not rst_frames or len(rst_frames) < th.R02_MIN_RST_PER_STREAM:
            continue
        fin_frames = [f for f, t in zip(frames, tags_per) if "fin" in t]
        has_syn = any("syn" in t or "synack" in t for t in tags_per)
        server_port = _server_port(frames)

        fin_sides = {_side_of(f, server_port) for f in fin_frames}
        rst_sides = {_side_of(f, server_port) for f in rst_frames}

        if len(fin_sides) >= 2:
            # 双向都优雅关闭过:RST 属关闭后的残留,不报
            continue

        if len(fin_sides) == 1:
            # 半关闭:一方 FIN,另一方未优雅关闭就被 RST
            case = "half_closed"
        elif has_syn:
            case = "confirmed_server" if "server" in rst_sides else "confirmed_client"
        else:
            case = "neutral"

        b = buckets.setdefault(case, {
            "streams": set(), "rst_frames": [], "fin_frames": [],
            "rst_from_server": 0, "rst_from_client": 0, "half_closed_side": set(),
        })
        b["streams"].add(_sid)
        b["rst_frames"].extend(rst_frames)
        b["fin_frames"].extend(fin_frames)
        b["rst_from_server"] += sum(1 for f in rst_frames if _side_of(f, server_port) == "server")
        b["rst_from_client"] += sum(1 for f in rst_frames if _side_of(f, server_port) == "client")
        if case == "half_closed":
            fin_side = next(iter(fin_sides))
            b["half_closed_side"].add(fin_side)  # 发过 FIN 的一方;未关闭方为对端

    if not buckets:
        return None

    findings = []
    for case in CASE_ORDER:
        if case not in buckets:
            continue
        b = buckets[case]
        all_rst = sorted(b["rst_frames"], key=lambda f: f["no"])
        evidence_pool = all_rst + sorted(b["fin_frames"], key=lambda f: f["no"]) \
            if case == "half_closed" else all_rst
        evidence_pool = sorted(evidence_pool, key=lambda f: f["no"])
        stats = {
            "streams_affected": len(b["streams"]),
            "rst_frames": len(all_rst),
            "rst_from_server": b["rst_from_server"],
            "rst_from_client": b["rst_from_client"],
            "fin_frames": len(b["fin_frames"]),
            "sample_streams": sorted(s for s in b["streams"] if s is not None)[:10],
        }
        if case == "half_closed":
            # 发过 FIN 的一方记入 stats;未优雅关闭的是其对端
            stats["fin_from"] = sorted(b["half_closed_side"])
        findings.append(Finding(
            rule_id="R02_SERVER_RST",
            tier="confirmed" if case in ("confirmed_server", "confirmed_client") else "suspect",
            title=_CASE_TITLE[case],
            evidence_frames=cap_evidence(evidence_pool),
            stats=stats,
            suggestion=(
                "RST 而非 FIN 结束连接属异常断开:若 RST 来自服务端,排查服务进程崩溃/重启、"
                "监听队列溢出、防火墙或负载均衡的空闲/限流策略;若来自客户端,排查客户端异常退出"
                "或中间设备注入 RST。半关闭场景确认对端为何不再发送数据即被重置。"
                if case != "half_closed" else
                "半关闭被 RST 掐断:一方已 FIN 进入半关闭,对端未完成优雅关闭即被重置。"
                "排查未关闭方的进程退出方式与中间设备对半关闭连接的空闲/超时策略。"
            ),
        ))
    return findings


def group_tcp_by_stream(frames: List[Dict[str, dict]]):
    out: Dict[Optional[int], List[dict]] = {}
    for f in frames:
        if not is_tcp(f) or f.get("stream") is None:
            continue
        out.setdefault(f["stream"], []).append(f)
    return out
