# -*- coding: utf-8 -*-
"""规则引擎公共类型与工具。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# 档位优先级(排序用)
TIER_ORDER = {"confirmed": 0, "suspect": 1, "potential": 2}
TIER_ZH = {"confirmed": "确诊", "suspect": "疑似", "potential": "潜在"}

MAX_EVIDENCE = 50  # evidence_frames 上限(契约)

# ---------------------------------------------------------------- expert severity 分类
# 实测口径(Wireshark 4.6.8,_ws.expert.severity 按位分类):
#   0x800000=error(Malformed Packet)、0x600000=warn(lost_segment/Connection reset 等)、
#   0x400000=note(retransmission/FIN)、0x200000=chat(SYN)。
SEV_ERROR = 0x800000
SEV_WARN = 0x600000
SEV_NOTE = 0x400000
SEV_CHAT = 0x200000


def classify_severity(sev) -> str:
    """把 severity 数值(或字符串)分类为 error/warn/note/chat;无法解析返回空串。"""
    try:
        v = int(sev)
    except (TypeError, ValueError):
        return ""
    return {SEV_ERROR: "error", SEV_WARN: "warn",
            SEV_NOTE: "note", SEV_CHAT: "chat"}.get(v & 0xE00000, "")


@dataclass
class Finding:
    rule_id: str
    tier: str                      # confirmed | suspect | potential
    title: str
    evidence_frames: List[int] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    suggestion: str = ""
    kb_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "tier": self.tier,
            "title": self.title,
            "evidence_frames": self.evidence_frames[:MAX_EVIDENCE],
            "stats": self.stats,
            "suggestion": self.suggestion,
            "kb_ids": self.kb_ids,
        }


@dataclass
class RuleContext:
    capture_id: str
    capture: Dict[str, Any]        # captures 行(dict)
    frames: List[Dict[str, Any]]   # 全部帧,按 no 升序;analysis/expert 已反序列化
    stats: Dict[str, Any] = field(default_factory=dict)  # 已解析的 -z 统计(io/conversations 等)
    consumed: set = field(default_factory=set)  # 已被其它规则证据消费的帧号(U17 等兜底规则用)


# ---------------------------------------------------------------- 工具函数
def tagged(frames: List[Dict[str, Any]], prefix: str) -> List[Dict[str, Any]]:
    """analysis 标签含 prefix(精确或 key=value 前缀)的帧。"""
    out = []
    for f in frames:
        for t in f.get("analysis", []):
            if t == prefix or t.startswith(prefix + "=") or t.startswith(prefix + "/"):
                out.append(f)
                break
    return out


def tag_value(frame: Dict[str, Any], prefix: str) -> Optional[str]:
    """取 key=value 标签的值部分,如 tag_value(f,"dns_rcode") -> "2"。"""
    for t in frame.get("analysis", []):
        if t.startswith(prefix + "="):
            return t[len(prefix) + 1:]
    return None


def is_tcp(frame: Dict[str, Any]) -> bool:
    """帧是否 TCP:导入时给存在 tcp.stream/tcp.srcport/tcp.flags 的帧打了 "tcp" 标签。

    不能按 proto(即 _ws.col.Protocol)=="TCP" 判断 —— HTTP/TLS/HTTP2 载荷帧的
    col 值不是 "TCP",那会让规则引擎对 TLS/HTTP 列全盲。保留 proto=="TCP"
    作为兜底(兼容手工构造的帧)。
    """
    return "tcp" in (frame.get("analysis") or []) or \
        (frame.get("proto") or "").upper() == "TCP"


def tcp_frames(frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [f for f in frames if is_tcp(f)]


def group_by_stream(frames: List[Dict[str, Any]]) -> Dict[Any, List[Dict[str, Any]]]:
    """按 TCP/UDP 流号分组(无流号的帧忽略)。"""
    out: Dict[Any, List[Dict[str, Any]]] = {}
    for f in frames:
        s = f.get("stream")
        if s is None:
            continue
        out.setdefault(s, []).append(f)
    return out


def fmt_ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def cap_evidence(frames: List[Dict[str, Any]]) -> List[int]:
    """证据帧号:取前 MAX_EVIDENCE 个,并保留首尾代表帧。"""
    nos = [f["no"] for f in frames]
    if len(nos) <= MAX_EVIDENCE:
        return nos
    step = len(nos) / MAX_EVIDENCE
    picked = sorted({nos[int(i * step)] for i in range(MAX_EVIDENCE)})
    if nos[-1] not in picked:
        picked[-1] = nos[-1]
    return picked
