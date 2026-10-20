"""Conservative diagnostics for incomplete transactions and capture reliability."""
from __future__ import annotations

from collections import defaultdict

from .base import Finding, RuleContext, cap_evidence, tag_value, tagged
from .registry import register


def _tail(ctx: RuleContext, last_ts: float, seconds: float = 2.0) -> bool:
    return bool(ctx.frames) and max(f["ts"] for f in ctx.frames) - last_ts >= seconds


@register("S18_TCP_CONNECT_TIMEOUT")
def tcp_connect_timeout(ctx: RuleContext):
    streams = defaultdict(list)
    for f in tagged(ctx.frames, "syn"):
        if f.get("stream") is not None:
            streams[f["stream"]].append(f)
    affected = []
    for sid, syns in streams.items():
        if len(syns) < 2 or not _tail(ctx, syns[-1]["ts"]):
            continue
        if any(("synack" in f.get("analysis", []) or "reset" in f.get("analysis", []))
               for f in ctx.frames if f.get("stream") == sid):
            continue
        affected.extend(syns)
    if not affected:
        return None
    return Finding("S18_TCP_CONNECT_TIMEOUT", "suspect", "TCP SYN 重试后未见响应",
                   cap_evidence(affected), {"syn_frames": len(affected),
                   "streams_affected": len({f["stream"] for f in affected})},
                   "检查抓包是否覆盖双向流量及完整重试时间；双端复抓后排查 ACL、路由、服务监听和回程路径。")


def _dns_key(f):
    qname = tag_value(f, "dns_qname")
    xid = tag_value(f, "dns_id")
    qtype = tag_value(f, "dns_type")
    if not qname or xid is None or qtype is None:
        return None
    return (f.get("src"), f.get("dst"), f.get("sport"), f.get("dport"),
            xid, qname.lower(), qtype)


@register("S19_DNS_TIMEOUT")
def dns_timeout(ctx: RuleContext):
    queries = defaultdict(list)
    responses = set()
    for f in ctx.frames:
        key = _dns_key(f)
        if key is None:
            continue
        if "dns_resp" in f.get("analysis", []):
            responses.add((f.get("dst"), f.get("src"), f.get("dport"), f.get("sport"),
                           key[4], key[5], key[6]))
        else:
            queries[key].append(f)
    missed = [(k, q) for k, q in queries.items() if k not in responses
              and len(q) >= 2 and _tail(ctx, q[-1]["ts"])]
    if not missed:
        return None
    return Finding("S19_DNS_TIMEOUT", "suspect", "DNS 重试后未见应答",
                   cap_evidence([f for _, q in missed for f in q]),
                   {"transactions": len(missed), "sample_names": list(dict.fromkeys(k[5] for k, _ in missed))[:10]},
                   "确认抓包双向完整；检查 DNS 服务器、UDP/TCP 53 路径、转发链和服务端日志。")


@register("S20_DHCP_TIMEOUT")
def dhcp_timeout(ctx: RuleContext):
    groups = defaultdict(lambda: defaultdict(list))
    for f in ctx.frames:
        xid = tag_value(f, "dhcp_xid")
        msg = tag_value(f, "dhcp_msg")
        if xid is not None and msg is not None:
            groups[(xid, tag_value(f, "dhcp_client"))][msg].append(f)
    no_offer, no_ack = [], []
    no_offer_count = no_ack_count = 0
    for msgs in groups.values():
        discovers = msgs.get("1", [])
        requests = msgs.get("3", [])
        if len(discovers) >= 2 and not msgs.get("2") and _tail(ctx, discovers[-1]["ts"]):
            no_offer.extend(discovers)
            no_offer_count += 1
        if len(requests) >= 2 and not (msgs.get("5") or msgs.get("6")) and _tail(ctx, requests[-1]["ts"]):
            no_ack.extend(requests)
            no_ack_count += 1
    if not (no_offer or no_ack):
        return None
    return Finding("S20_DHCP_TIMEOUT", "suspect", "DHCP 重试后未见 OFFER/ACK",
                   cap_evidence(no_offer + no_ack),
                   {"discover_no_offer": no_offer_count, "request_no_ack": no_ack_count},
                   "检查抓包是否覆盖服务器及中继方向；核对 DHCP 服务、作用域、中继和安全策略。")


@register("S21_IPV6_NEIGHBOR_TIMEOUT")
def ipv6_neighbor_timeout(ctx: RuleContext):
    solicitations = defaultdict(list)
    advertisements = set()
    for f in ctx.frames:
        kind = tag_value(f, "icmpv6_type")
        target = tag_value(f, "nd_target")
        if kind == "135" and target:
            solicitations[(f.get("src"), target)].append(f)
        elif kind == "136" and target:
            advertisements.add(target)
    missed = [q for (_, target), q in solicitations.items()
              if target not in advertisements and len(q) >= 2 and _tail(ctx, q[-1]["ts"])]
    if not missed:
        return None
    return Finding("S21_IPV6_NEIGHBOR_TIMEOUT", "suspect", "IPv6 邻居请求重试后未见通告",
                   cap_evidence([f for q in missed for f in q]), {"targets": len(missed)},
                   "确认抓包覆盖同一链路双向 ICMPv6；排查邻居可达性、VLAN、组播及安全策略。")


@register("S22_IPV6_PACKET_TOO_BIG")
def ipv6_packet_too_big(ctx: RuleContext):
    frames = tagged(ctx.frames, "icmpv6_type=2")
    if not frames:
        return None
    return Finding("S22_IPV6_PACKET_TOO_BIG", "potential", "观察到 IPv6 Packet Too Big",
                   cap_evidence(frames), {"messages": len(frames)},
                   "这是路径 MTU 发现反馈，单独出现不代表故障；结合数据重传、ACK 推进和双端抓包核查。")


@register("U23_CAPTURE_TRUNCATED")
def capture_truncated(ctx: RuleContext):
    frames = tagged(ctx.frames, "capture_truncated")
    if not frames:
        return None
    return Finding("U23_CAPTURE_TRUNCATED", "potential", "部分抓包帧已截断，诊断证据可能不完整",
                   cap_evidence(frames), {"truncated_frames": len(frames)},
                   "检查抓包 snaplen，并用完整长度重新抓取；截断帧不宜用于应用协议和校验和诊断。")


_SMB_FINAL_ERRORS = {
    0xC0000022: "拒绝访问", 0xC000006D: "登录失败",
    0xC00000CC: "共享名不存在", 0xC00000C9: "网络名称失效",
}


@register("S24_SMB_SESSION_FAILURE")
def smb_session_failure(ctx: RuleContext):
    failed = []
    for f in tagged(ctx.frames, "smb2_status"):
        if tag_value(f, "smb2_cmd") not in ("0", "1", "3"):
            continue
        try:
            code = int(tag_value(f, "smb2_status") or "0", 0)
        except ValueError:
            continue
        if code in _SMB_FINAL_ERRORS:
            failed.append((f, code))
    if not failed:
        return None
    return Finding("S24_SMB_SESSION_FAILURE", "suspect", "SMB 协商/认证/共享连接返回错误",
                   cap_evidence([f for f, _ in failed]),
                   {"errors": len(failed), "codes": {hex(c): _SMB_FINAL_ERRORS[c] for _, c in failed}},
                   "按 SMB 命令和 NTSTATUS 检查权限、账号、共享名、Kerberos/SPN 与服务器日志；返回码只定位阶段。")


@register("S25_SIP_SERVER_FAILURE")
def sip_server_failure(ctx: RuleContext):
    failed = []
    for f in tagged(ctx.frames, "sip_status"):
        try:
            code = int(tag_value(f, "sip_status") or "0")
        except ValueError:
            continue
        if 500 <= code < 600:
            failed.append((f, code))
    if not failed:
        return None
    return Finding("S25_SIP_SERVER_FAILURE", "suspect", "SIP 服务端返回 5xx",
                   cap_evidence([f for f, _ in failed]),
                   {"responses": len(failed), "codes": sorted({c for _, c in failed})},
                   "按 Call-ID 与 CSeq 关联请求；排查代理、注册服务器和媒体服务日志。486 Busy Here 等正常业务拒绝不在本规则内。")


@register("S26_HTTP2_STREAM_ERROR")
def http2_stream_error(ctx: RuleContext):
    failed = []
    for f in ctx.frames:
        for prefix in ("http2_rst_error", "http2_goaway_error"):
            value = tag_value(f, prefix)
            if value is None:
                continue
            try:
                code = int(value, 0)
            except ValueError:
                continue
            if code not in (0, 8):  # NO_ERROR / CANCEL may be normal lifecycle events.
                failed.append((f, prefix, code))
    if not failed:
        return None
    return Finding("S26_HTTP2_STREAM_ERROR", "suspect", "HTTP/2 流或连接返回错误码",
                   cap_evidence([f for f, _, _ in failed]),
                   {"errors": len(failed), "sample_codes": [(k, c) for _, k, c in failed[:10]]},
                   "结合 stream ID、请求响应和代理/服务端日志判断原因；单个 RST_STREAM 也可能是应用主动取消。")
