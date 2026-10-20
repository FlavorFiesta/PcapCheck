# -*- coding: utf-8 -*-
"""tshark 子进程封装。

职责:
- 定位 tshark(设置 > 常见安装路径 > PATH);
- ``-T ek`` 流式逐行输出解析(导入与实时抓包共用一份字段表);
- ``-z io,phs`` / ``-z io,stat,N`` / ``-z conv,<proto>`` 文本统计解析;
- 单帧 ``-T json`` 全字段树;
- Follow Stream(基于 tcp.payload/udp.payload 的按帧重组);
- 网卡列表(``-D``)与 display filter 校验。

全部子进程以 UTF-8 解码,路径以参数列表传入(避免空格转义问题)。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Iterator, List, Optional

# ---------------------------------------------------------------- 字段表
# 契约"必提字段"(ek 输出键为下划线形式,如 tcp_analysis_retransmission)
# 在契约基础上补充了规则引擎需要的少量字段(tcp.flags.ack / arp.src.hw_mac / rtp.p_type 等)。
EK_FIELDS: List[str] = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.stream", "udp.stream",
    "_ws.col.Protocol", "_ws.col.Info",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission", "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack", "tcp.analysis.zero_window", "tcp.analysis.window_full",
    "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "tcp.analysis.ack_rtt", "tcp.analysis.rto",
    "_ws.expert.message", "_ws.expert.severity", "_ws.expert.group", "_ws.malformed",
    "dns.flags.rcode", "dns.flags.response", "dns.qry.name", "dns.id", "dns.qry.type",
    "tls.record.content_type", "tls.alert_message.desc",
    "http.response.code", "http.request.method",
    "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.src.hw_mac",
    "dhcp.option.dhcp", "dhcp.id", "dhcp.hw.mac_addr",
    "ip.ttl", "icmp.type", "icmp.code", "icmpv6.type",
    "icmpv6.nd.ns.target_address", "icmpv6.nd.na.target_address",
    "sip.CSeq.seq", "rtp.ssrc", "rtp.p_type",
    "sip.Status-Code", "smb2.cmd", "smb2.nt_status",
    "http2.rst_stream.error", "http2.goaway.error",
]

_RETRANS_TAGS = {
    "tcp_analysis_retransmission": "retransmission",
    "tcp_analysis_fast_retransmission": "fast_retransmission",
    "tcp_analysis_spurious_retransmission": "spurious_retransmission",
}

_TLS_ALERT_DESC = {
    "40": "握手失败(Handshake Failure)",
    "41": "无证书(No Certificate)",
    "42": "证书无效(Bad Certificate)",
    "43": "证书不受支持(Unsupported Certificate)",
    "44": "证书被吊销(Certificate Revoked)",
    "45": "证书已过期(Certificate Expired)",
    "46": "证书未知错误(Certificate Unknown)",
    "112": "无法识别的服务器名(Unrecognized Name)",
}


def tls_alert_name(desc: str) -> str:
    return _TLS_ALERT_DESC.get(str(desc), f"TLS 告警(desc={desc})")


# ---------------------------------------------------------------- tshark 定位
def resolve_tshark(explicit: Optional[str] = None) -> str:
    """定位 tshark 可执行文件;找不到返回空串。"""
    from . import settings as app_settings

    candidates = []
    if explicit:
        candidates.append(explicit)
    try:
        candidates.append(app_settings.load_settings().get("tshark_path") or "")
    except Exception:
        pass
    candidates += [r"C:\Program Files\Wireshark\tshark.exe",
                   r"C:\Program Files (x86)\Wireshark\tshark.exe"]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    found = shutil.which("tshark")
    return found or ""


def _popen(tshark: str, args: List[str], stderr_file=None) -> subprocess.Popen:
    cmd = [tshark] + args
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=(stderr_file if stderr_file is not None else subprocess.DEVNULL),
        text=True, encoding="utf-8", errors="replace",
    )


# ---------------------------------------------------------------- ek 流式
def _ek_field_args() -> List[str]:
    """每个字段一个 -e 参数(tshark 的 -e 不支持逗号合并)。"""
    out: List[str] = []
    for f in EK_FIELDS:
        out += ["-e", f]
    return out


def ek_read_args(source_path: str) -> List[str]:
    """从文件读取的 ek 命令参数。"""
    return ["-r", str(source_path), "-T", "ek", "-n"] + _ek_field_args()


def ek_live_args(iface: str, snaplen: Optional[int] = None, write_path: Optional[str] = None) -> List[str]:
    """实时抓包 ek 命令参数;write_path 非空则同步落盘 pcap。"""
    # -l flushes stdout after each packet; without it a pipe can stay buffered
    # for a long time, making the live view appear to capture nothing.
    args = ["-i", str(iface), "-l"]
    if snaplen:
        args += ["-s", str(int(snaplen))]
    args += ["-T", "ek", "-n"] + _ek_field_args()
    if write_path:
        args += ["-w", str(write_path)]
    return args


def iter_ek(tshark: str, args: List[str], stderr_file=None) -> Iterator[Dict[str, Any]]:
    """启动子进程并逐行产出解析后的帧 dict;子进程退出/异常时停止。"""
    proc = _popen(tshark, args, stderr_file=stderr_file)
    try:
        yield from iter_ek_proc(proc)
        code = proc.wait(timeout=10)
        if code != 0:
            detail = ""
            if stderr_file is not None:
                stderr_file.seek(0)
                detail = stderr_file.read().decode("utf-8", errors="replace")[:1000]
            raise RuntimeError(f"tshark 解析失败(exit={code}):{detail}")
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def iter_ek_proc(proc: subprocess.Popen) -> Iterator[Dict[str, Any]]:
    """从已启动的 ek 子进程逐行产出 layers dict(实时抓包复用)。"""
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("layers"), dict):
            yield obj["layers"]


def parse_ek_layers(layers: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """把 ek layers 解析成规范帧 dict(导入入库与实时推送共用)。

    返回字段:no, ts, src, dst, sport, dport, proto, length, info, stream,
             analysis(标签列表), expert([{severity,message,group}]), extra(原始关键值)。
    """

    def first(key: str) -> Optional[str]:
        v = layers.get(key)
        if isinstance(v, list) and v:
            return str(v[0])
        if isinstance(v, (str, int, float)):
            return str(v)
        return None

    def all_values(key: str) -> List[str]:
        v = layers.get(key)
        if isinstance(v, list):
            return [str(x) for x in v]
        if v is None:
            return []
        return [str(v)]

    def flag(key: str) -> bool:
        """布尔字段在 ek 里是 "True"/"False"/"1"/"0"。"""
        v = first(key)
        return v is not None and v.strip().lower() in ("1", "true")

    no = first("frame_number")
    if no is None:
        return None
    ts_raw = first("frame_time_epoch")
    try:
        ts = float(ts_raw) if ts_raw is not None else 0.0
    except ValueError:
        ts = 0.0

    src = first("ip_src") or first("ipv6_src") or first("arp_src_proto_ipv4")
    dst = first("ip_dst") or first("ipv6_dst") or first("arp_dst_proto_ipv4")
    sport = first("tcp_srcport") or first("udp_srcport")
    dport = first("tcp_dstport") or first("udp_dstport")
    proto = first("_ws_col_protocol") or ""
    info = first("_ws_col_info") or ""
    stream_raw = first("tcp_stream") if layers.get("tcp_stream") else first("udp_stream")
    try:
        stream = int(stream_raw) if stream_raw is not None else None
    except ValueError:
        stream = None

    # ---- analysis 标签(规则引擎与前端着色共用) ----
    tags: List[str] = []
    cap_len, wire_len = first("frame_cap_len"), first("frame_len")
    if cap_len is not None and wire_len is not None:
        try:
            if int(cap_len) < int(wire_len):
                tags.append("capture_truncated")
        except ValueError:
            pass
    # 是否真实 TCP 帧:存在 tcp.stream / tcp.srcport / tcp.flags 任一字段即 TCP。
    # 不能用 _ws.col.Protocol 判断(HTTP/TLS/HTTP2 载荷帧的 col 值不是 "TCP",
    # 会导致规则引擎对 TLS/HTTP 列的 TCP 全盲)。
    tcp_present = any(layers.get(k) for k in (
        "tcp_stream", "tcp_srcport", "tcp_dstport",
        "tcp_flags_syn", "tcp_flags_ack", "tcp_flags_fin", "tcp_flags_reset"))
    if tcp_present:
        tags.append("tcp")
    for key, tag in _RETRANS_TAGS.items():
        if layers.get(key):
            if "retransmission" not in tags:
                tags.append("retransmission")
            tags.append(tag)
    for key, tag in [
        ("tcp_analysis_out_of_order", "out_of_order"),
        ("tcp_analysis_duplicate_ack", "duplicate_ack"),
        ("tcp_analysis_zero_window", "zero_window"),
        ("tcp_analysis_window_full", "window_full"),
        ("tcp_analysis_lost_segment", "lost_segment"),
        ("tcp_analysis_ack_lost_segment", "ack_lost_segment"),
    ]:
        if layers.get(key) and tag not in tags:
            tags.append(tag)

    flags_syn = flag("tcp_flags_syn")
    flags_ack = flag("tcp_flags_ack")
    if flag("tcp_flags_reset") and "reset" not in tags:
        tags.append("reset")
    if flags_syn:
        tags.append("synack" if flags_ack else "syn")
    if flag("tcp_flags_fin"):
        tags.append("fin")
    if flags_syn:
        rtt = first("tcp_analysis_ack_rtt")
        if rtt:
            try:
                tags.append("ack_rtt=%.6f" % float(rtt))
            except ValueError:
                pass

    # DNS
    if flag("dns_flags_response"):
        tags.append("dns_resp")
        rcode = first("dns_flags_rcode")
        if rcode and rcode != "0":
            tags.append(f"dns_rcode={rcode}")
    qname = first("dns_qry_name")
    if qname:
        tags.append(f"dns_qname={qname}")
        for field, prefix in (("dns_id", "dns_id"), ("dns_qry_type", "dns_type")):
            value = first(field)
            if value is not None:
                tags.append(f"{prefix}={value}")

    # TLS 告警
    for desc in all_values("tls_alert_message_desc"):
        tags.append(f"tls_alert={desc}")

    # HTTP
    code = first("http_response_code")
    if code:
        tags.append(f"http_code={code}")
    for field, tag in (("smb2_cmd", "smb2_cmd"), ("smb2_nt_status", "smb2_status"),
                       ("sip_Status-Code", "sip_status"),
                       ("http2_rst_stream_error", "http2_rst_error"),
                       ("http2_goaway_error", "http2_goaway_error")):
        value = first(field)
        if value is not None:
            tags.append(f"{tag}={value}")

    # ICMP
    itype = first("icmp_type")
    if itype is not None:
        icode = first("icmp_code") or "0"
        tags.append(f"icmp={itype}/{icode}")

    # DHCP
    msg = first("dhcp_option_dhcp")
    if msg:
        tags.append(f"dhcp_msg={msg}")
        xid = first("dhcp_id")
        mac = first("dhcp_hw_mac_addr")
        if xid:
            tags.append(f"dhcp_xid={xid}")
        if mac:
            tags.append(f"dhcp_client={mac}")

    icmpv6_type = first("icmpv6_type")
    if icmpv6_type is not None:
        tags.append(f"icmpv6_type={icmpv6_type}")
        nd_target = first("icmpv6_nd_ns_target_address") or first("icmpv6_nd_na_target_address")
        if nd_target:
            tags.append(f"nd_target={nd_target}")

    # ARP(冲突检测需要 发送方IP+MAC)
    if layers.get("arp_opcode"):
        try:
            tags.append("arp_op=%s" % int(first("arp_opcode") or "0"))
        except ValueError:
            pass
    sender_ips = all_values("arp_src_proto_ipv4")
    sender_macs = all_values("arp_src_hw_mac")
    for i, ip in enumerate(sender_ips):
        mac = sender_macs[i] if i < len(sender_macs) else "?"
        tags.append(f"arp_sender={ip}|{mac}")

    # RTP
    for ssrc in all_values("rtp_ssrc"):
        tags.append(f"rtp_ssrc={ssrc}")

    # 畸形帧(_ws.malformed:malformed 帧上该生成字段的值是消息文本数组,
    # 如 ["[Malformed Packet: NVMe/TCP]", "_ws.malformed"];普通帧无此键)
    mv = layers.get("_ws_malformed")
    if mv:
        vals = mv if isinstance(mv, list) else [mv]
        if any(str(x).strip().lower() not in ("0", "false", "") for x in vals):
            tags.append("malformed")

    # ---- expert ----
    expert: List[Dict[str, str]] = []
    msgs = all_values("_ws_expert_message")
    sevs = all_values("_ws_expert_severity")
    groups = all_values("_ws_expert_group")
    for i, m in enumerate(msgs):
        expert.append({
            "severity": sevs[i] if i < len(sevs) else "",
            "message": m,
            "group": groups[i] if i < len(groups) else "",
        })

    def _int(v: Optional[str]) -> Optional[int]:
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    return {
        "no": int(no),
        "ts": ts,
        "src": src,
        "dst": dst,
        "sport": _int(sport),
        "dport": _int(dport),
        "proto": proto,
        "length": _int(first("frame_len")) or 0,
        "info": info,
        "stream": stream,
        "analysis": tags,
        "expert": expert,
        "extra": {
            "ack_rtt": first("tcp_analysis_ack_rtt"),
            "dns_qname": qname,
            "rtp_ssrc": all_values("rtp_ssrc"),
            "rtp_p_type": all_values("rtp_p_type"),
        },
    }


# ---------------------------------------------------------------- 单帧详情
def get_frame_tree(tshark: str, path: str, no: int) -> Dict[str, Any]:
    """单帧协议字段树:tshark -r file -Y frame.number==N -T pdml。

    输出 {"no": N, "tree": [{label, children:[...]}]}:
    - 顶层节点 = 协议层(按实际协议栈序,即 PDML 文档序),label 用 proto 的 showname;
    - 字段节点 label 优先 showname,缺省回退 "name: show" / "name: value";
    - 丢弃 geninfo/_index/_score 等存储原语与无字段的层(如 raw)。
    """
    import xml.etree.ElementTree as ET

    args = ["-r", str(path), "-Y", f"frame.number=={int(no)}", "-T", "pdml", "-n"]
    p = subprocess.run([tshark] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"tshark 退出码 {p.returncode}")

    def field_label(elem) -> str:
        showname = elem.get("showname")
        if showname:
            return showname
        name = elem.get("name") or "?"
        show = elem.get("show")
        value = elem.get("value")
        if show:
            return f"{name}: {show}"
        if value:
            return f"{name}: {value}"
        return name

    def walk_field(elem) -> Dict[str, Any]:
        children = [walk_field(c) for c in elem.findall("field")]
        return {"label": field_label(elem), "children": children}

    tree: List[Dict[str, Any]] = []
    root = ET.fromstring(p.stdout)
    packets = root.findall("packet")
    if not packets:
        raise KeyError(f"帧 {no} 不存在")
    # 丢弃:存储原语(geninfo)与内部包装层(fake-field-wrapper,非真实协议)
    _SKIP_PROTOS = {"geninfo", "fake-field-wrapper"}
    for proto in packets[0].findall("proto"):
        pname = proto.get("name") or ""
        if pname in _SKIP_PROTOS:
            continue
        fields = proto.findall("field")
        if not fields:  # 无实际字段的层(如 raw)丢弃
            continue
        label = proto.get("showname") or pname
        tree.append({"label": label, "children": [walk_field(f) for f in fields]})
    return {"no": int(no), "tree": tree}


def get_frame_detail(tshark: str, path: str, no: int) -> Any:
    """兼容保留:原始 -T json(tshark -T json,含 _index/_source 信封)。"""
    args = ["-r", str(path), "-Y", f"frame.number=={int(no)}", "-T", "json"]
    p = subprocess.run([tshark] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"tshark 退出码 {p.returncode}")
    try:
        return json.loads(p.stdout)
    except Exception:
        return {"raw": p.stdout}


def filtered_frame_numbers(tshark: str, path: str, display_filter: str) -> List[int]:
    """按 display filter 二次查询,返回命中的帧号(升序)。"""
    args = ["-r", str(path), "-Y", display_filter, "-T", "ek", "-n", "-e", "frame.number"]
    nums: List[int] = []
    with tempfile.TemporaryFile() as errf:
        for layers in iter_ek(tshark, args, stderr_file=errf):
            v = layers.get("frame_number")
            if isinstance(v, list) and v:
                try:
                    nums.append(int(v[0]))
                except ValueError:
                    pass
        if not nums:
            errf.seek(0)
            err = errf.read().decode("utf-8", errors="replace").strip()
            if err and "doesn't exist" in err.lower() or "invalid" in err.lower() or "unknown" in err.lower():
                raise RuntimeError(err[:500])
    return nums


def validate_display_filter(tshark: str, display_filter: str) -> tuple:
    """用合法空 pcap 验证 display filter,返回 (ok, 错误文本)。"""
    empty = _empty_pcap()
    try:
        p = subprocess.run([tshark, "-r", empty, "-Y", display_filter, "-T", "ek"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        if p.returncode == 0:
            return True, ""
        raw = (p.stderr.strip() or p.stdout.strip() or "无效表达式")
        # 取第一条有意义的报错行(tshark 会输出 caret 指示行,无信息量)
        msg = ""
        for ln in raw.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("^") and not set(ln) <= {"~", " ", "^"}:
                msg = ln
                break
        return False, msg[:500]
    except Exception as e:  # 子进程异常按校验失败处理
        return False, str(e)
    finally:
        try:
            os.unlink(empty)
        except OSError:
            pass


def _empty_pcap() -> str:
    """生成只含全局头的合法 pcap(24 字节),用于 filter 校验。"""
    import struct
    fd, path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(fd, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    return path


# ---------------------------------------------------------------- -z 统计解析
def get_stats_phs(tshark: str, path: str) -> List[Dict[str, Any]]:
    """协议分级:解析 `tshark -z io,phs -q` 输出为嵌套树。

    返回 [{label, frames, bytes, children:[...]}, ...]
    """
    p = subprocess.run([tshark, "-r", str(path), "-q", "-z", "io,phs", "-n"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "io,phs 失败")
    line_re = re.compile(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)\s*$")
    root: List[Dict[str, Any]] = []
    stack: List[tuple] = []  # (indent, node)
    for line in p.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        indent, label, frames, size = len(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        node = {"label": label, "frames": frames, "bytes": size, "children": []}
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            root.append(node)
        else:
            stack[-1][1]["children"].append(node)
        stack.append((indent, node))
    return root


def get_stats_io(tshark: str, path: str, interval: int = 1) -> List[Dict[str, Any]]:
    """IO 时间线:解析 `tshark -z io,stat,N -q` 输出为 [{t, frames, bytes}]。

    t 为该区间起始时刻的绝对 epoch 秒(捕获首帧时间 + 区间偏移)。
    """
    p = subprocess.run([tshark, "-r", str(path), "-q", "-z", f"io,stat,{int(interval)}", "-n"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "io,stat 失败")
    base = _first_ts(tshark, path)
    row_re = re.compile(
        r"(\d+\.\d+)\s*<>\s*(\d+\.\d+)\s*\|((?:\s*[\d.]+\s*\|)+)")
    out: List[Dict[str, Any]] = []
    for line in p.stdout.splitlines():
        m = row_re.search(line)
        if not m:
            continue
        start = float(m.group(1))
        cells = [c.strip() for c in m.group(3).split("|") if c.strip()]
        if not cells:
            continue
        try:
            frames = int(float(cells[0]))
            size = int(float(cells[1])) if len(cells) > 1 else 0
        except ValueError:
            continue
        out.append({"t": round(base + start, 6), "frames": frames, "bytes": size})
    return out


def get_stats_conversations(tshark: str, path: str, proto: str = "tcp") -> List[Dict[str, Any]]:
    """会话表:解析 `tshark -z conv,<proto> -q`。

    返回 [{src,sport,dst,dport,frames,bytes,frames_ab,bytes_ab,frames_ba,bytes_ba}]
    列序(tshark 4.x):A  <-> B | <- Frames Bytes | -> Frames Bytes | Total Frames Bytes ...
    即第一对数字是 B->A,第二对是 A->B(已实测核对)。
    """
    proto = (proto or "tcp").lower()
    if proto not in ("tcp", "udp", "ip", "ipv6"):
        raise ValueError("proto 仅支持 tcp|udp|ip|ipv6")
    p = subprocess.run([tshark, "-r", str(path), "-q", "-z", f"conv,{proto}", "-n"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"conv,{proto} 失败")
    row_re = re.compile(
        r"^\s*(\S+)\s*<->\s*(\S+)\s+(\d+)\s+(\d+)\s*(?:bytes)?\s+"
        r"(\d+)\s+(\d+)\s*(?:bytes)?\s+(\d+)\s+(\d+)\s*(?:bytes)?")
    out: List[Dict[str, Any]] = []

    def split_addr(addr: str, with_port: bool):
        if with_port and ":" in addr:
            host, _, port = addr.rpartition(":")
            return host, int(port)
        return addr, None

    with_port = proto in ("tcp", "udp")
    for line in p.stdout.splitlines():
        m = row_re.match(line)
        if not m:
            continue
        a, b = m.group(1), m.group(2)
        ba_f, ba_by, ab_f, ab_by, t_f, t_by = (int(m.group(i)) for i in range(3, 9))
        s, sport = split_addr(a, with_port)
        d, dport = split_addr(b, with_port)
        out.append({
            "src": s, "sport": sport, "dst": d, "dport": dport,
            "frames": t_f, "bytes": t_by,
            "frames_ab": ab_f, "bytes_ab": ab_by,
            "frames_ba": ba_f, "bytes_ba": ba_by,
        })
    return out


def _first_ts(tshark: str, path: str) -> float:
    """捕获首帧的绝对 epoch 时间(用于 io,stat 区间换算)。"""
    try:
        p = subprocess.run([tshark, "-r", str(path), "-T", "ek", "-n", "-e", "frame.time_epoch", "-c", "1"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        for line in p.stdout.splitlines():
            try:
                obj = json.loads(line)
                layers = obj.get("layers") or {}
                v = layers.get("frame_time_epoch")
                if isinstance(v, list) and v:
                    return float(v[0])
            except Exception:
                continue
    except Exception:
        pass
    return 0.0


# ---------------------------------------------------------------- Follow Stream
def get_follow_messages(tshark: str, path: str, stream: int, proto: str = "tcp") -> Dict[str, Any]:
    """Follow Stream。

    TCP:每个方向按 tcp.seq 重组 —— 重排、重叠字节去重(先到先得)、缺口显式标注
    "[N bytes missing (gap before frame M)]",纯 ACK 不产消息;消息保留首帧号(可回跳)
    与方向。UDP:无序号,按帧平铺(空负载跳过)。
    输出形状不变:{client, server, messages:[{no, ts, dir, data, len}]}(允许新增字段)。
    """
    proto = (proto or "tcp").lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("proto 仅支持 tcp|udp")
    payload_field = f"{proto}.payload"
    stream_field = f"{proto}.stream"
    args = ["-r", str(path), "-Y", f"{stream_field}=={int(stream)}", "-T", "ek", "-n",
            "-e", "frame.number", "-e", "frame.time_epoch",
            "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport", "-e", "udp.srcport",
            "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport", "-e", "udp.dstport",
            "-e", "tcp.flags.syn", "-e", "tcp.flags.ack", "-e", "tcp.seq",
            "-e", payload_field]

    rows = []
    with tempfile.TemporaryFile() as errf:
        for layers in iter_ek(tshark, args, stderr_file=errf):
            rows.append(layers)

    def first(layers, key):
        v = layers.get(key)
        return v[0] if isinstance(v, list) and v else v

    client = server = None
    parsed = []
    for layers in rows:
        src = first(layers, "ip_src") or first(layers, "ipv6_src") or ""
        dst = first(layers, "ip_dst") or first(layers, "ipv6_dst") or ""
        sport = first(layers, "tcp_srcport") or first(layers, "udp_srcport")
        dport = first(layers, "tcp_dstport") or first(layers, "udp_dstport")
        no = int(first(layers, "frame_number") or 0)
        try:
            ts = float(first(layers, "frame_time_epoch") or 0)
        except (TypeError, ValueError):
            ts = 0.0
        hex_payload = first(layers, payload_field.replace(".", "_")) or ""
        syn = str(first(layers, "tcp_flags_syn") or "").strip().lower() in ("1", "true")
        ack = str(first(layers, "tcp_flags_ack") or "").strip().lower() in ("1", "true")
        seq_raw = first(layers, "tcp_seq")
        try:
            seq = int(seq_raw) if seq_raw is not None else None
        except (TypeError, ValueError):
            seq = None
        parsed.append({"no": no, "ts": ts, "src": src, "sport": sport,
                       "dst": dst, "dport": dport, "hex": hex_payload,
                       "syn": syn, "ack": ack, "seq": seq})
        if proto == "tcp" and syn and not ack and client is None:
            client = (src, sport)
            server = (dst, dport)
    if client is None and parsed:
        client = (parsed[0]["src"], parsed[0]["sport"])
        server = (parsed[0]["dst"], parsed[0]["dport"])

    def decode(raw: bytes) -> str:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.hex(":")

    messages: List[Dict[str, Any]] = []

    def _assemble_tcp(segs: List[tuple], dir_label: str) -> List[Dict[str, Any]]:
        """单方向按 seq 重组:重排、重叠去重(先到先得)、缺口标注。

        返回按流位置排序的消息(即该方向可连续拼读的文本顺序)。
        """
        segs = sorted(segs, key=lambda s: (s[0], s[1]))  # seq 升序,同 seq 先到帧优先
        out: List[Dict[str, Any]] = []
        expected = None
        for seq, no, ts, raw in segs:
            if expected is None:
                expected = seq
            if seq + len(raw) <= expected:
                continue  # 完全重复(重传/重叠旧数据),字节已被先到帧覆盖
            gap = 0
            prefix = ""
            if seq > expected:
                gap = seq - expected
                prefix = f"[{gap} bytes missing (gap before frame {no})]"
            chunk = raw[max(0, expected - seq):]  # 重叠时只取新增字节(防负索引)
            expected = seq + len(raw)
            out.append({
                "no": no, "ts": ts, "dir": dir_label,
                "data": prefix + decode(chunk), "len": len(chunk),
                **({"gap": gap} if gap else {}),
            })
        return out

    if proto == "tcp":
        per_dir: Dict[str, List[tuple]] = {"c2s": [], "s2c": []}
        for p in parsed:
            if p["seq"] is None or not p["hex"]:
                continue  # 纯 ACK/无负载帧不产消息
            try:
                raw = bytes.fromhex(p["hex"])
            except ValueError:
                continue
            if not raw:
                continue
            if (p["src"], p["sport"]) == client:
                per_dir["c2s"].append((p["seq"], p["no"], p["ts"], raw))
            else:
                per_dir["s2c"].append((p["seq"], p["no"], p["ts"], raw))
        # 两个方向各自保持流内字节序,再按时间归并(单方向文本始终连续可读)
        c2s_msgs = _assemble_tcp(per_dir["c2s"], "c2s")
        s2c_msgs = _assemble_tcp(per_dir["s2c"], "s2c")
        i = j = 0
        while i < len(c2s_msgs) or j < len(s2c_msgs):
            take_c2s = j >= len(s2c_msgs) or (
                i < len(c2s_msgs) and
                (c2s_msgs[i]["ts"], c2s_msgs[i]["no"]) <= (s2c_msgs[j]["ts"], s2c_msgs[j]["no"]))
            if take_c2s:
                messages.append(c2s_msgs[i])
                i += 1
            else:
                messages.append(s2c_msgs[j])
                j += 1
    else:
        for p in parsed:
            if not p["hex"]:
                continue
            try:
                raw = bytes.fromhex(p["hex"])
            except ValueError:
                continue
            if not raw:
                continue
            is_c2s = (p["src"], p["sport"]) == client
            messages.append({
                "no": p["no"], "ts": p["ts"],
                "dir": "c2s" if is_c2s else "s2c",
                "data": decode(raw), "len": len(raw),
            })
        messages.sort(key=lambda m: (m["ts"], m["no"]))

    return {"client": f"{client[0]}:{client[1]}", "server": f"{server[0]}:{server[1]}", "messages": messages}


# ---------------------------------------------------------------- 网卡
def list_interfaces(tshark: str) -> List[Dict[str, Any]]:
    """解析 `tshark -D`,返回 [{idx,name,desc,capture}]."""
    p = subprocess.run([tshark, "-D"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    out: List[Dict[str, Any]] = []
    for line in (p.stdout or "").splitlines():
        m = re.match(r"^\s*(\d+)\.\s+(.+?)(?:\s+\((.*)\))?\s*$", line)
        if m:
            name = m.group(2).strip()
            desc = (m.group(3) or "").strip()
            out.append({"idx": int(m.group(1)), "name": name, "desc": desc,
                        "capture": name.lower() != "etwdump"})
    if not out and p.stderr:
        # Npcap 未装等情况:把错误带给前端
        out = []
    return out


def interface_diagnostics(interfaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    """指出只有 ETW 或完全没有 NPF 网卡时的安装依赖。"""
    capture_interfaces = [item for item in interfaces if item.get("capture", True)]
    if capture_interfaces:
        return {"capture_ready": True, "warning": "", "capture_count": len(capture_interfaces)}
    if any(str(item.get("name", "")).lower() == "etwdump" for item in interfaces):
        warning = "只检测到 ETW reader，未检测到可抓包网卡。请安装或启动 Npcap 后点击“刷新接口”。"
    else:
        warning = "未检测到可抓包网卡。请安装或启动 Npcap 后点击“刷新接口”。"
    return {"capture_ready": False, "warning": warning, "capture_count": 0}
