# -*- coding: utf-8 -*-
"""合成 pcap 构造器:为规则测试生成 DNS/TLS/ARP/DHCP/ICMP/HTTP/TCP 故障样本。

只用于测试夹具 —— 生成的报文足以让 tshark 正确解码出相应协议字段。
"""
from __future__ import annotations

import struct
from typing import List, Tuple

# TCP 标志位
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

Packet = Tuple[float, bytes]  # (ts 秒(可为小数), 以太网帧)


# ---------------------------------------------------------------- 基础层
def _ip_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(dst: str, src: str, ethertype: int) -> bytes:
    def mac(s: str) -> bytes:
        return bytes(int(x, 16) for x in s.split(":"))
    return mac(dst) + mac(src) + struct.pack("!H", ethertype)


def ipv4(src: str, dst: str, proto: int, payload: bytes, flags_frag: int = 0x4000) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234,
                         flags_frag, 64, proto, 0,
                         bytes(int(x) for x in src.split(".")),
                         bytes(int(x) for x in dst.split(".")))
    cks = _ip_checksum(header)
    header = header[:10] + struct.pack("!H", cks) + header[12:]
    return header + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
        window: int = 8192, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                       window, 0, 0) + payload


def icmp(itype: int, code: int, rest: bytes) -> bytes:
    return struct.pack("!BBHI", itype, code, 0, 0) + rest


# ---------------------------------------------------------------- 应用层
def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_message(qid: int, qname: str, response: bool, rcode: int = 0) -> bytes:
    flags = (0x8180 if response else 0x0100) | (rcode & 0x0F)
    question = dns_name(qname) + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", qid, flags, 1 if not response else 1,
                       0, 0, 0) + question


def dhcp_message(msg_type: int, op: int, xid: int = 0x3D1D, chaddr: str = "aa:bb:cc:dd:ee:ff") -> bytes:
    mac = bytes(int(x, 16) for x in chaddr.split(":"))
    base = struct.pack("!BBBBIH", op, 1, 6, 0, xid, 0)  # op/htype/hlen/hops/xid/secs
    base += struct.pack("!H", 0x8000)           # flags: broadcast
    base += bytes(4) * 4                        # ciaddr/yiaddr/siaddr/giaddr
    base += mac + bytes(16 - len(mac))          # chaddr[16]
    base += bytes(64)                           # sname
    base += bytes(128)                          # file
    base += bytes.fromhex("63825363")           # magic cookie
    base += bytes([53, 1, msg_type])            # DHCP Message Type
    base += b"\xff"
    return base


def tls_alert_record(level: int, desc: int) -> bytes:
    return bytes([0x15, 0x03, 0x03, 0x00, 0x02, level, desc])


def http_response(code: int, reason: str) -> bytes:
    return (f"HTTP/1.1 {code} {reason}\r\nServer: pcapcheck-test\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n").encode()


def arp_packet(opcode: int, sender_ip: str, sender_mac: str,
               target_ip: str, target_mac: str = "00:00:00:00:00:00") -> bytes:
    htype, ptype, hlen, plen = 1, 0x0800, 6, 4
    body = struct.pack("!HHBBH", htype, ptype, hlen, plen, opcode)
    body += bytes(int(x, 16) for x in sender_mac.split(":"))
    body += bytes(int(x) for x in sender_ip.split("."))
    body += bytes(int(x, 16) for x in target_mac.split(":"))
    body += bytes(int(x) for x in target_ip.split("."))
    return body


# ---------------------------------------------------------------- 写文件
def write_pcap(path, packets: List[Packet]) -> str:
    """packets: [(ts, eth_frame)],ts 为浮点秒。返回文件路径。"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec += 1
                usec -= 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    return str(path)


def eth_ip_udp(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str,
               sport: int, dport: int, payload: bytes) -> bytes:
    frame = eth(dst_mac, src_mac, 0x0800)
    frame += ipv4(src_ip, dst_ip, 17, udp(sport, dport, payload))
    return frame


def eth_ip_tcp(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str,
               sport: int, dport: int, tcp_seg: bytes) -> bytes:
    frame = eth(dst_mac, src_mac, 0x0800)
    frame += ipv4(src_ip, dst_ip, 6, tcp_seg)
    return frame
