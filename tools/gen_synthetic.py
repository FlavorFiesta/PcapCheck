# -*- coding: utf-8 -*-
"""生成合成语料到 tests/captures_synthetic/ —— 场景与 backend/tests/test_rules.py 一致,
另加良性对照包(不应触发确诊级结论)。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "tests"))

import pcapcraft as pc  # noqa: E402

OUT = ROOT / "tests" / "captures_synthetic"
OUT.mkdir(exist_ok=True)


def craft(name, packets):
    p = pc.write_pcap(OUT / name, packets)
    print("gen", name, Path(p).stat().st_size, "B")


def retrans_storm():
    c, s = "10.0.0.1", "10.0.0.2"
    cm, sm = "aa:bb:cc:11:00:01", "aa:bb:cc:11:00:02"
    pkts = [
        (1000.0, pc.eth_ip_tcp(cm, c, sm, s, 30000, 80, pc.tcp(30000, 80, 0, 0, pc.SYN))),
        (1000.001, pc.eth_ip_tcp(sm, s, cm, c, 80, 30000, pc.tcp(80, 30000, 200, 1, pc.SYN | pc.ACK))),
        (1000.002, pc.eth_ip_tcp(cm, c, sm, s, 30000, 80, pc.tcp(30000, 80, 1, 201, pc.ACK))),
    ]
    seq = 1
    ts = 1000.1
    for i in range(12):  # 12 次重传(同一数据被重发,推进 ack 才形成"风暴"节奏)
        data = b"A" * 100
        pkts.append((ts, pc.eth_ip_tcp(cm, c, sm, s, 30000, 80,
                                       pc.tcp(30000, 80, seq, 201, pc.PSH | pc.ACK, 8192, data))))
        ts += 0.05
        pkts.append((ts, pc.eth_ip_tcp(sm, s, cm, c, 80, 30000,
                                       pc.tcp(80, 30000, 201 + (i + 1) * 100, seq + 101,
                                              pc.ACK, 8192))))
        ts += 0.05
        # 重传同一 seq(ack 未推进前重发)
        pkts.append((ts, pc.eth_ip_tcp(cm, c, sm, s, 30000, 80,
                                       pc.tcp(30000, 80, seq, 201, pc.PSH | pc.ACK, 8192, data))))
        ts += 0.05
        seq += 100
    craft("syn-retrans-storm.pcap", pkts)


def benign_http():
    c, s = "10.0.1.1", "10.0.1.2"
    cm, sm = "aa:bb:cc:12:00:01", "aa:bb:cc:12:00:02"
    req = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    pkts = [
        (2000.0, pc.eth_ip_tcp(cm, c, sm, s, 31000, 80, pc.tcp(31000, 80, 0, 0, pc.SYN))),
        (2000.001, pc.eth_ip_tcp(sm, s, cm, c, 80, 31000, pc.tcp(80, 31000, 100, 1, pc.SYN | pc.ACK))),
        (2000.002, pc.eth_ip_tcp(cm, c, sm, s, 31000, 80, pc.tcp(31000, 80, 1, 101, pc.ACK))),
        (2000.01, pc.eth_ip_tcp(cm, c, sm, s, 31000, 80, pc.tcp(31000, 80, 1, 101, pc.PSH | pc.ACK, 8192, req))),
        (2000.02, pc.eth_ip_tcp(sm, s, cm, c, 80, 31000, pc.tcp(80, 31000, 101, 1 + len(req), pc.PSH | pc.ACK, 8192, resp))),
        (2000.03, pc.eth_ip_tcp(cm, c, sm, s, 31000, 80, pc.tcp(31000, 80, 1 + len(req), 101 + len(resp), pc.ACK | pc.FIN))),
        (2000.04, pc.eth_ip_tcp(sm, s, cm, c, 80, 31000, pc.tcp(80, 31000, 101 + len(resp), 2 + len(req), pc.ACK | pc.FIN))),
    ]
    craft("syn-benign-http.pcap", pkts)


def benign_dns():
    mac1, mac2 = "aa:bb:cc:13:00:01", "aa:bb:cc:13:00:02"
    pkts = []
    for i in range(5):
        t = 3000.0 + i * 0.2
        pkts.append((t, pc.eth_ip_udp(mac1, "10.0.2.1", mac2, "10.0.2.53", 32000 + i, 53,
                                      pc.dns_message(0x100 + i, f"ok{i}.example.com", False))))
        pkts.append((t + 0.02, pc.eth_ip_udp(mac2, "10.0.2.53", mac1, "10.0.2.1", 53, 32000 + i,
                                             pc.dns_message(0x100 + i, f"ok{i}.example.com", True, 0))))
    craft("syn-benign-dns.pcap", pkts)


def dns_fail():
    craft("syn-dns-fail.pcap", [
        (100.0, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.0.1", "aa:bb:cc:00:00:02",
                              "10.6.0.53", 40000, 53, pc.dns_message(0x1111, "gone.example.com", False))),
        (100.1, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.0.53", "aa:bb:cc:00:00:01",
                              "10.6.0.1", 53, 40000, pc.dns_message(0x1111, "gone.example.com", True, 3))),
        (100.2, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.0.1", "aa:bb:cc:00:00:02",
                              "10.6.0.53", 40001, 53, pc.dns_message(0x2222, "oops.example.com", False))),
        (100.3, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.0.53", "aa:bb:cc:00:00:01",
                              "10.6.0.1", 53, 40001, pc.dns_message(0x2222, "oops.example.com", True, 2))),
    ])


def dns_slow():
    craft("syn-dns-slow.pcap", [
        (200.0, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.1.1", "aa:bb:cc:00:00:02",
                              "10.6.1.53", 41000, 53, pc.dns_message(0x1111, "slow.example.com", False))),
        (200.0, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.1.1", "aa:bb:cc:00:00:02",
                              "10.6.1.53", 41001, 53, pc.dns_message(0x2222, "fast.example.com", False))),
        (200.1, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.1.53", "aa:bb:cc:00:00:01",
                              "10.6.1.1", 53, 41001, pc.dns_message(0x2222, "fast.example.com", True, 0))),
        (202.0, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.1.53", "aa:bb:cc:00:00:01",
                              "10.6.1.1", 53, 41000, pc.dns_message(0x1111, "slow.example.com", True, 0))),
    ])


def tls_alert():
    payload = pc.tls_alert_record(2, 40)
    craft("syn-tls-alert.pcap", [
        (300.0, pc.eth_ip_tcp("aa:bb:cc:00:00:03", "10.8.0.10", "aa:bb:cc:00:00:04",
                              "10.8.0.20", 50000, 443, pc.tcp(50000, 443, 0, 0, pc.SYN))),
        (300.001, pc.eth_ip_tcp("aa:bb:cc:00:00:04", "10.8.0.20", "aa:bb:cc:00:00:03",
                                "10.8.0.10", 443, 50000, pc.tcp(443, 50000, 1000, 1, pc.SYN | pc.ACK))),
        (300.002, pc.eth_ip_tcp("aa:bb:cc:00:00:03", "10.8.0.10", "aa:bb:cc:00:00:04",
                                "10.8.0.20", 50000, 443, pc.tcp(50000, 443, 1, 1001, pc.ACK))),
        (300.01, pc.eth_ip_tcp("aa:bb:cc:00:00:04", "10.8.0.20", "aa:bb:cc:00:00:03",
                               "10.8.0.10", 443, 50000,
                               pc.tcp(443, 50000, 1001, 1, pc.PSH | pc.ACK, 8192, payload))),
    ])


def arp_conflict():
    mac_a, mac_c = "aa:aa:aa:aa:aa:01", "cc:cc:cc:cc:cc:02"
    craft("syn-arp-conflict.pcap", [
        (400.0, pc.eth("ff:ff:ff:ff:ff:ff", mac_a, 0x0806) + pc.arp_packet(2, "10.9.9.9", mac_a, "10.9.9.1")),
        (400.1, pc.eth("ff:ff:ff:ff:ff:ff", mac_c, 0x0806) + pc.arp_packet(2, "10.9.9.9", mac_c, "10.9.9.1")),
        (400.2, pc.eth("ff:ff:ff:ff:ff:ff", mac_a, 0x0806) + pc.arp_packet(2, "10.9.9.8", mac_a, "10.9.9.1")),
    ])


def dhcp_nak():
    bcast, cli, srv = "ff:ff:ff:ff:ff:ff", "aa:bb:cc:00:00:10", "aa:bb:cc:00:00:99"
    craft("syn-dhcp-nak.pcap", [
        (500.0, pc.eth_ip_udp(cli, "0.0.0.0", bcast, "255.255.255.255", 68, 67, pc.dhcp_message(1, op=1))),
        (500.1, pc.eth_ip_udp(srv, "192.168.9.1", bcast, "255.255.255.255", 67, 68, pc.dhcp_message(2, op=2))),
        (500.2, pc.eth_ip_udp(cli, "0.0.0.0", bcast, "255.255.255.255", 68, 67, pc.dhcp_message(3, op=1))),
        (500.3, pc.eth_ip_udp(srv, "192.168.9.1", bcast, "255.255.255.255", 67, 68, pc.dhcp_message(6, op=2))),
    ])


def zero_window():
    c, s = "10.7.0.1", "10.7.0.2"
    cm, sm = "aa:bb:cc:00:00:21", "aa:bb:cc:00:00:22"
    craft("syn-zero-window.pcap", [
        (600.0, pc.eth_ip_tcp(cm, c, sm, s, 40000, 9000, pc.tcp(40000, 9000, 1000, 0, pc.SYN))),
        (600.001, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000, pc.tcp(9000, 40000, 5000, 1001, pc.SYN | pc.ACK))),
        (600.002, pc.eth_ip_tcp(cm, c, sm, s, 40000, 9000, pc.tcp(40000, 9000, 1001, 5001, pc.ACK))),
        (600.01, pc.eth_ip_tcp(cm, c, sm, s, 40000, 9000,
                               pc.tcp(40000, 9000, 1001, 5001, pc.PSH | pc.ACK, 8192, b"x" * 10))),
        (600.02, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000, pc.tcp(9000, 40000, 5001, 1011, pc.ACK, 0))),
        (600.52, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000, pc.tcp(9000, 40000, 5001, 1011, pc.ACK, 0))),
        (601.02, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000, pc.tcp(9000, 40000, 5001, 1011, pc.ACK, 0))),
    ])


def mtu_blackhole():
    inner = pc.ipv4("10.7.0.1", "10.9.0.9", 6, b"\x00" * 8)
    craft("syn-mtu-blackhole.pcap", [
        (700.0, pc.eth("aa:bb:cc:00:00:31", "aa:bb:cc:00:00:32", 0x0800) +
         pc.ipv4("10.7.0.254", "10.7.0.1", 1, pc.icmp(3, 4, inner))),
    ])


def handshake_rtt():
    c, s = "10.4.0.1", "10.4.0.2"
    cm, sm = "aa:bb:cc:00:00:41", "aa:bb:cc:00:00:42"
    craft("syn-handshake-rtt.pcap", [
        (800.0, pc.eth_ip_tcp(cm, c, sm, s, 41000, 443, pc.tcp(41000, 443, 900, 0, pc.SYN))),
        (801.5, pc.eth_ip_tcp(sm, s, cm, c, 443, 41000, pc.tcp(443, 41000, 7000, 901, pc.SYN | pc.ACK))),
        (801.501, pc.eth_ip_tcp(cm, c, sm, s, 41000, 443, pc.tcp(41000, 443, 901, 7001, pc.ACK))),
    ])


def http_5xx():
    c, s = "10.5.0.1", "10.5.0.2"
    cm, sm = "aa:bb:cc:00:00:51", "aa:bb:cc:00:00:52"
    pkts = [
        (900.0, pc.eth_ip_tcp(cm, c, sm, s, 42000, 80, pc.tcp(42000, 80, 10, 0, pc.SYN))),
        (900.001, pc.eth_ip_tcp(sm, s, cm, c, 80, 42000, pc.tcp(80, 42000, 20, 11, pc.SYN | pc.ACK))),
        (900.002, pc.eth_ip_tcp(cm, c, sm, s, 42000, 80, pc.tcp(42000, 80, 11, 21, pc.ACK))),
    ]
    for i in range(3):
        pkts.append((900.1 + i,
                     pc.eth_ip_tcp(sm, s, cm, c, 80, 42000,
                                   pc.tcp(80, 42000, 21 + i * 100, 11, pc.PSH | pc.ACK, 8192,
                                          pc.http_response(503, "Service Unavailable")))))
    craft("syn-http-5xx.pcap", pkts)


if __name__ == "__main__":
    retrans_storm()
    benign_http()
    benign_dns()
    dns_fail()
    dns_slow()
    tls_alert()
    arp_conflict()
    dhcp_nak()
    zero_window()
    mtu_blackhole()
    handshake_rtt()
    http_5xx()
    print("done ->", OUT)
