# -*- coding: utf-8 -*-
"""规则引擎测试。

- 真实 pcap:tests/captures 下的 tcp-badsegments(重传/乱序)、tcp-rst-diagnostic(RST)、
  sip-rtp(RTP 单向);
- 合成 pcap:backend/tests/pcapcraft.py 生成的 DNS 失败/慢响应、TLS 告警、ARP 冲突、
  DHCP NAK、零窗口、MTU 黑洞、握手 RTT、HTTP 5xx 样本;
- 纯单元:P13(带宽)、R01(重传风暴)阈值行为。

全部走真实管线:tshark -T ek 解析 -> SQLite -> 规则引擎。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import CAPTURES
import pcapcraft as pc
from app import analysis, db, imports
from app.filterlang import FilterCompileError, compile_expr
from app.rules import all_rule_ids, run_all
from app.rules.base import Finding, RuleContext
from app import tshark_service


# ---------------------------------------------------------------- 工具
def import_and_analyze(path: Path):
    """真实管线:导入 pcap -> analyze,返回 (capture_meta, findings)。"""
    cap_id = imports.create_capture(str(path))
    try:
        imports.import_sync(cap_id, str(path))
        meta = db.query_one("SELECT * FROM captures WHERE id=?", (cap_id,))
        assert meta["status"] == "ready", f"导入失败:{meta['error']}"
        report_id = analysis.analyze_capture(cap_id)
        rep = db.query_one("SELECT findings FROM reports WHERE id=?", (report_id,))
        findings = json.loads(rep["findings"])
        return dict(meta), findings
    finally:
        db.execute("DELETE FROM frames WHERE capture_id=?", (cap_id,))
        db.execute("DELETE FROM reports WHERE capture_id=?", (cap_id,))
        db.execute("DELETE FROM captures WHERE id=?", (cap_id,))


def find(findings, rule_id):
    for f in findings:
        if f["rule_id"] == rule_id:
            return f
    return None


def craft(packets, tmp_path, name):
    return Path(pc.write_pcap(tmp_path / name, packets))


# ---------------------------------------------------------------- 注册表
def test_registry_has_26_rules():
    ids = all_rule_ids()
    assert len(ids) == 26, ids
    assert all(r[0] in "RSPU" for r in ids)
    assert "U16_MALFORMED" in ids and "U17_EXPERT_FALLBACK" in ids


# ---------------------------------------------------------------- 过滤器编译
def test_filterlang_compile():
    cases = {
        "ip==10.0.0.1": "ip.addr==10.0.0.1",
        "port==443": "(tcp.port==443 || udp.port==443)",
        "proto==dns": "dns",
        'contains "abc"': "frame contains 61:62:63",
        "stream==5": "(tcp.stream==5 || udp.stream==5)",
        "ip==1.2.3.4 && port==80": "ip.addr==1.2.3.4 && ((tcp.port==80 || udp.port==80))",
        "!proto==arp": "!arp",
        "(proto==tcp || proto==udp) && port==53": None,  # 只验证可编译
    }
    for expr, want in cases.items():
        got = compile_expr(expr)
        if want:
            assert got == want, expr
    with pytest.raises(FilterCompileError):
        compile_expr("ip==999.1.1.1")
    with pytest.raises(FilterCompileError):
        compile_expr("port==abc")
    with pytest.raises(FilterCompileError):
        compile_expr('contains "abc" ||')
    with pytest.raises(FilterCompileError):
        compile_expr("proto==smtp")


# ---------------------------------------------------------------- 真实 pcap
@pytest.mark.external_capture
@pytest.mark.tshark
def test_tcp_badsegments_p14_retrans_trend(tmp_path):
    meta, findings = import_and_analyze(CAPTURES / "tcp-badsegments.pcap")
    assert meta["frame_count"] == 25
    p14 = find(findings, "P14_RETRANS_TREND")
    assert p14 and p14["tier"] == "potential"
    assert p14["evidence_frames"] == [10]
    assert p14["stats"]["max_window_ratio"] > 0.05
    s08 = find(findings, "S08_OUT_OF_ORDER")
    assert s08 and s08["tier"] == "suspect"
    # 重传只有 1 次,不构成 R01 风暴
    assert find(findings, "R01_RETRANS_STORM") is None


@pytest.mark.external_capture
@pytest.mark.tshark
def test_tcp_rst_diagnostic_r02(tmp_path):
    """4 条流只有 RST(无 SYN/SYN-ACK,连接建立不可见)→ suspect 中性标题。"""
    meta, findings = import_and_analyze(CAPTURES / "tcp-rst-diagnostic.pcap")
    r02 = find(findings, "R02_SERVER_RST")
    assert r02 and r02["tier"] == "suspect"
    assert "连接建立不可见" in r02["title"]
    assert "服务端" not in r02["title"]
    assert r02["stats"]["rst_frames"] == 4
    assert r02["stats"]["streams_affected"] == 4
    assert r02["evidence_frames"] == [1, 2, 3, 4]


@pytest.mark.external_capture
@pytest.mark.tshark
def test_tls_renegotiation_r02_half_closed(tmp_path):
    """tls-renegotiation:服务端 4433 发 FIN(帧51)后,同侧又发 RST(帧53)→ suspect 半关闭。"""
    meta, findings = import_and_analyze(CAPTURES / "tls-renegotiation.pcap")
    r02s = [f for f in findings if f["rule_id"] == "R02_SERVER_RST"]
    assert r02s, findings
    r02 = r02s[0]
    assert r02["tier"] == "suspect"
    assert "半关闭" in r02["title"]
    assert r02["stats"]["fin_frames"] == 1
    assert r02["stats"]["rst_frames"] == 1
    assert r02["evidence_frames"] == [51, 53]


@pytest.mark.external_capture
@pytest.mark.tshark
def test_http2_data_reassembly_r02_half_closed(tmp_path):
    """http2-data-reassembly:服务端 8443 FIN(帧43),客户端 49178 发 RST(帧44)→ suspect 半关闭。"""
    meta, findings = import_and_analyze(CAPTURES / "http2-data-reassembly.pcap")
    r02s = [f for f in findings if f["rule_id"] == "R02_SERVER_RST"]
    assert r02s, findings
    r02 = r02s[0]
    assert r02["tier"] == "suspect"
    assert "半关闭" in r02["title"]
    assert r02["stats"]["fin_frames"] == 1
    assert r02["stats"]["rst_frames"] == 1
    assert r02["evidence_frames"] == [43, 44]
    assert r02["stats"]["rst_from_client"] == 1


@pytest.mark.external_capture
@pytest.mark.tshark
def test_dns_mdns_r02_neutral_not_server(tmp_path):
    """dns-mdns 裸 RST(无 SYN/FIN,对等端口)→ suspect 中性,不得断言「服务端」。"""
    meta, findings = import_and_analyze(CAPTURES / "dns-mdns.pcap")
    r02s = [f for f in findings if f["rule_id"] == "R02_SERVER_RST"]
    assert r02s, findings
    r02 = r02s[0]
    assert r02["tier"] == "suspect"
    assert "服务端" not in r02["title"]
    assert r02["stats"]["rst_frames"] == 1


@pytest.mark.external_capture
@pytest.mark.tshark
def test_http_ooo_s08_and_tcp_visibility(tmp_path):
    """http-ooo:TCP 帧应为 16(col.Protocol 盲区修复),OOO 4 帧全部在证据里。"""
    meta, findings = import_and_analyze(CAPTURES / "http-ooo.pcap")
    s08 = find(findings, "S08_OUT_OF_ORDER")
    assert s08 and s08["tier"] == "suspect"
    assert s08["stats"]["tcp_frames"] == 16
    assert s08["stats"]["out_of_order_frames"] == 4
    assert s08["evidence_frames"] == [4, 6, 10, 15]
    assert find(findings, "R01_RETRANS_STORM") is None


@pytest.mark.external_capture
@pytest.mark.tshark
def test_http_ooo2_s08(tmp_path):
    meta, findings = import_and_analyze(CAPTURES / "http-ooo2.pcap")
    s08 = find(findings, "S08_OUT_OF_ORDER")
    assert s08 and s08["tier"] == "suspect"
    assert s08["stats"]["tcp_frames"] == 7
    assert s08["stats"]["out_of_order_frames"] == 2


@pytest.mark.external_capture
@pytest.mark.tshark
def test_http2_follow_multistream_s08(tmp_path):
    """http2_follow_multistream:36/197(critic 实测 tshark 口径)。"""
    meta, findings = import_and_analyze(CAPTURES / "http2_follow_multistream.pcapng")
    s08 = find(findings, "S08_OUT_OF_ORDER")
    assert s08 and s08["tier"] == "suspect"
    assert s08["stats"]["tcp_frames"] == 197
    assert s08["stats"]["out_of_order_frames"] == 36
    assert len(s08["evidence_frames"]) == 36


@pytest.mark.external_capture
@pytest.mark.tshark
def test_retrans_tls_tcp_visibility(tmp_path):
    """retrans-tls:2 帧 TLS 流量,TCP 帧数应为 2(不再对 TLS 列全盲);无重传标记故 R01/P14 不触发。"""
    meta, findings = import_and_analyze(CAPTURES / "retrans-tls.pcap")
    assert meta["frame_count"] == 2
    from app.analysis import _load_frames
    from app.rules.base import tcp_frames
    # 帧已随 import_and_analyze 清理,重新导入检查
    cap_id = imports.create_capture(str(CAPTURES / "retrans-tls.pcap"))
    try:
        imports.import_sync(cap_id, str(CAPTURES / "retrans-tls.pcap"))
        frames = _load_frames(cap_id)
        assert len(tcp_frames(frames)) == 2
        assert not any("tcp" not in f["analysis"] for f in tcp_frames(frames))
    finally:
        db.execute("DELETE FROM frames WHERE capture_id=?", (cap_id,))
        db.execute("DELETE FROM captures WHERE id=?", (cap_id,))
    assert find(findings, "R01_RETRANS_STORM") is None
    assert find(findings, "P14_RETRANS_TREND") is None
    assert find(findings, "S08_OUT_OF_ORDER") is None


@pytest.mark.external_capture
@pytest.mark.tshark
def test_sip_rtp_p15_oneway(tmp_path):
    meta, findings = import_and_analyze(CAPTURES / "sip-rtp.pcapng")
    p15 = find(findings, "P15_RTP_ONEWAY")
    assert p15 and p15["tier"] == "potential"
    assert p15["stats"]["rtp_frames"] >= 500
    assert len(p15["stats"]["ssrcs"]) >= 1


# ---------------------------------------------------------------- 合成 pcap
@pytest.mark.tshark
def test_dns_failure_r03(tmp_path):
    path = craft([
        (100.0, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.0.1", "aa:bb:cc:00:00:02",
                              "10.6.0.53", 40000, 53, pc.dns_message(0x1111, "gone.example.com", False))),
        (100.1, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.0.53", "aa:bb:cc:00:00:01",
                              "10.6.0.1", 53, 40000, pc.dns_message(0x1111, "gone.example.com", True, 3))),
        (100.2, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.0.1", "aa:bb:cc:00:00:02",
                              "10.6.0.53", 40001, 53, pc.dns_message(0x2222, "oops.example.com", False))),
        (100.3, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.0.53", "aa:bb:cc:00:00:01",
                              "10.6.0.1", 53, 40001, pc.dns_message(0x2222, "oops.example.com", True, 2))),
    ], tmp_path, "dns-fail.pcap")
    meta, findings = import_and_analyze(path)
    r03 = find(findings, "R03_DNS_FAILURE")
    assert r03 and r03["tier"] == "confirmed"
    assert r03["stats"]["rcode_3_nxdomain"] == 1
    assert r03["stats"]["rcode_2_servfail"] == 1
    assert set(r03["stats"]["sample_names"]) == {"gone.example.com", "oops.example.com"}


@pytest.mark.tshark
def test_dns_slow_s10(tmp_path):
    path = craft([
        (200.0, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.1.1", "aa:bb:cc:00:00:02",
                              "10.6.1.53", 41000, 53, pc.dns_message(0x1111, "slow.example.com", False))),
        (200.0, pc.eth_ip_udp("aa:bb:cc:00:00:01", "10.6.1.1", "aa:bb:cc:00:00:02",
                              "10.6.1.53", 41001, 53, pc.dns_message(0x2222, "fast.example.com", False))),
        (200.1, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.1.53", "aa:bb:cc:00:00:01",
                              "10.6.1.1", 53, 41001, pc.dns_message(0x2222, "fast.example.com", True, 0))),
        (202.0, pc.eth_ip_udp("aa:bb:cc:00:00:02", "10.6.1.53", "aa:bb:cc:00:00:01",
                              "10.6.1.1", 53, 41000, pc.dns_message(0x1111, "slow.example.com", True, 0))),
    ], tmp_path, "dns-slow.pcap")
    meta, findings = import_and_analyze(path)
    s10 = find(findings, "S10_DNS_SLOW")
    assert s10 and s10["tier"] == "suspect"
    assert s10["stats"]["slow_count"] == 1
    assert s10["stats"]["max_delay_sec"] > 1.0
    assert s10["stats"]["samples"][0]["query_name"] == "slow.example.com"


@pytest.mark.tshark
def test_tls_alert_r04(tmp_path):
    payload = pc.tls_alert_record(2, 40)
    path = craft([
        (300.0, pc.eth_ip_tcp("aa:bb:cc:00:00:03", "10.8.0.10", "aa:bb:cc:00:00:04",
                              "10.8.0.20", 50000, 443,
                              pc.tcp(50000, 443, 0, 0, pc.SYN, 8192))),
        (300.001, pc.eth_ip_tcp("aa:bb:cc:00:00:04", "10.8.0.20", "aa:bb:cc:00:00:03",
                                "10.8.0.10", 443, 50000,
                                pc.tcp(443, 50000, 1000, 1, pc.SYN | pc.ACK, 8192))),
        (300.002, pc.eth_ip_tcp("aa:bb:cc:00:00:03", "10.8.0.10", "aa:bb:cc:00:00:04",
                                "10.8.0.20", 50000, 443,
                                pc.tcp(50000, 443, 1, 1001, pc.ACK, 8192))),
        (300.01, pc.eth_ip_tcp("aa:bb:cc:00:00:04", "10.8.0.20", "aa:bb:cc:00:00:03",
                               "10.8.0.10", 443, 50000,
                               pc.tcp(443, 50000, 1001, 1, pc.PSH | pc.ACK, 8192, payload))),
    ], tmp_path, "tls-alert.pcap")
    meta, findings = import_and_analyze(path)
    r04 = find(findings, "R04_TLS_ALERT")
    assert r04 and r04["tier"] == "confirmed"
    assert r04["stats"]["desc_counts"].get("40") == 1


@pytest.mark.tshark
def test_arp_conflict_r05(tmp_path):
    mac_a = "aa:aa:aa:aa:aa:01"
    mac_c = "cc:cc:cc:cc:cc:02"
    path = craft([
        (400.0, pc.eth("ff:ff:ff:ff:ff:ff", mac_a, 0x0806) +
         pc.arp_packet(2, "10.9.9.9", mac_a, "10.9.9.1")),
        (400.1, pc.eth("ff:ff:ff:ff:ff:ff", mac_c, 0x0806) +
         pc.arp_packet(2, "10.9.9.9", mac_c, "10.9.9.1")),
        (400.2, pc.eth("ff:ff:ff:ff:ff:ff", mac_a, 0x0806) +
         pc.arp_packet(2, "10.9.9.8", mac_a, "10.9.9.1")),  # 不冲突的另一个 IP
    ], tmp_path, "arp-conflict.pcap")
    meta, findings = import_and_analyze(path)
    r05 = find(findings, "R05_ARP_CONFLICT")
    assert r05 and r05["tier"] == "confirmed"
    assert r05["stats"]["ip"] == "10.9.9.9"
    assert r05["stats"]["mac_count"] == 2
    assert set(r05["evidence_frames"]) == {1, 2}


@pytest.mark.tshark
def test_dhcp_nak_r06(tmp_path):
    bcast = "ff:ff:ff:ff:ff:ff"
    cli = "aa:bb:cc:00:00:10"
    srv = "aa:bb:cc:00:00:99"
    path = craft([
        (500.0, pc.eth_ip_udp(cli, "0.0.0.0", bcast, "255.255.255.255",
                              68, 67, pc.dhcp_message(1, op=1))),
        (500.1, pc.eth_ip_udp(srv, "192.168.9.1", bcast, "255.255.255.255",
                              67, 68, pc.dhcp_message(2, op=2))),
        (500.2, pc.eth_ip_udp(cli, "0.0.0.0", bcast, "255.255.255.255",
                              68, 67, pc.dhcp_message(3, op=1))),
        (500.3, pc.eth_ip_udp(srv, "192.168.9.1", bcast, "255.255.255.255",
                              67, 68, pc.dhcp_message(6, op=2))),
    ], tmp_path, "dhcp-nak.pcap")
    meta, findings = import_and_analyze(path)
    r06 = find(findings, "R06_DHCP_FAILURE")
    assert r06 and r06["tier"] == "confirmed"
    assert r06["stats"]["nak_count"] == 1
    assert r06["stats"]["nak_servers"] == {"192.168.9.1": 1}
    assert r06["evidence_frames"] == [4]


@pytest.mark.tshark
def test_zero_window_r07(tmp_path):
    c, s = "10.7.0.1", "10.7.0.2"
    cm, sm = "aa:bb:cc:00:00:21", "aa:bb:cc:00:00:22"
    pkts = [
        (600.0, pc.eth_ip_tcp(cm, c, sm, s, 40000, 9000,
                              pc.tcp(40000, 9000, 1000, 0, pc.SYN, 8192))),
        (600.001, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000,
                                pc.tcp(9000, 40000, 5000, 1001, pc.SYN | pc.ACK, 8192))),
        (600.002, pc.eth_ip_tcp(cm, c, sm, s, 40000, 9000,
                                pc.tcp(40000, 9000, 1001, 5001, pc.ACK, 8192))),
        (600.01, pc.eth_ip_tcp(cm, c, sm, s, 40000, 9000,
                               pc.tcp(40000, 9000, 1001, 5001, pc.PSH | pc.ACK, 8192, b"x" * 10))),
        (600.02, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000,
                               pc.tcp(9000, 40000, 5001, 1011, pc.ACK, 0))),
        (600.52, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000,
                               pc.tcp(9000, 40000, 5001, 1011, pc.ACK, 0))),
        (601.02, pc.eth_ip_tcp(sm, s, cm, c, 9000, 40000,
                               pc.tcp(9000, 40000, 5001, 1011, pc.ACK, 0))),
    ]
    path = craft(pkts, tmp_path, "zero-win.pcap")
    meta, findings = import_and_analyze(path)
    r07 = find(findings, "R07_ZERO_WINDOW")
    assert r07 and r07["tier"] == "confirmed"
    assert r07["stats"]["zero_window_frames"] == 3


@pytest.mark.tshark
def test_mtu_blackhole_s09(tmp_path):
    inner = pc.ipv4("10.7.0.1", "10.9.0.9", 6, b"\x00" * 8)
    path = craft([
        (700.0, pc.eth("aa:bb:cc:00:00:31", "aa:bb:cc:00:00:32", 0x0800) +
         pc.ipv4("10.7.0.254", "10.7.0.1", 1, pc.icmp(3, 4, inner))),
    ], tmp_path, "mtu.pcap")
    meta, findings = import_and_analyze(path)
    s09 = find(findings, "S09_MTU_BLACKHOLE")
    assert s09 and s09["tier"] == "suspect"
    assert "黑洞" not in s09["title"]
    assert s09["stats"]["icmp_frag_needed_count"] == 1
    assert s09["stats"]["reporters"] == ["10.7.0.254"]


@pytest.mark.tshark
def test_handshake_rtt_s11(tmp_path):
    c, s = "10.4.0.1", "10.4.0.2"
    cm, sm = "aa:bb:cc:00:00:41", "aa:bb:cc:00:00:42"
    path = craft([
        (800.0, pc.eth_ip_tcp(cm, c, sm, s, 41000, 443,
                              pc.tcp(41000, 443, 900, 0, pc.SYN, 8192))),
        (801.5, pc.eth_ip_tcp(sm, s, cm, c, 443, 41000,
                              pc.tcp(443, 41000, 7000, 901, pc.SYN | pc.ACK, 8192))),
        (801.501, pc.eth_ip_tcp(cm, c, sm, s, 41000, 443,
                                pc.tcp(41000, 443, 901, 7001, pc.ACK, 8192))),
    ], tmp_path, "rtt.pcap")
    meta, findings = import_and_analyze(path)
    s11 = find(findings, "S11_HANDSHAKE_RTT")
    assert s11 and s11["tier"] == "suspect"
    assert s11["stats"]["max_rtt_sec"] > 1.0


@pytest.mark.tshark
def test_http_5xx_s12(tmp_path):
    c, s = "10.5.0.1", "10.5.0.2"
    cm, sm = "aa:bb:cc:00:00:51", "aa:bb:cc:00:00:52"
    pkts = [
        (900.0, pc.eth_ip_tcp(cm, c, sm, s, 42000, 80, pc.tcp(42000, 80, 10, 0, pc.SYN, 8192))),
        (900.001, pc.eth_ip_tcp(sm, s, cm, c, 80, 42000, pc.tcp(80, 42000, 20, 11, pc.SYN | pc.ACK, 8192))),
        (900.002, pc.eth_ip_tcp(cm, c, sm, s, 42000, 80, pc.tcp(42000, 80, 11, 21, pc.ACK, 8192))),
    ]
    for i in range(3):
        pkts.append((900.1 + i,
                     pc.eth_ip_tcp(sm, s, cm, c, 80, 42000,
                                   pc.tcp(80, 42000, 21 + i * 100, 11, pc.PSH | pc.ACK, 8192,
                                          pc.http_response(503, "Service Unavailable")))))
    path = craft(pkts, tmp_path, "http5xx.pcap")
    meta, findings = import_and_analyze(path)
    s12 = find(findings, "S12_HTTP_5XX")
    assert s12 and s12["tier"] == "suspect"
    assert s12["stats"]["count_5xx"] == 3
    assert s12["stats"]["codes"] == {"503": 3}


# ---------------------------------------------------------------- U16/U17(真实包直跑)
@pytest.mark.external_capture
@pytest.mark.tshark
def test_u16_malformed_nvme_packs():
    """三个 nvme-tcp 故障包都应命中 U16(实测 malformed 帧数)。"""
    for name, expect in [("nvme-tcp-admin.pcapng", 1),
                         ("nvme-tcp-logpage-datal.pcapng", 2),
                         ("nvme-tcp-truncated.pcapng", 1)]:
        meta, findings = import_and_analyze(CAPTURES / name)
        u16 = find(findings, "U16_MALFORMED")
        assert u16, f"{name} 未命中 U16: {[f['rule_id'] for f in findings]}"
        assert u16["tier"] == "suspect"
        assert u16["stats"]["malformed_frames"] == expect
        assert u16["evidence_frames"], name


@pytest.mark.external_capture
@pytest.mark.tshark
def test_u17_expert_fallback_dtn_packs():
    """dtn 系 6 个有 warn/error 且未消费的包应命中 U17(potential)。"""
    expects = {
        "dtn_tcpclv4_bpv7_transfer.pcapng": 2,   # 2 帧 error(XFER_SEGMENT/CRC)
        "dtn_udpcl_bpv7_bpsec_cose_encrypt_ec.pcap": 1,
        "dtn_udpcl_bpv7_bpsec_cose_mac0.pcap": 1,
        "dtn_udpcl_bpv7_bpsec_cose_sign1_ec.pcap": 1,
        "dtn_udpcl_bpv7_eid_schemes.pcap": 1,    # 2 条 warn 在同一帧
        "dtn_udpcl_bpv7_ipn_invalid.pcap": None,  # malformed 帧被 U16 消费 → U17 不报
    }
    for name, expect in expects.items():
        meta, findings = import_and_analyze(CAPTURES / name)
        u17 = find(findings, "U17_EXPERT_FALLBACK")
        if expect is None:
            assert u17 is None, f"{name} 不应命中 U17"
            assert find(findings, "U16_MALFORMED") is not None
        else:
            assert u17, f"{name} 未命中 U17: {[f['rule_id'] for f in findings]}"
            assert u17["tier"] == "potential"
            assert u17["stats"]["unconsumed_warn_error_frames"] == expect
            assert u17["evidence_frames"]


@pytest.mark.external_capture
@pytest.mark.tshark
def test_u17_artifact_and_benign_silent():
    """伪影豁免与良性包零命中。"""
    # dns-ooo:唯一 warn 是 "common at capture start" 伪影 → 豁免
    _, findings = import_and_analyze(CAPTURES / "dns-ooo.pcap")
    assert find(findings, "U17_EXPERT_FALLBACK") is None
    # tcp-badsegments:未消费 warn 全部是捕获起点伪影 → 豁免
    _, findings = import_and_analyze(CAPTURES / "tcp-badsegments.pcap")
    assert find(findings, "U17_EXPERT_FALLBACK") is None
    # 良性包:无 warn/error → 零命中
    for name in ("dhcp.pcap", "http.cap", "rsasnakeoil2.pcap"):
        _, findings = import_and_analyze(CAPTURES / name)
        assert find(findings, "U17_EXPERT_FALLBACK") is None, name
        assert find(findings, "U16_MALFORMED") is None, name


def test_u17_respects_consumed_set():
    """单元:已消费帧不出现在 U17;伪影消息豁免。"""
    from app.rules.u17_expert_fallback import check as u17
    frames = [
        {"no": 1, "ts": 0, "proto": "TCP", "stream": 0,
         "analysis": ["tcp"], "expert": [{"severity": "6291456",
                                          "message": "Connection reset (RST)",
                                          "group": "33554432"}]},
        {"no": 2, "ts": 1, "proto": "TCP", "stream": 0,
         "analysis": ["tcp"], "expert": [{"severity": "6291456",
                                          "message": "Previous segment(s) not captured (common at capture start)",
                                          "group": "33554432"}]},
        {"no": 3, "ts": 2, "proto": "TCP", "stream": 0,
         "analysis": ["tcp"], "expert": [{"severity": "4194304",
                                          "message": "This frame is a (suspected) retransmission",
                                          "group": "33554432"}]},
    ]
    ctx = RuleContext(capture_id="t", capture={}, frames=frames, stats={},
                      consumed={1})  # 帧1 已被其它规则消费
    f = u17(ctx)
    # 帧1 已消费,帧2 是捕获起点伪影,帧3 只是 note,因此不应产生兜底结论。
    assert f is None

    # 帧1 未消费时才命中
    ctx2 = RuleContext(capture_id="t", capture={}, frames=frames, stats={}, consumed=set())
    f2 = u17(ctx2)
    assert f2 and f2.stats["unconsumed_warn_error_frames"] == 1
    assert f2.evidence_frames == [1]


def _fake_ctx(frames, *, capture=None, stats=None, consumed=None):
    """为纯规则单测构造最小上下文,避免把 SQLite/导入管线带进阈值测试。"""
    return RuleContext(
        capture_id="unit-test",
        capture=capture or {},
        frames=frames,
        stats=stats or {},
        consumed=consumed or set(),
    )


def _tcp_frame(no, ts, tags=None, length=100, proto="TCP"):
    return {"no": no, "ts": ts, "src": "1.1.1.1", "dst": "2.2.2.2", "sport": 1000,
            "dport": 80, "proto": proto, "length": length, "info": "", "stream": 0,
            "analysis": tags or [], "expert": []}


def test_r01_retrans_storm_threshold():
    from app.rules.r01_retrans_storm import check as r01
    frames = [_tcp_frame(i, i * 0.1, ["retransmission"] if i % 5 == 0 else [])
              for i in range(1, 51)]  # 10 次重传
    f = r01(_fake_ctx(frames))
    assert f and f.rule_id == "R01_RETRANS_STORM" and f.tier == "confirmed"
    assert f.stats["retrans_count"] == 10
    # 只有 1 次重传:不触发
    frames2 = [_tcp_frame(1, 0.1, ["retransmission"])] + \
              [_tcp_frame(i, i * 0.1) for i in range(2, 51)]
    assert r01(_fake_ctx(frames2)) is None


def test_is_tcp_tag_vs_proto():
    """TCP 判定:col 值为 TLS/HTTP 的帧凭 "tcp" 标签归位,不再全盲。"""
    from app.rules.base import is_tcp, tcp_frames
    tls_frame = {"no": 1, "ts": 0, "proto": "TLSv1.2", "analysis": ["tcp"],
                 "expert": [], "stream": 0}
    http_frame = {"no": 2, "ts": 0, "proto": "HTTP", "analysis": ["tcp", "retransmission"],
                  "expert": [], "stream": 0}
    udp_frame = {"no": 3, "ts": 0, "proto": "DNS", "analysis": [], "expert": []}
    old_style = {"no": 4, "ts": 0, "proto": "TCP", "analysis": [], "expert": []}
    assert is_tcp(tls_frame) and is_tcp(http_frame) and is_tcp(old_style)
    assert not is_tcp(udp_frame)
    assert [f["no"] for f in tcp_frames([tls_frame, http_frame, udp_frame, old_style])] == [1, 2, 4]


def test_s08_threshold_branches():
    from app.rules.s08_out_of_order import check as s08

    def make(count, total):
        frames = [_tcp_frame(i, i * 0.1, ["out_of_order"] if i <= count else [])
                  for i in range(1, total + 1)]
        return _fake_ctx(frames)

    assert s08(make(6, 25)) is not None        # 6/25: count>=5 且 0.24>=0.10
    assert s08(make(4, 16)) is not None        # 4/16: count<5 但 0.25>=0.20
    assert s08(make(2, 7)) is not None         # 2/7:  0.286>=0.20
    assert s08(make(36, 197)) is not None      # 36/197: count>=5 且 0.183>=0.10
    assert s08(make(2, 16)) is None            # 2/16: 0.125,两档都不满足
    assert s08(make(3, 20)) is None            # 3/20: 0.15,两档都不满足
    assert s08(make(1, 2)) is None             # count<2 不触发


def _rst_stream_frames(rst_from_server: bool, fins: tuple, has_syn: bool):
    """构造一条 RST 流:0.0.0.1:1000(client) <-> 0.0.0.2:80(server)。"""
    frames = []
    no = 1
    if has_syn:
        frames.append(_tcp_frame(1, 0.0, ["syn"]))            # client -> server:80
        no = 2
    for side in fins:  # "client" / "server"
        tags = ["fin"]
        f = _tcp_frame(no, no * 0.01, tags)
        if side == "server":
            f["sport"], f["dport"] = 80, 1000
        else:
            f["sport"], f["dport"] = 1000, 80
        frames.append(f)
        no += 1
    rst = _tcp_frame(no, no * 0.01, ["reset"])
    if rst_from_server:
        rst["sport"], rst["dport"] = 80, 1000
    else:
        rst["sport"], rst["dport"] = 1000, 80
    frames.append(rst)
    return frames


def test_r02_semantics_three_tiers():
    from app.rules.r02_server_rst import check as r02

    # 1) 双向 FIN 后 RST:优雅关闭完成,不报
    both_fin = _rst_stream_frames(rst_from_server=True, fins=("client", "server"), has_syn=True)
    assert r02(_fake_ctx(both_fin)) is None

    # 2) 单向 FIN 后 RST:suspect 半关闭(客户端 FIN,服务端 RST)
    half = _rst_stream_frames(rst_from_server=True, fins=("client",), has_syn=True)
    fs = r02(_fake_ctx(half))
    assert fs and len(fs) == 1
    assert fs[0].tier == "suspect" and "半关闭" in fs[0].title
    assert fs[0].stats["fin_from"] == ["client"]
    assert fs[0].stats["rst_from_server"] == 1

    # 3) 无 FIN + 有 SYN:confirmed,方向按 RST 发送方
    srv = r02(_fake_ctx(_rst_stream_frames(True, (), True)))
    assert srv and srv[0].tier == "confirmed" and "服务端" in srv[0].title
    cli = r02(_fake_ctx(_rst_stream_frames(False, (), True)))
    assert cli and cli[0].tier == "confirmed" and "客户端发起" in cli[0].title

    # 4) 无 FIN + 无 SYN(连接建立不可见):suspect 中性标题
    blind = _rst_stream_frames(True, (), False)
    nb = r02(_fake_ctx(blind))
    assert nb and nb[0].tier == "suspect"
    assert "服务端" not in nb[0].title and "连接建立不可见" in nb[0].title


def test_p13_bandwidth_saturation_threshold():
    from app.rules.p13_bandwidth import check as p13
    def make(secs_high):
        frames = []
        no = 1
        for sec in range(0, 20):
            n = 13 if sec < secs_high else 1
            for _ in range(n):
                frames.append(_tcp_frame(no, 1000 + sec + no * 1e-4, length=1_000_000))
                no += 1
        return frames
    f = p13(_fake_ctx(make(12)))    # 12 秒 x 13MB/s
    assert f and f.rule_id == "P13_BANDWIDTH_SATURATION" and f.tier == "potential"
    assert f.stats["sustain_sec"] >= 10
    assert p13(_fake_ctx(make(5))) is None  # 高位不足 10 秒:不触发


# ---------------------------------------------------------------- 单帧/统计解析(供 API 使用)
@pytest.mark.external_capture
@pytest.mark.tshark
def test_stats_parsers(tmp_path):
    path = CAPTURES / "tcp-badsegments.pcap"
    tshark = tshark_service.resolve_tshark()
    phs = tshark_service.get_stats_phs(str(tshark), str(path))
    assert phs[0]["label"] == "frame"
    io = tshark_service.get_stats_io(str(tshark), str(path), 1)
    assert io and io[0]["frames"] == 25
    conv = tshark_service.get_stats_conversations(str(tshark), str(path), "tcp")
    assert conv and conv[0]["frames_ab"] == 19 and conv[0]["frames_ba"] == 6
    ok, err = tshark_service.validate_display_filter(str(tshark), "tcp.stream==0")
    assert ok
    ok2, err2 = tshark_service.validate_display_filter(str(tshark), "bogus_field==1")
    assert not ok2 and err2


# ---------------------------------------------------------------- 知识库扫描
def test_kb_scan_and_rule_match(tmp_path):
    from app import kb
    kb_dir = tmp_path / "kb"
    kb_dir.mkdir()
    (kb_dir / "retrans-storm.md").write_text(
        "---\ntitle: TCP 重传风暴\nrule_ids: [R01_RETRANS_STORM, P14_RETRANS_TREND]\n"
        "protocols: [tcp]\nsymptoms: 大量重传\ntext-severity: high\n---\n\n# 机理\n丢包导致重传。\n",
        encoding="utf-8")
    arts = kb.scan_articles(str(kb_dir))
    assert len(arts) == 1 and arts[0]["title"] == "TCP 重传风暴"
    assert arts[0]["rule_ids"] == ["R01_RETRANS_STORM", "P14_RETRANS_TREND"]
    matched = kb.articles_for_rule("R01_RETRANS_STORM", str(kb_dir))
    assert len(matched) == 1 and "丢包导致重传" in matched[0]["content"]
    assert kb.articles_for_rule("R03_DNS_FAILURE", str(kb_dir)) == []
    assert kb.match_kb_ids(["R01_RETRANS_STORM"], str(kb_dir)) == ["retrans-storm"]


def test_kb_empty_or_missing_dir_returns_empty(tmp_path):
    from app import kb
    assert kb.scan_articles(str(tmp_path / "不存在")) == []
    empty = tmp_path / "空目录"
    empty.mkdir()
    assert kb.scan_articles(str(empty)) == []


# ---------------------------------------------------------------- 诊断管线整体(kb_ids 挂接)
@pytest.mark.external_capture
@pytest.mark.tshark
def test_analyze_with_kb_article(tmp_path):
    """命中规则的文章 id 会写进 finding.kb_ids(kb_dir 为空目录时为空列表,不报错)。"""
    from app import settings as app_settings
    empty_kb = tmp_path / "kb-empty"
    empty_kb.mkdir()
    kb_dir = tmp_path / "kb2"
    kb_dir.mkdir()
    (kb_dir / "rst.md").write_text(
        "---\ntitle: RST 断连\nrule_ids: R02_SERVER_RST\n---\n正文。\n", encoding="utf-8")
    saved = app_settings.load_settings().get("kb_dir")
    try:
        # 第一段:kb_dir 指向空目录 -> kb_ids 为空,不报错
        app_settings.save_settings({"kb_dir": str(empty_kb)})
        cap_id = imports.create_capture(str(CAPTURES / "tcp-rst-diagnostic.pcap"))
        try:
            imports.import_sync(cap_id, str(CAPTURES / "tcp-rst-diagnostic.pcap"))
            report_id = analysis.analyze_capture(cap_id)
            rep = db.query_one("SELECT findings FROM reports WHERE id=?", (report_id,))
            findings = json.loads(rep["findings"])
            r02 = find(findings, "R02_SERVER_RST")
            assert r02 and r02["kb_ids"] == [], r02
        finally:
            db.execute("DELETE FROM frames WHERE capture_id=?", (cap_id,))
            db.execute("DELETE FROM reports WHERE capture_id=?", (cap_id,))
            db.execute("DELETE FROM captures WHERE id=?", (cap_id,))
        # 第二段:kb_dir 指向含匹配文章的目录 -> kb_ids 挂上文章 id
        app_settings.save_settings({"kb_dir": str(kb_dir)})
        cap_id = imports.create_capture(str(CAPTURES / "tcp-rst-diagnostic.pcap"))
        try:
            imports.import_sync(cap_id, str(CAPTURES / "tcp-rst-diagnostic.pcap"))
            report_id = analysis.analyze_capture(cap_id)
            rep = db.query_one("SELECT findings FROM reports WHERE id=?", (report_id,))
            findings = json.loads(rep["findings"])
            r02 = find(findings, "R02_SERVER_RST")
            assert r02 and r02["kb_ids"] == ["rst"], r02["kb_ids"]
        finally:
            db.execute("DELETE FROM frames WHERE capture_id=?", (cap_id,))
            db.execute("DELETE FROM reports WHERE capture_id=?", (cap_id,))
            db.execute("DELETE FROM captures WHERE id=?", (cap_id,))
    finally:
        app_settings.save_settings({"kb_dir": saved})  # 恢复现场
