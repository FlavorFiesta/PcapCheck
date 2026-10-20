"""Core unanswered-transaction and capture-quality diagnostics."""
from app.rules import run_all
from app.rules.base import RuleContext
from app.tshark_service import parse_ek_layers


def frame(no, ts, tags, *, src="10.0.0.1", dst="10.0.0.2", stream=None,
          sport=None, dport=None):
    return {"no": no, "ts": ts, "src": src, "dst": dst, "sport": sport,
            "dport": dport, "stream": stream, "proto": "TCP" if "tcp" in tags else "",
            "length": 60, "analysis": tags, "expert": []}


def hits(frames):
    ctx = RuleContext("test", {"frame_count": len(frames)}, frames)
    return {f.rule_id: f for f in run_all(ctx)}


def test_tcp_unanswered_syn_requires_retries_and_capture_tail():
    frames = [frame(1, 0, ["tcp", "syn"], stream=1, sport=50001, dport=443),
              frame(2, 1, ["tcp", "syn"], stream=1, sport=50001, dport=443),
              frame(3, 5, ["tcp", "syn"], stream=2, sport=50002, dport=443)]
    assert "S18_TCP_CONNECT_TIMEOUT" in hits(frames)
    assert "S18_TCP_CONNECT_TIMEOUT" not in hits(frames[:2])
    frames[2]["analysis"] = ["tcp", "synack"]
    frames[2]["stream"] = 1
    assert "S18_TCP_CONNECT_TIMEOUT" not in hits(frames)


def test_dns_timeout_matches_transaction_and_ignores_other_reply():
    q = ["dns_qname=example.test", "dns_id=42", "dns_type=1"]
    frames = [frame(1, 0, q, sport=51000, dport=53),
              frame(2, 1, q, sport=51000, dport=53),
              frame(3, 5, ["dns_qname=other.test", "dns_id=43", "dns_type=1", "dns_resp"],
                    src="10.0.0.2", dst="10.0.0.1", sport=53, dport=51000)]
    assert "S19_DNS_TIMEOUT" in hits(frames)
    frames[2].update({"analysis": q + ["dns_resp"], "sport": 53, "dport": 51000})
    assert "S19_DNS_TIMEOUT" not in hits(frames)


def test_dhcp_discover_no_offer_and_request_no_ack():
    discover = ["dhcp_msg=1", "dhcp_xid=0x1234"]
    request = ["dhcp_msg=3", "dhcp_xid=0x5678"]
    frames = [frame(1, 0, discover), frame(2, 1, discover),
              frame(3, 2, request), frame(4, 3, request), frame(5, 8, ["tcp"])]
    result = hits(frames)["S20_DHCP_TIMEOUT"]
    assert result.stats["discover_no_offer"] == 1
    assert result.stats["request_no_ack"] == 1
    frames[4]["analysis"] = ["dhcp_msg=2", "dhcp_xid=0x1234"]
    frames.append(frame(6, 9, ["dhcp_msg=5", "dhcp_xid=0x5678"]))
    assert "S20_DHCP_TIMEOUT" not in hits(frames)


def test_ipv6_unanswered_neighbor_solicitation_and_packet_too_big():
    ns = ["icmpv6_type=135", "nd_target=2001:db8::2"]
    frames = [frame(1, 0, ns, src="2001:db8::1", dst="ff02::1:ff00:2"),
              frame(2, 1, ns, src="2001:db8::1", dst="ff02::1:ff00:2"),
              frame(3, 5, ["icmpv6_type=2"], src="2001:db8::3", dst="2001:db8::1")]
    result = hits(frames)
    assert "S21_IPV6_NEIGHBOR_TIMEOUT" in result
    assert "S22_IPV6_PACKET_TOO_BIG" in result
    frames[2]["analysis"] = ["icmpv6_type=136", "nd_target=2001:db8::2"]
    assert "S21_IPV6_NEIGHBOR_TIMEOUT" not in hits(frames)


def test_truncated_capture_frame_tag_and_quality_finding():
    parsed = parse_ek_layers({"frame_number": ["1"],
        "frame_time_epoch": ["1.0"], "frame_len": ["1500"], "frame_cap_len": ["96"]})
    assert "capture_truncated" in parsed["analysis"]
    result = hits([parsed])
    assert "U23_CAPTURE_TRUNCATED" in result


def test_smb_final_failure_not_intermediate_auth():
    frames = [frame(1, 0, ["smb2_cmd=1", "smb2_status=0xc0000016"]),
              frame(2, 1, ["smb2_cmd=1", "smb2_status=0xc000006d"])]
    result = hits(frames)["S24_SMB_SESSION_FAILURE"]
    assert result.evidence_frames == [2]
    assert "S24_SMB_SESSION_FAILURE" not in hits(frames[:1])


def test_sip_server_failure_and_http2_error():
    frames = [frame(1, 0, ["sip_status=486"]),
              frame(2, 1, ["sip_status=503"]),
              frame(3, 2, ["http2_rst_error=8"]),
              frame(4, 3, ["http2_rst_error=2"])]
    result = hits(frames)
    assert result["S25_SIP_SERVER_FAILURE"].evidence_frames == [2]
    assert result["S26_HTTP2_STREAM_ERROR"].evidence_frames == [4]


def test_business_protocol_tags_from_ek():
    parsed = parse_ek_layers({"frame_number": ["1"], "frame_time_epoch": ["1.0"],
        "frame_len": ["100"], "smb2_cmd": ["1"], "smb2_nt_status": ["0xc000006d"],
        "sip_Status-Code": ["503"], "http2_rst_stream_error": ["2"]})
    assert "smb2_cmd=1" in parsed["analysis"]
    assert "smb2_status=0xc000006d" in parsed["analysis"]
    assert "sip_status=503" in parsed["analysis"]
    assert "http2_rst_error=2" in parsed["analysis"]
