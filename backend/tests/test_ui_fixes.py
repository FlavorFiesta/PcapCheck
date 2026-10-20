# -*- coding: utf-8 -*-
"""UI critic 三项修复的回归测试:单帧字段树 / Follow TCP 重组 / 报告 coverage。"""
from __future__ import annotations

import json
import pytest

from conftest import CAPTURES
from app import analysis, db, imports, settings, tshark_service


def _import_analyze(path):
    cap_id = imports.create_capture(str(path))
    try:
        imports.import_sync(cap_id, str(path))
        meta = db.query_one("SELECT * FROM captures WHERE id=?", (cap_id,))
        assert meta["status"] == "ready", meta["error"]
        report_id = analysis.analyze_capture(cap_id)
        rep = db.query_one("SELECT * FROM reports WHERE id=?", (report_id,))
        return cap_id, dict(rep)
    finally:
        pass


def _cleanup(cap_id):
    db.execute("DELETE FROM frames WHERE capture_id=?", (cap_id,))
    db.execute("DELETE FROM reports WHERE capture_id=?", (cap_id,))
    db.execute("DELETE FROM captures WHERE id=?", (cap_id,))


@pytest.mark.external_capture
@pytest.mark.tshark
def test_ai_direct_report_skips_rules_and_kb(monkeypatch):
    """AI 直达模式只组装帧摘要,不触发本地规则或知识库。"""
    cap_id = imports.create_capture(str(CAPTURES / "dns_port.pcap"))
    try:
        imports.import_sync(cap_id, str(CAPTURES / "dns_port.pcap"))
        monkeypatch.setattr(settings, "load_settings", lambda: {
            "llm": {"enabled": True, "base_url": "https://example.test/v1", "model": "demo"},
            "masking": {"enabled": True}, "kb_dir": "unused",
        })
        monkeypatch.setattr(analysis.llm, "is_configured", lambda _settings: True)
        monkeypatch.setattr(analysis.llm, "generate_direct_analysis",
                            lambda _cap, frames, _settings: f"AI直达:{len(frames)}")
        monkeypatch.setattr(analysis.rules_pkg, "run_all",
                            lambda _ctx: (_ for _ in ()).throw(AssertionError("不应运行规则")))
        monkeypatch.setattr(analysis.kb, "match_kb_ids",
                            lambda *_args: (_ for _ in ()).throw(AssertionError("不应匹配知识库")))
        meta = db.query_one("SELECT * FROM captures WHERE id=?", (cap_id,))
        report_id = analysis.analyze_capture(cap_id, mode="ai_direct")
        rep = db.query_one("SELECT * FROM reports WHERE id=?", (report_id,))
        assert rep["analysis_mode"] == "ai_direct"
        assert rep["engine"] == "ai-direct"
        assert rep["findings"] == "[]"
        assert rep["narrative"].startswith("AI直达:")
        coverage = json.loads(rep["coverage"])
        assert coverage["local_rules_skipped"] is True
        assert coverage["local_kb_skipped"] is True
        assert coverage["frame_count"] == meta["frame_count"]
        assert coverage["sampled_frames"] <= 200
    finally:
        _cleanup(cap_id)


# ---------------------------------------------------------------- 1. 单帧协议字段树
@pytest.mark.external_capture
@pytest.mark.tshark
def test_frame_tree_structure():
    tshark = tshark_service.resolve_tshark()
    out = tshark_service.get_frame_tree(tshark, str(CAPTURES / "tcp-badsegments.pcap"), 10)
    assert out["no"] == 10
    tree = out["tree"]
    # 顶层 = 协议栈序:Frame / IP / TCP,无 geninfo/raw 信封
    labels = [n["label"] for n in tree]
    assert len(tree) == 3
    assert labels[0].startswith("Frame 10: ")
    assert labels[1] == "Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2"
    assert labels[2].startswith("Transmission Control Protocol, Src Port: 32323, Dst Port: 80,")
    # 字段 label 用 showname(按 label 查找,不依赖下标)
    frame_children = tree[0]["children"]
    assert "Frame Number: 10" in [c["label"] for c in frame_children]
    assert tree[1]["children"][0]["label"] == "0100 .... = Version: 4"
    assert tree[1]["children"][1]["label"] == ".... 0101 = Header Length: 20 bytes (5)"
    # 每个节点都有 label/children
    for node in tree:
        assert isinstance(node["label"], str) and isinstance(node["children"], list)


@pytest.mark.external_capture
@pytest.mark.tshark
def test_frame_tree_http_layer():
    """带 HTTP 载荷的帧(帧6),顶层多出 HTTP 协议层(按栈序 Frame/IP/TCP/HTTP)。"""
    tshark = tshark_service.resolve_tshark()
    out = tshark_service.get_frame_tree(tshark, str(CAPTURES / "tcp-badsegments.pcap"), 6)
    labels = [n["label"] for n in out["tree"]]
    assert len(labels) == 4
    assert labels[0].startswith("Frame 6: ")
    assert labels[1].startswith("Internet Protocol Version 4")
    assert labels[2].startswith("Transmission Control Protocol")
    assert labels[3] == "Hypertext Transfer Protocol"
    # 内部包装层不外露
    assert all("fake-field-wrapper" not in l for l in labels)


@pytest.mark.external_capture
@pytest.mark.tshark
def test_frame_tree_missing_frame():
    import pytest
    tshark = tshark_service.resolve_tshark()
    with pytest.raises(KeyError):
        tshark_service.get_frame_tree(tshark, str(CAPTURES / "tcp-badsegments.pcap"), 9999)


# ---------------------------------------------------------------- 2. Follow TCP 重组
@pytest.mark.external_capture
@pytest.mark.tshark
def test_follow_tcp_reassembly():
    tshark = tshark_service.resolve_tshark()
    follow = tshark_service.get_follow_messages(tshark, str(CAPTURES / "tcp-badsegments.pcap"), 0, "tcp")
    assert follow["client"] == "10.0.0.1:32323"
    assert follow["server"] == "10.0.0.2:80"
    msgs = follow["messages"]
    # 纯 ACK/无负载帧不产消息;每条消息有 no/ts/dir/data/len 且 len>0
    assert all(m["len"] > 0 and m["data"] for m in msgs)
    assert all(set(m) >= {"no", "ts", "dir", "data", "len"} for m in msgs)
    # 完全重复的重传帧(X-Overlap-IGNORE)被去重,不再出现
    assert all("X-Overlap-IGNORE" not in m["data"] for m in msgs)
    c2s = "".join(m["data"] for m in msgs if m["dir"] == "c2s")
    # 按 seq 重组的连续文本(与 Wireshark Follow TCP Stream 语义对齐)
    assert c2s.startswith("GET / HTTP/1.1\r\nHost:localhost\r\n")
    assert "X-Swapped: 1st\r\nX-Swapped: 2nd\r\n" in c2s          # 帧序被交换,按 seq 归位
    assert "X-Overlap-Packet: extra data--\r\n" in c2s            # 重叠去重后连续
    assert "X-OoO-Overlap: this is delayed\r\n" in c2s            # OoO 补齐后连读
    assert "X-OoO-Overlap2: second delayed\r\n" in c2s
    assert "X-OoO-Overlap3:extend fragment\r\n" in c2s
    # 真实缺口显式标注
    assert "[32 bytes missing (gap before frame 18)]" in c2s
    assert "[16 bytes missing (gap before frame 21)]" in c2s
    assert "[13 bytes missing (gap before frame 20)]" in c2s
    assert "[1 bytes missing (gap before frame 22)]" in c2s
    # 消息首帧号可用于回跳:2nd 来自帧6、1st 来自帧7(流内顺序 7 在前)
    m7 = next(m for m in msgs if m["data"] == "X-Swapped: 1st\r\n")
    m6 = next(m for m in msgs if m["data"] == "X-Swapped: 2nd\r\n")
    assert m7["no"] == 7 and m6["no"] == 6
    assert msgs.index(m7) < msgs.index(m6)  # 文本顺序 = 流字节序


@pytest.mark.external_capture
@pytest.mark.tshark
def test_follow_tcp_gap_gap_field():
    tshark = tshark_service.resolve_tshark()
    follow = tshark_service.get_follow_messages(tshark, str(CAPTURES / "tcp-badsegments.pcap"), 0, "tcp")
    gap_msgs = [m for m in follow["messages"] if m.get("gap")]
    assert sorted(m["gap"] for m in gap_msgs) == [1, 13, 16, 32]


@pytest.mark.external_capture
@pytest.mark.tshark
def test_follow_udp_still_flat():
    """UDP 无序号语义,保持按帧平铺(dns_port.pcap stream0)。"""
    tshark = tshark_service.resolve_tshark()
    follow = tshark_service.get_follow_messages(tshark, str(CAPTURES / "dns_port.pcap"), 0, "udp")
    assert follow["messages"], "UDP follow 应有消息"
    assert all(m["len"] > 0 for m in follow["messages"])


# ---------------------------------------------------------------- 3. 报告 coverage
@pytest.mark.external_capture
@pytest.mark.tshark
def test_report_coverage_badsegments():
    cap_id, rep = _import_analyze(CAPTURES / "tcp-badsegments.pcap")
    try:
        cov = json.loads(rep["coverage"])
        # 实测(修正后口径):15 个 warn 帧(ooo/lost,0x600000);retrans 帧10 是 note 不计;
        # 6 帧被 S08 证据消费 → 9 帧未消费(全部为捕获起点伪影,U17 豁免不报)
        assert cov["expert_errors"] == 0
        assert cov["expert_warns"] == 15
        assert cov["unconsumed"] == 9
        assert cov["unconsumed_frames"] == [6, 12, 13, 14, 18, 19, 20, 22, 23]
        assert cov["note"]
        assert "专家层 error/warn 帧共 15,其中 9 帧超出 V1 规则范围未判定" in rep["summary"]
        ids = {f["rule_id"] for f in json.loads(rep["findings"]) if isinstance(f, dict) and "rule_id" in f}
        assert "U17_EXPERT_FALLBACK" not in ids
    finally:
        _cleanup(cap_id)


@pytest.mark.external_capture
@pytest.mark.tshark
def test_report_coverage_error_frame():
    """nvme-tcp-truncated 的 Malformed error 帧被 U16 消费 → unconsumed=0。"""
    cap_id, rep = _import_analyze(CAPTURES / "nvme-tcp-truncated.pcapng")
    try:
        cov = json.loads(rep["coverage"])
        assert cov["expert_errors"] == 1
        assert cov["unconsumed"] == 0
        assert "专家层 error/warn 帧共 1,其中 0 帧超出" in rep["summary"]
        findings = json.loads(rep["findings"])
        assert any(f["rule_id"] == "U16_MALFORMED" for f in findings)
    finally:
        _cleanup(cap_id)


@pytest.mark.external_capture
@pytest.mark.tshark
def test_report_coverage_zero_explicit():
    """无任何 expert 的捕获也要显式声明 0(不静默)。"""
    cap_id, rep = _import_analyze(CAPTURES / "dhcp.pcap")
    try:
        cov = json.loads(rep["coverage"])
        assert cov["expert_errors"] == 0 and cov["expert_warns"] == 0 and cov["unconsumed"] == 0
        assert "专家层 error/warn 帧共 0,其中 0 帧超出 V1 规则范围未判定" in rep["summary"]
    finally:
        _cleanup(cap_id)
