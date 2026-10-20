# -*- coding: utf-8 -*-
r"""知识库第一批文章验证:解析 + 与规则注册表对账。

用法:backend\\.venv\\Scripts\\python.exe tools\\verify_kb.py
检查项:
  1. 默认 kb_dir 下文章数 >= 35 且全部解析成功(frontmatter 完整);
  2. 26 篇规则文章的 rule_ids 与 registry 精确一致;
  3. registry 全部 rule_id 被规则文章覆盖;
  4. 专题文章 rule_ids 为空或均为 registry 中存在的 ID;
  5. 每篇正文顶部有「AI 起草,未经人工审核」标注;
  6. 正文中文字数在 250~500 区间(信息密度约束,纯命令行不计)。
"""
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

BACKEND = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND))

from app.kb import scan_articles, article_by_id  # noqa: E402
from app.rules.registry import all_rule_ids  # noqa: E402

BANNER = "> ⚠️ 状态:AI 起草,未经人工审核——不得直接作为结论依据"

# 规则文章 -> 必须精确对应的 rule_id
RULE_ARTICLES = {
    "retrans-storm": "R01_RETRANS_STORM",
    "server-rst": "R02_SERVER_RST",
    "dns-failure": "R03_DNS_FAILURE",
    "tls-alert": "R04_TLS_ALERT",
    "arp-conflict": "R05_ARP_CONFLICT",
    "dhcp-failure": "R06_DHCP_FAILURE",
    "zero-window": "R07_ZERO_WINDOW",
    "out-of-order": "S08_OUT_OF_ORDER",
    "mtu-blackhole": "S09_MTU_BLACKHOLE",
    "dns-slow": "S10_DNS_SLOW",
    "handshake-rtt": "S11_HANDSHAKE_RTT",
    "http-5xx": "S12_HTTP_5XX",
    "bandwidth-saturation": "P13_BANDWIDTH_SATURATION",
    "retrans-trend": "P14_RETRANS_TREND",
    "rtp-oneway": "P15_RTP_ONEWAY",
    "malformed-packet": "U16_MALFORMED",
    "expert-unclassified": "U17_EXPERT_FALLBACK",
    "tcp-connect-timeout": "S18_TCP_CONNECT_TIMEOUT",
    "dns-timeout": "S19_DNS_TIMEOUT",
    "dhcp-timeout": "S20_DHCP_TIMEOUT",
    "ipv6-neighbor-timeout": "S21_IPV6_NEIGHBOR_TIMEOUT",
    "ipv6-packet-too-big": "S22_IPV6_PACKET_TOO_BIG",
    "capture-quality": "U23_CAPTURE_TRUNCATED",
    "smb-session-failure": "S24_SMB_SESSION_FAILURE",
    "sip-server-failure": "S25_SIP_SERVER_FAILURE",
    "http2-stream-error": "S26_HTTP2_STREAM_ERROR",
}


def main() -> int:
    articles = scan_articles()  # 默认 kb_dir = <项目根>/docs/kb
    print(f"[1] 默认 kb_dir 扫描到文章 {len(articles)} 篇")
    ok = len(articles) >= 35

    by_id = {a["id"]: a for a in articles}

    # ---- 2. 解析完整性 ----
    bad_meta = []
    for a in articles:
        if not a["title"] or a["title"] == a["id"]:
            bad_meta.append(f"{a['id']}: title 缺失")
        if not a["protocols"]:
            bad_meta.append(f"{a['id']}: protocols 缺失")
        if not a["symptoms"]:
            bad_meta.append(f"{a['id']}: symptoms 缺失")
        if not a["severity"]:
            bad_meta.append(f"{a['id']}: severity 缺失")
    if bad_meta:
        ok = False
        print("[2] frontmatter 缺失项:")
        for b in bad_meta:
            print("    -", b)
    else:
        print("[2] 全部文章 frontmatter 完整(title/protocols/symptoms/severity)")

    # ---- 3. 规则文章 rule_ids 精确对账 ----
    reg = set(all_rule_ids())
    covered_by_rule_articles: set = set()
    for aid, rid in RULE_ARTICLES.items():
        a = by_id.get(aid)
        if a is None:
            ok = False
            print(f"[3] 错误:缺少规则文章 {aid}.md")
            continue
        if set(a["rule_ids"]) != {rid}:
            ok = False
            print(f"[3] 错误:{aid}.md rule_ids={a['rule_ids']},期望 [{rid}]")
        else:
            covered_by_rule_articles.add(rid)

    missing = reg - covered_by_rule_articles
    extra = covered_by_rule_articles - reg
    if missing or extra:
        ok = False
        if missing:
            print(f"[3] 错误:registry 中未被规则文章覆盖的 ID:{sorted(missing)}")
        if extra:
            print(f"[3] 错误:规则文章引用了 registry 不存在的 ID:{sorted(extra)}")
    else:
        print(f"[3] registry 全部 {len(reg)} 个 rule_id 与 {len(RULE_ARTICLES)} 篇规则文章精确对上")

    # ---- 4. 专题文章 rule_ids 合法 ----
    topic_ids = [a["id"] for a in articles
                 if a["id"] not in RULE_ARTICLES]
    for aid in topic_ids:
        bad = [r for r in by_id[aid]["rule_ids"] if r not in reg]
        if bad:
            ok = False
            print(f"[4] 错误:专题文章 {aid}.md 引用了不存在的 rule_id:{bad}")
    print(f"[4] 专题文章 {len(topic_ids)} 篇 rule_ids 检查完成(空列表或均在 registry 内)")

    # ---- 5. 正文顶部 AI 起草标注 ----
    no_banner = []
    for a in articles:
        full = article_by_id(a["id"])
        first = next((ln for ln in (full.get("content") or "").splitlines()
                      if ln.strip()), "")
        if not first.startswith(BANNER):
            no_banner.append(a["id"])
    if no_banner:
        ok = False
        print(f"[5] 错误:以下文章正文顶部缺少 AI 起草标注:{no_banner}")
    else:
        print("[5] 全部文章正文顶部均有「AI 起草,未经人工审核」标注")

    # ---- 6. 正文中文字数(250~500,排除命令与代码片段所在行) ----
    cjk = re.compile(r"[\u4e00-\u9fff]")
    out_of_range = []
    for a in articles:
        full = article_by_id(a["id"])
        body_lines = [
            ln for ln in (full.get("content") or "").splitlines()
            if ln.strip() and not ln.lstrip().startswith(BANNER[:1])
            and "`tshark" not in ln and not ln.startswith("  ")
        ]
        n = sum(len(cjk.findall(ln)) for ln in body_lines)
        if not 250 <= n <= 500:
            out_of_range.append(f"{a['id']}:{n}")
    if out_of_range:
        print("[6] 正文中文字数超出 250~500 区间(人工复核参考):", ", ".join(out_of_range))
    else:
        print("[6] 全部文章正文中文字数在 250~500 区间(命令行不计)")

    # ---- 清单 ----
    print("-" * 100)
    for a in articles:
        tag = "规则" if a["id"] in RULE_ARTICLES else "专题"
        print(f"  [{tag}] {a['id']:<22} | {a['title']:<30} | rule_ids={a['rule_ids']}")
    print("-" * 100)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
