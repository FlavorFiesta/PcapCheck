# -*- coding: utf-8 -*-
"""极简过滤器表达式 -> tshark display filter 编译器。

支持的原子表达式(契约):
  ip==a.b.c.d        ->  ip.addr==a.b.c.d
  port==N            ->  (tcp.port==N || udp.port==N)
  proto==tcp|udp|dns|tls|http|arp|icmp|dhcp|sip|rtp
                     ->  对应协议过滤字段
  contains "abc"     ->  frame contains 61:62:63   (utf8 字节)
  stream==N          ->  (tcp.stream==N || udp.stream==N)
扩展记号(前端预设按钮):
  analysis==retransmission|out_of_order|zero_window|dup_ack|lost_segment
  flag==rst|syn|fin
  dns==fail          ->  响应且 rcode!=0
  tls==alert         ->  存在 TLS alert
  http==5xx          ->  响应码 500~599
组合符 && || ! 与括号直传。

非法表达式抛 FilterCompileError,由 API 层转成 {"error": ...}。
"""
from __future__ import annotations

import re
from typing import List, Tuple

PROTO_MAP = {
    "tcp": "tcp",
    "udp": "udp",
    "dns": "dns",
    "tls": "tls",
    "http": "http",
    "arp": "arp",
    "icmp": "icmp",
    "icmpv6": "icmpv6",
    "dhcp": "dhcp",
    "sip": "sip",
    "rtp": "rtp",
}


class FilterCompileError(ValueError):
    """表达式编译失败(含人类可读中文/原始原因)。"""


# ---------------------------------------------------------------- 词法
_TOKEN_RE = re.compile(r"""
    \s*(?:
      (?P<op>&&|\|\||!|==|\(|\))
    | (?P<str>"(?:[^"\\]|\\.)*")
    | (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
    | (?P<num>\d+(?:\.\d+)*)
    )""", re.VERBOSE)


def _tokenize(expr: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            # 跳过纯空白
            if expr[pos:].strip() == "":
                break
            rest = expr[pos:].lstrip()
            raise FilterCompileError(f"无法解析的片段:{rest[:30]!r}")
        pos = m.end()
        if m.group("op"):
            tokens.append(("op", m.group("op")))
        elif m.group("str"):
            raw = m.group("str")[1:-1]
            raw = raw.replace('\\"', '"').replace("\\\\", "\\")
            tokens.append(("str", raw))
        elif m.group("ident"):
            tokens.append(("ident", m.group("ident")))
        elif m.group("num"):
            tokens.append(("num", m.group("num")))
    if not tokens:
        raise FilterCompileError("空表达式")
    return tokens


# ---------------------------------------------------------------- 语法
class _Parser:
    """expr := term ('||' term)*
       term := factor ('&&' factor)*
       factor := '!' factor | '(' expr ')' | atom"""

    def __init__(self, tokens: List[Tuple[str, str]]):
        self.toks = tokens
        self.i = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def next(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect_op(self, op: str):
        kind, val = self.next()
        if kind != "op" or val != op:
            raise FilterCompileError(f"期望 {op!r},实际 {val!r}")

    def parse(self) -> str:
        out = self.expr()
        if self.i != len(self.toks):
            raise FilterCompileError(f"表达式末尾有多余内容:{self.toks[self.i:]}")
        return out

    def expr(self) -> str:
        parts = [self.term()]
        while self.peek() == ("op", "||"):
            self.next()
            parts.append(self.term())
        return " || ".join(parts) if len(parts) > 1 else parts[0]

    def term(self) -> str:
        parts = [self.factor()]
        while self.peek() == ("op", "&&"):
            self.next()
            parts.append(self.factor())
        return " && ".join(f"({p})" if " || " in p else p for p in parts) \
            if len(parts) > 1 else parts[0]

    def factor(self) -> str:
        kind, val = self.peek()
        if kind == "op" and val == "!":
            self.next()
            inner = self.factor()
            return f"!({inner})" if (" " in inner) else f"!{inner}"
        if kind == "op" and val == "(":
            self.next()
            inner = self.expr()
            self.expect_op(")")
            return f"({inner})"
        return self.atom()

    def atom(self) -> str:
        kind, name = self.next()
        if kind != "ident":
            raise FilterCompileError(f"此处应为字段名(如 ip / port / proto),实际 {name!r}")
        low = name.lower()

        # contains "abc" —— 关键字语法,后面直接跟字符串,不走 '=='
        if low == "contains":
            kind3, sval = self.next()
            if kind3 != "str":
                raise FilterCompileError('contains 后应为带引号字符串,如 contains "abc"')
            data = sval.encode("utf-8")
            if not data:
                raise FilterCompileError("contains 字符串为空")
            hexs = ":".join(f"{b:02x}" for b in data)
            return f"frame contains {hexs}"

        kind2, op = self.next()
        if kind2 != "op" or op != "==":
            raise FilterCompileError(f"{name} 后应为 '==',实际 {op!r}")

        kind3, val = self.next()
        if kind3 not in ("ident", "num", "str"):
            raise FilterCompileError(f"{name}== 后缺值")

        if low == "ip":
            _check_ip(val)
            return f"ip.addr=={val}"
        if low == "port":
            if not val.isdigit() or not (0 <= int(val) <= 65535):
                raise FilterCompileError(f"端口应为 0~65535 的整数,实际 {val!r}")
            return f"(tcp.port=={val} || udp.port=={val})"
        if low == "proto":
            p = val.lower()
            if p not in PROTO_MAP:
                raise FilterCompileError(
                    f"不支持的 proto:{val!r},支持 {sorted(PROTO_MAP)}")
            return PROTO_MAP[p]
        if low == "stream":
            if not val.isdigit():
                raise FilterCompileError(f"stream 应为非负整数,实际 {val!r}")
            return f"(tcp.stream=={val} || udp.stream=={val})"

        # ---- 扩展记号(前端预设按钮使用) ----
        if low == "analysis":
            a = val.lower()
            a_map = {
                "retransmission": "tcp.analysis.retransmission || tcp.analysis.fast_retransmission",
                "out_of_order": "tcp.analysis.out_of_order",
                "zero_window": "tcp.analysis.zero_window || tcp.analysis.window_full",
                "dup_ack": "tcp.analysis.duplicate_ack",
                "lost_segment": "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment",
            }
            if a not in a_map:
                raise FilterCompileError(
                    f"不支持的 analysis:{val!r},支持 {sorted(a_map)}")
            return f"({a_map[a]})"
        if low == "flag":
            f = val.lower()
            f_map = {"rst": "tcp.flags.reset==1", "syn": "tcp.flags.syn==1",
                     "fin": "tcp.flags.fin==1"}
            if f not in f_map:
                raise FilterCompileError(
                    f"不支持的 flag:{val!r},支持 {sorted(f_map)}")
            return f_map[f]
        if low == "dns":
            if val.lower() == "fail":
                return "(dns.flags.response==1 && dns.flags.rcode!=0)"
            raise FilterCompileError(f"不支持的 dns 记号:{val!r},仅支持 dns==fail")
        if low == "tls":
            if val.lower() == "alert":
                return "tls.alert_message.desc"
            raise FilterCompileError(f"不支持的 tls 记号:{val!r},仅支持 tls==alert")
        if low == "http":
            if val.lower() == "5xx":
                return "(http.response.code>=500 && http.response.code<=599)"
            raise FilterCompileError(f"不支持的 http 记号:{val!r},仅支持 http==5xx")

        raise FilterCompileError(
            f"不支持的字段:{name!r},支持 ip / port / proto / contains / stream / "
            "analysis / flag / dns / tls / http")


def _check_ip(val: str) -> None:
    parts = val.split(".")
    if len(parts) != 4:
        raise FilterCompileError(f"IP 地址格式错误:{val!r}")
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            raise FilterCompileError(f"IP 地址格式错误:{val!r}")


def compile_expr(expr: str) -> str:
    """编译极简表达式为 tshark display filter。"""
    if not expr or not expr.strip():
        raise FilterCompileError("空表达式")
    return _Parser(_tokenize(expr)).parse()
