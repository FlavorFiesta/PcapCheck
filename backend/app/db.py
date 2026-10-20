# -*- coding: utf-8 -*-
"""SQLite 访问层:契约定义的三张表 captures / frames / reports。

- WAL 模式,导入线程写与 API 线程读互不阻塞;
- 每线程一个连接(threading.local),busy_timeout 兜底;
- 时间统一 epoch 秒(float);帧号从 1 开始,与 Wireshark 一致。
"""
from __future__ import annotations

import sqlite3
import threading
import os
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable, Optional

from .paths import DATA_DIR, ensure_dirs

DB_PATH = DATA_DIR / "pcapcheck.db"
LEGACY_DB_PATH = DATA_DIR / "pcapdoctor.db"

_local = threading.local()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures(
  id TEXT PRIMARY KEY,
  name TEXT,
  path TEXT,
  size INTEGER,
  frame_count INTEGER,
  first_ts REAL,
  last_ts REAL,
  protocols TEXT,          -- json: ["TCP","DNS",...]
  created_at REAL,
  status TEXT,             -- importing | ready | error
  error TEXT
);
CREATE TABLE IF NOT EXISTS frames(
  capture_id TEXT,
  no INTEGER,
  ts REAL,
  src TEXT,
  dst TEXT,
  sport INTEGER,
  dport INTEGER,
  proto TEXT,
  length INTEGER,
  info TEXT,
  stream INTEGER,
  analysis TEXT,           -- json: ["retransmission","zero_window",...]
  expert TEXT,             -- json: [{severity,message,group}]
  PRIMARY KEY(capture_id, no)
);
CREATE TABLE IF NOT EXISTS reports(
  id TEXT PRIMARY KEY,
  capture_id TEXT,
  created_at REAL,
  engine TEXT,
  analysis_mode TEXT DEFAULT 'rules', -- rules | ai_direct
  findings TEXT,           -- json
  summary TEXT,
  narrative TEXT,
  masked INTEGER,
  coverage TEXT            -- json: {expert_errors,expert_warns,unconsumed,note}
);
CREATE INDEX IF NOT EXISTS idx_frames_stream ON frames(capture_id, stream);
"""

# 旧库平滑迁移:reports 表补 coverage 列(已存在则忽略)
_MIGRATIONS = (
    "ALTER TABLE reports ADD COLUMN coverage TEXT",
    "ALTER TABLE reports ADD COLUMN analysis_mode TEXT DEFAULT 'rules'",
)


def init_db() -> None:
    ensure_dirs()
    if DB_PATH == DATA_DIR / "pcapcheck.db":
        migrate_legacy_database(LEGACY_DB_PATH, DB_PATH)
    with _conn() as conn:
        conn.executescript(_SCHEMA)
        for sql in _MIGRATIONS:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass  # 列已存在


def migrate_legacy_database(old: Path, new: Path) -> None:
    """Copy a legacy SQLite database with its WAL committed state, preserving the source."""
    if not old.is_file() or new.exists():
        return
    fd, temp_name = tempfile.mkstemp(prefix=".pcapcheck-migrate-", suffix=".db", dir=new.parent)
    os.close(fd)
    temporary = Path(temp_name)
    try:
        with closing(sqlite3.connect(str(old))) as source, closing(sqlite3.connect(str(temporary))) as target:
            source.backup(target)
        if not new.exists():
            os.replace(temporary, new)
    finally:
        temporary.unlink(missing_ok=True)


def _conn() -> sqlite3.Connection:
    """线程局部连接;调用方负责用 with 管理事务。"""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return conn


def query(sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    with _conn() as conn:
        return conn.execute(sql, tuple(params)).fetchall()


def query_one(sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
    with _conn() as conn:
        return conn.execute(sql, tuple(params)).fetchone()


def execute(sql: str, params: Iterable[Any] = ()) -> None:
    with _conn() as conn:
        conn.execute(sql, tuple(params))


def executemany(sql: str, seq: Iterable[Iterable[Any]]) -> None:
    with _conn() as conn:
        conn.executemany(sql, seq)


def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}
