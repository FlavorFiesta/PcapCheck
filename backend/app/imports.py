# -*- coding: utf-8 -*-
"""导入管线:tshark -T ek 流式解析入 SQLite。

- 后台线程执行,批量 executemany 入库;
- 进度(已入库帧数)持续更新到 captures.frame_count;
- 完成时回填 first_ts/last_ts/protocols,状态置 ready;失败置 error。
"""
from __future__ import annotations

import json
import os
import threading
import traceback
import uuid
from datetime import datetime
from typing import List, Optional

from . import db, tshark_service
from .paths import UPLOAD_DIR

_INSERT = ("INSERT OR REPLACE INTO frames"
           "(capture_id,no,ts,src,dst,sport,dport,proto,length,info,stream,analysis,expert) "
           "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")

_UPDATE_META = ("UPDATE captures SET frame_count=?, first_ts=?, last_ts=?, protocols=?, status='ready', error=NULL "
                "WHERE id=?")
_UPDATE_PROGRESS = "UPDATE captures SET frame_count=? WHERE id=?"
_UPDATE_ERROR = "UPDATE captures SET error=?, status='error' WHERE id=?"

_BATCH = 1000


def create_capture(path: str, name: Optional[str] = None) -> str:
    """登记一条 capture 记录(status=importing),返回 capture_id。"""
    p = os.path.abspath(path)
    capture_id = uuid.uuid4().hex[:12]
    db.execute(
        "INSERT INTO captures(id,name,path,size,frame_count,first_ts,last_ts,protocols,created_at,status,error) "
        "VALUES (?,?,?,?,0,NULL,NULL,?,?,'importing',NULL)",
        (capture_id, name or os.path.basename(p), p,
         _safe_size(p), json.dumps([], ensure_ascii=False),
         datetime.now().timestamp()))
    return capture_id


def start_import(path: str, name: Optional[str] = None) -> str:
    """创建记录并起后台线程导入。"""
    capture_id = create_capture(path, name)
    t = threading.Thread(target=import_sync, args=(capture_id, path),
                         name=f"import-{capture_id}", daemon=True)
    t.start()
    return capture_id


def import_sync(capture_id: str, path: str) -> None:
    """同步执行导入(后台线程与测试共用)。任何异常落到 captures.error。"""
    tshark = tshark_service.resolve_tshark()
    if not tshark:
        db.execute(_UPDATE_ERROR, ("未找到 tshark,请在设置里指定路径", capture_id))
        return
    if not os.path.isfile(path):
        db.execute(_UPDATE_ERROR, (f"文件不存在:{path}", capture_id))
        return

    protocols = set()
    first_ts = None
    last_ts = None
    total = 0
    batch: List[tuple] = []
    stderr_msg = ""
    try:
        with _stderr_file() as errf:
            for layers in tshark_service.iter_ek(tshark, tshark_service.ek_read_args(path), stderr_file=errf):
                frame = tshark_service.parse_ek_layers(layers)
                if frame is None:
                    continue
                ts = frame["ts"]
                first_ts = ts if first_ts is None else min(first_ts, ts)
                last_ts = ts if last_ts is None else max(last_ts, ts)
                if frame["proto"]:
                    protocols.add(frame["proto"])
                batch.append((
                    capture_id, frame["no"], ts, frame["src"], frame["dst"],
                    frame["sport"], frame["dport"], frame["proto"], frame["length"],
                    frame["info"], frame["stream"],
                    json.dumps(frame["analysis"], ensure_ascii=False),
                    json.dumps(frame["expert"], ensure_ascii=False),
                ))
                if len(batch) >= _BATCH:
                    db.executemany(_INSERT, batch)
                    total += len(batch)
                    db.execute(_UPDATE_PROGRESS, (total, capture_id))
                    batch.clear()
        if batch:
            db.executemany(_INSERT, batch)
            total += len(batch)
        if total == 0:
            try:
                errf.seek(0)
                stderr_msg = errf.read().decode("utf-8", errors="replace").strip()
            except Exception:
                stderr_msg = ""
            raise RuntimeError("tshark 未解出任何帧(文件损坏或格式不支持)"
                               + (f":{stderr_msg[:300]}" if stderr_msg else ""))
        db.execute(_UPDATE_META, (total, first_ts, last_ts,
                                  json.dumps(sorted(protocols), ensure_ascii=False), capture_id))
    except Exception as e:  # 任何失败都要可见,不静默
        err = f"{e} | {traceback.format_exc(limit=2)}"
        db.execute(_UPDATE_ERROR, (err[:2000], capture_id))


def import_upload_sync(file_bytes: bytes, filename: str) -> str:
    """上传文件落盘并导入。"""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe = os.path.basename(filename) or "upload.pcap"
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{safe}"
    dest.write_bytes(file_bytes)
    return start_import(str(dest), name=safe)


class _stderr_file:
    """tshark stderr 临时文件上下文(出错时读取)。"""

    def __enter__(self):
        import tempfile
        self.f = tempfile.TemporaryFile()
        return self.f

    def __exit__(self, exc_type, exc, tb):
        self.f.close()
        return False


def _safe_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0
